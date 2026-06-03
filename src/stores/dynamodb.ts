import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';

import {
  RefreshTokenExpiredError,
  RefreshTokenInvalidError,
  RefreshTokenReusedError,
  RefreshTokenRevokedError,
} from './refresh-token-errors';
import type { RefreshTokenStore, StoreOptions, TokenRecord, IssueParams, RotateParams, RevokeParams, IssueResult, RotateResult } from '../types/index';
import { randomtoken, sha256hex } from '../utils/hash';
import { epochsec } from '../utils/time';

/** Re-exported types for consumers that import the DynamoDB store module. */
export { RefreshTokenStore, StoreOptions, TokenRecord, IssueParams, RotateParams, RevokeParams, IssueResult, RotateResult };

/** Default partition key prefix for refresh token items. */
const DEFAULT_PRIMARY_KEY_PREFIX = 'rt#';

/**
 * {@link RefreshTokenStore} implementation backed by a single DynamoDB table.
 *
 * Items use partition key `pk`, logical expiration `expiresAt`, and DynamoDB TTL attribute `ttl`
 * (Unix seconds). Enable table TTL on attribute `ttl` so expired and rotated rows are removed
 * asynchronously. This class owns the DynamoDB client; callers supply `tableName`, `region`, and
 * optional {@link StoreOptions}.
 */
export class DynamodbRefreshTokenProvider implements RefreshTokenStore {
  /** Lazily initialized and cached document client. */
  private ddb: DynamoDBDocumentClient | null = null;

  /** Random byte length for generated refresh tokens (default 32 → 256-bit). */
  private readonly tokenBytes = 32;

  /**
   * @param tableName - DynamoDB table name for refresh token items.
   * @param region - AWS region for the DynamoDB client.
   * @param options - Token lifetime, PK prefix, consistent reads, or custom endpoint.
   */
  constructor(
    private readonly tableName: string,
    private readonly region: string,
    private readonly options?: StoreOptions,
  ) {}

  /**
   * Inserts a new token record with `expiresAt` and matching `ttl`. Fails the put if `pk` already exists.
   *
   * @param params - Subject, session, and optional clock (`now`).
   * @returns Plaintext refresh token and expiration as Unix seconds.
   */
  public issue = async (params: IssueParams): Promise<IssueResult> => {
    const ddb = this.getddb();

    const now = params.now ?? new Date();
    const nowSec = epochsec(now);
    const expiresAt = this.makeExpiresAt(nowSec);

    const refreshToken = randomtoken(this.tokenBytes);
    const hash = sha256hex(refreshToken);
    const pk = this.getPrimaryKey(hash);

    await ddb.send(
      new PutCommand({
        TableName: this.tableName,
        Item: {
          pk,
          subjectId: params.subjectId,
          sessionId: params.sessionId,
          createdAt: nowSec,
          expiresAt,
          ttl: expiresAt,
        },
        ConditionExpression: 'attribute_not_exists(pk)',
      }),
    );

    return {
      refreshToken,
      refreshTokenExpiresAt: expiresAt,
    };
  };

  /**
   * Marks the current token as rotated and creates the successor row in one transaction.
   *
   * Updates the previous row’s `ttl` to its `expiresAt` and sets `ttl` on the new Put to the
   * successor’s expiration so DynamoDB can delete both when appropriate.
   *
   * @param params - Client refresh token and optional clock (`now`).
   * @returns Subject, session, new plaintext token, and new expiration.
   * @throws {@link RefreshTokenInvalidError} When the token format is invalid or no row exists.
   * @throws {@link RefreshTokenExpiredError} When `expiresAt` is not after `now`.
   * @throws {@link RefreshTokenRevokedError} When the token row has `revokedAt` set.
   * @throws {@link RefreshTokenReusedError} When the token was already rotated or the transaction indicates reuse.
   */
  public rotate = async (params: RotateParams): Promise<RotateResult> => {
    // validate refresh token
    this.validateRefreshToken(params.refreshToken);

    const ddb = this.getddb();

    const now = params.now ?? new Date();
    const nowSec = epochsec(now);

    const currentHash = sha256hex(params.refreshToken);
    const currentPk = this.getPrimaryKey(currentHash);

    const current = await this.getTokenRecord(currentPk);
    if (!current) {
      throw new RefreshTokenInvalidError();
    }
    if (current.expiresAt <= nowSec) {
      throw new RefreshTokenExpiredError();
    }
    if (current.revokedAt) {
      throw new RefreshTokenRevokedError();
    }
    if (current.rotatedAt) {
      throw new RefreshTokenReusedError();
    }

    const nextRefreshTokenExpiresAt = this.makeExpiresAt(nowSec);
    const nextRefreshToken = randomtoken(this.tokenBytes);
    const nextHash = sha256hex(nextRefreshToken);
    const nextPk = this.getPrimaryKey(nextHash);

    try {
      await ddb.send(new TransactWriteCommand({
        TransactItems: [
          {
            Update: {
              TableName: this.tableName,
              Key: { pk: currentPk },
              UpdateExpression: 'SET rotatedAt = :now, replacedByPk = :nextPk, #ttl = :ttl',
              ConditionExpression: 'attribute_exists(pk) AND attribute_not_exists(rotatedAt) AND attribute_not_exists(revokedAt)',
              ExpressionAttributeNames: {
                '#ttl': 'ttl',
              },
              ExpressionAttributeValues: {
                ':now': nowSec,
                ':nextPk': nextPk,
                ':ttl': current.expiresAt,
              },
            },
          },
          {
            Put: {
              TableName: this.tableName,
              Item: {
                pk: nextPk,
                subjectId: current.subjectId,
                sessionId: current.sessionId,
                createdAt: nowSec,
                expiresAt: nextRefreshTokenExpiresAt,
                ttl: nextRefreshTokenExpiresAt,
              },
              ConditionExpression: 'attribute_not_exists(pk)',
            },
          },
        ],
      }));

    } catch (error: unknown) {
      if (error instanceof Error && error.name === 'TransactionCanceledException') {
        // Treat conditional transaction failure as token reuse.
        throw new RefreshTokenReusedError();
      }
      throw error;
    }

    return {
      subjectId: current.subjectId,
      sessionId: current.sessionId,
      refreshToken: nextRefreshToken,
      refreshTokenExpiresAt: nextRefreshTokenExpiresAt,
    };
  };

  /**
   * Sets `revokedAt` on the token row. Missing items succeed (idempotent revoke).
   *
   * Does not update `ttl`; existing `ttl` from issue/rotate still applies for DynamoDB cleanup.
   *
   * @param params - Refresh token and optional clock (`now`).
   * @returns `true` after a successful update or no-op when the item is absent.
   * @throws {@link RefreshTokenInvalidError} When the token string format is invalid.
   */
  public revoke = async (params: RevokeParams): Promise<true> => {
    // validate refresh token
    this.validateRefreshToken(params.refreshToken);

    const ddb = this.getddb();

    const now = params.now ?? new Date();
    const nowSec = epochsec(now);

    const hash = sha256hex(params.refreshToken);
    const pk = this.getPrimaryKey(hash);

    try {
      await ddb.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { pk },
          UpdateExpression: 'SET revokedAt = :now',
          ConditionExpression: 'attribute_exists(pk)',
          ExpressionAttributeValues: {
            ':now': nowSec,
          },
        }),
      );
    } catch (error: unknown) {
      // Missing item: treat as success (idempotent revoke).
      if (error instanceof Error && error.name === 'ConditionalCheckFailedException') {
        return true;
      }
      throw error;
    }
    return true;
  };

  /**
   * Returns the cached {@link DynamoDBDocumentClient}, creating it on first use.
   *
   * @returns Document client configured for `region` and optional `endpoint`.
   */
  private getddb = (): DynamoDBDocumentClient => {
    if (!this.ddb) {
      const client = new DynamoDBClient({
        region: this.region,
        endpoint: (() => {
          if (this.options?.endpoint) {
            return this.options.endpoint;
          }
          return `https://dynamodb.${this.region}.amazonaws.com`;
        })(),
      });
      this.ddb = DynamoDBDocumentClient.from(client);
    }
    return this.ddb;
  };

  /**
   * Loads a token row by partition key.
   *
   * @param pk - Full partition key (`prefix` + hash).
   * @returns Parsed {@link TokenRecord}, or `null` if the item does not exist.
   */
  private getTokenRecord = async (pk: string): Promise<TokenRecord | null> => {
    const ddb = this.getddb();

    const res = await ddb.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { pk },
        ConsistentRead: this.options?.consistentRead ?? true,
      }),
    );
    return (res.Item as TokenRecord) ?? null;
  };

  /**
   * Effective partition key prefix from {@link StoreOptions} or {@link DEFAULT_PRIMARY_KEY_PREFIX}.
   *
   * @returns Prefix string (e.g. `rt#`).
   */
  private getPrimaryKeyPrefix = (): string => {
    return `${this.options?.pkPrefix ?? DEFAULT_PRIMARY_KEY_PREFIX}`;
  };

  /**
   * Builds the full partition key for a token hash.
   *
   * @param hash - SHA-256 hex digest of the plaintext token.
   * @returns `prefix` + `hash`.
   */
  private getPrimaryKey = (hash: string): string => {
    return `${this.getPrimaryKeyPrefix()}${hash}`;
  };

  /**
   * Computes logical expiration (`expiresAt` / `ttl`) as `nowSec` plus {@link StoreOptions.ttlDays}.
   *
   * @param nowSec - Current time as Unix seconds.
   * @returns Expiration timestamp in Unix seconds (default lifetime: 60 days).
   */
  private makeExpiresAt = (nowSec: number): number => {
    return nowSec + (this.options?.ttlDays ?? 60) * 24 * 60 * 60;
  };

  /**
   * Ensures the token is non-empty and matches the expected base64url length for `tokenBytes`.
   *
   * @param token - Plaintext refresh token from the client.
   * @throws {@link RefreshTokenInvalidError} When validation fails.
   */
  private validateRefreshToken(token: string): void {
    if (!token || token.length !== Math.ceil(this.tokenBytes * 8 / 6)) {
      throw new RefreshTokenInvalidError();
    }
  }

}
