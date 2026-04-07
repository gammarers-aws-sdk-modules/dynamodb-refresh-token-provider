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
 * {@link RefreshTokenStore} implementation using a single DynamoDB table.
 *
 * This class owns the DynamoDB client; callers supply `tableName`, `region`, and optional {@link StoreOptions}.
 */
export class DynamoRefreshTokenStore implements RefreshTokenStore {
  /** Lazily initialized and cached document client. */
  private ddb: DynamoDBDocumentClient | null = null;

  /** Random byte length for generated refresh tokens (default 32 → 256-bit). */
  private readonly tokenBytes = 32;

  /**
   * @param tableName - DynamoDB table name for refresh token items.
   * @param region - AWS region for the DynamoDB client.
   * @param options - TTL, PK prefix, consistent reads, or custom endpoint.
   */
  constructor(
    private readonly tableName: string,
    private readonly region: string,
    private readonly options?: StoreOptions,
  ) {}

  /**
   * Inserts a new token record. Fails the put if the partition key already exists.
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
              UpdateExpression: 'SET rotatedAt = :now, replacedByPk = :nextPk',
              ConditionExpression: 'attribute_exists(pk) AND attribute_not_exists(rotatedAt) AND attribute_not_exists(revokedAt)',
              ExpressionAttributeValues: {
                ':now': nowSec,
                ':nextPk': nextPk,
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

  /** Returns the cached client, creating it on first use. */
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

  /** Loads a token row by partition key, or `null` if absent. */
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

  /** Effective PK prefix from options or {@link DEFAULT_PRIMARY_KEY_PREFIX}. */
  private getPrimaryKeyPrefix = (): string => {
    return `${this.options?.pkPrefix ?? DEFAULT_PRIMARY_KEY_PREFIX}`;
  };

  /** Full partition key: prefix + SHA-256 hex of the raw token. */
  private getPrimaryKey = (hash: string): string => {
    return `${this.getPrimaryKeyPrefix()}${hash}`;
  };

  /** Expiration timestamp: `nowSec` plus TTL from options (default 60 days). */
  private makeExpiresAt = (nowSec: number): number => {
    return nowSec + (this.options?.ttlDays ?? 60) * 24 * 60 * 60;
  };

  /**
   * Ensures the token is non-empty and matches the expected base64url length for `tokenBytes` (32 bytes → URL-safe base64 length).
   *
   * @throws {@link RefreshTokenInvalidError} When validation fails.
   */
  private validateRefreshToken(token: string): void {
    if (!token || token.length !== Math.ceil(this.tokenBytes * 8 / 6)) {
      throw new RefreshTokenInvalidError();
    }
  }

}
