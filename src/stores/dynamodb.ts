import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';

import {
  RefreshTokenExpiredError,
  RefreshTokenInvalidError,
  RefreshTokenReusedError,
  RefreshTokenRevokedError,
} from './refresh-token-errors';
import type {
  RefreshTokenStore,
  StoreOptions,
  TokenRecord,
  IssueParams,
  RotateParams,
  RevokeParams,
  RevokeSessionParams,
  RevokeSessionResult,
  IssueResult,
  RotateResult,
} from '../types/index';
import { randomtoken, sha256hex } from '../utils/hash';
import { epochsec } from '../utils/time';

/** Re-exported types for consumers that import the DynamoDB store module. */
export {
  RefreshTokenStore,
  StoreOptions,
  TokenRecord,
  IssueParams,
  RotateParams,
  RevokeParams,
  RevokeSessionParams,
  RevokeSessionResult,
  IssueResult,
  RotateResult,
};

/** Default partition key prefix for refresh token items. */
const DEFAULT_PRIMARY_KEY_PREFIX = 'rt#';

/** Default GSI name for querying token rows by `sessionId`. */
const DEFAULT_SESSION_ID_INDEX_NAME = 'sessionId-index';

/**
 * {@link RefreshTokenStore} implementation backed by a single DynamoDB table.
 *
 * Items use partition key `pk`, logical expiration `expiresAt`, and DynamoDB TTL attribute `ttl`
 * (Unix seconds). Enable table TTL on attribute `ttl` so expired and rotated rows are removed
 * asynchronously. Session-wide revocation requires a GSI whose partition key is `sessionId`
 * (see {@link StoreOptions.sessionIdIndexName}). This class owns the DynamoDB client; callers
 * supply `tableName`, `region`, and optional {@link StoreOptions}.
 */
export class DynamodbRefreshTokenProvider implements RefreshTokenStore {
  /** Lazily initialized and cached document client. */
  private ddb: DynamoDBDocumentClient | null = null;

  /** Random byte length for generated refresh tokens (default 32 → 256-bit). */
  private readonly tokenBytes = 32;

  /**
   * @param tableName - DynamoDB table name for refresh token items.
   * @param region - AWS region for the DynamoDB client.
   * @param options - Token lifetime, PK prefix, GSI name, reuse revocation, or custom endpoint.
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
   * When reuse is detected and {@link StoreOptions.revokeSessionOnReuse} is true, all tokens for
   * the same `sessionId` and `subjectId` are revoked via {@link DynamodbRefreshTokenProvider.revokeSession}
   * before throwing.
   *
   * @param params - Client refresh token and optional clock (`now`).
   * @returns Subject, session, new plaintext token, and new expiration.
   * @throws {@link RefreshTokenInvalidError} When the token format is invalid or no row exists.
   * @throws {@link RefreshTokenExpiredError} When `expiresAt` is not after `now`.
   * @throws {@link RefreshTokenRevokedError} When the token row has `revokedAt` set.
   * @throws {@link RefreshTokenReusedError} When the token was already rotated or the transaction
   *   indicates reuse. Includes `subjectId` and `sessionId` from the loaded row.
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
      await this.handleRefreshTokenReuse(current, now);
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
        await this.handleRefreshTokenReuse(current, now);
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
   * Sets `revokedAt` on every token row for the given `sessionId` (optionally filtered by `subjectId`).
   *
   * Queries the session GSI (partition key `sessionId`; `KEYS_ONLY` is enough), then updates each
   * base-table item. When `subjectId` is set, it is required in the `UpdateItem` condition.
   * Missing or non-matching items are skipped (idempotent). Paginate with `LastEvaluatedKey`.
   *
   * @param params - Session id, optional subject filter, and optional clock.
   * @returns Count of rows updated with `revokedAt` in this call.
   */
  public revokeSession = async (params: RevokeSessionParams): Promise<RevokeSessionResult> => {
    const ddb = this.getddb();

    const now = params.now ?? new Date();
    const nowSec = epochsec(now);
    const indexName = this.options?.sessionIdIndexName ?? DEFAULT_SESSION_ID_INDEX_NAME;

    let revokedCount = 0;
    let exclusiveStartKey: Record<string, unknown> | undefined;

    /** Whether another Query page is available after the previous response. */
    const shouldContinuePaging = (): boolean => exclusiveStartKey !== undefined;

    do {
      const res = await ddb.send(
        new QueryCommand({
          TableName: this.tableName,
          IndexName: indexName,
          KeyConditionExpression: 'sessionId = :sessionId',
          ExpressionAttributeValues: {
            ':sessionId': params.sessionId,
          },
          ProjectionExpression: 'pk',
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );

      const items = res.Items ?? [];
      for (const item of items) {
        const pk = item.pk;
        if (typeof pk !== 'string') {
          continue;
        }

        const expressionAttributeValues: Record<string, string | number> = {
          ':now': nowSec,
        };
        let conditionExpression = 'attribute_exists(pk)';
        if (params.subjectId) {
          conditionExpression = 'attribute_exists(pk) AND subjectId = :subjectId';
          expressionAttributeValues[':subjectId'] = params.subjectId;
        }

        try {
          await ddb.send(
            new UpdateCommand({
              TableName: this.tableName,
              Key: { pk },
              UpdateExpression: 'SET revokedAt = :now',
              ConditionExpression: conditionExpression,
              ExpressionAttributeValues: expressionAttributeValues,
            }),
          );
          revokedCount += 1;
        } catch (error: unknown) {
          if (error instanceof Error && error.name === 'ConditionalCheckFailedException') {
            continue;
          }
          throw error;
        }
      }

      exclusiveStartKey = res.LastEvaluatedKey as Record<string, unknown> | undefined;
    } while (shouldContinuePaging());

    return { revokedCount };
  };

  /**
   * Handles refresh-token reuse detection: optionally cascades {@link DynamodbRefreshTokenProvider.revokeSession}
   * when {@link StoreOptions.revokeSessionOnReuse} is true, then throws {@link RefreshTokenReusedError}
   * populated with `subjectId` / `sessionId` from `current`.
   *
   * @param current - Token row that indicated reuse (`rotatedAt` set or transaction canceled).
   * @param now - Clock used for `revokedAt` when cascading revoke is enabled.
   * @throws {@link RefreshTokenReusedError} Always (return type is `never`).
   */
  private handleRefreshTokenReuse = async (current: TokenRecord, now: Date): Promise<never> => {
    if (this.options?.revokeSessionOnReuse) {
      await this.revokeSession({
        sessionId: current.sessionId,
        subjectId: current.subjectId,
        now,
      });
    }

    throw new RefreshTokenReusedError(undefined, {
      subjectId: current.subjectId,
      sessionId: current.sessionId,
    });
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
