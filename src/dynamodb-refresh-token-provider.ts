import { DynamoDBClient, type DynamoDBClientConfig } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';

import {
  DynamodbRefreshTokenProviderExpiredError,
  DynamodbRefreshTokenProviderInvalidError,
  DynamodbRefreshTokenProviderReusedError,
  DynamodbRefreshTokenProviderRevokedError,
  DynamodbRefreshTokenProviderValidateError,
} from './core/errors';
import { randomToken, sha256Hex } from './core/hash';
import { hasNextPage } from './core/paging-predicates';
import { epochSec } from './core/time';
import type {
  RefreshTokenStore,
  StoreOptions,
  TokenRecord,
  IssueParams,
  RotateParams,
  RevokeParams,
  RevokeSessionParams,
  RevokeSessionResult,
  RevokeSubjectParams,
  RevokeSubjectResult,
  IssueResult,
  RotateResult,
} from './core/types';

/** Default partition key prefix for refresh token items. */
const DEFAULT_PRIMARY_KEY_PREFIX = 'rt#';

/** Default GSI name for querying token rows by `sessionId`. */
const DEFAULT_SESSION_ID_INDEX_NAME = 'sessionId-index';

/** Default GSI name for querying token rows by `subjectId`. */
const DEFAULT_SUBJECT_ID_INDEX_NAME = 'subjectId-index';

/** Default random byte length for generated refresh tokens (32 → 256-bit). */
const DEFAULT_TOKEN_BYTES = 32;

/** Default token lifetime in days when neither ttlSeconds nor ttlDays is set. */
const DEFAULT_TTL_DAYS = 60;

/** DynamoDB error name when a condition expression fails. */
const CONDITIONAL_CHECK_FAILED_EXCEPTION = 'ConditionalCheckFailedException';

/** DynamoDB error name when a transactional write is canceled. */
const TRANSACTION_CANCELED_EXCEPTION = 'TransactionCanceledException';

/**
 * {@link RefreshTokenStore} implementation backed by a single DynamoDB table.
 *
 * Items use partition key `pk`, logical expiration `expiresAt`, and DynamoDB TTL attribute `ttl`
 * (Unix seconds). Enable table TTL on attribute `ttl` so expired and rotated rows are removed
 * asynchronously. Session-wide revocation requires a GSI whose partition key is `sessionId`
 * (see {@link StoreOptions.sessionIdIndexName}). Callers supply `tableName`, `region`, and optional
 * {@link StoreOptions}. A document client is created lazily from `region` unless
 * {@link StoreOptions.documentClient} is provided.
 */
export class DynamodbRefreshTokenProvider implements RefreshTokenStore {
  /** Lazily initialized and cached document client. */
  private ddb: DynamoDBDocumentClient | null = null;

  /** Random byte length for generated refresh tokens. */
  private readonly tokenBytes: number;

  /**
   * Creates a provider for the refresh-token table.
   *
   * @param tableName - DynamoDB table name for refresh token items.
   * @param region - AWS region used when this class constructs the DynamoDB client.
   *   Unused for client construction when {@link StoreOptions.documentClient} is set.
   * @param options - Token lifetime, PK prefix, GSI names, reuse revocation, client injection, or custom endpoint.
   * @throws {DynamodbRefreshTokenProviderValidateError} When `tokenBytes`, `ttlSeconds`, or `ttlDays` is invalid,
   *   or when `documentClient` and `clientConfig` are both set.
   */
  constructor(
    private readonly tableName: string,
    private readonly region: string,
    private readonly options?: StoreOptions,
  ) {
    this.tokenBytes = this.resolveTokenBytes(this.options?.tokenBytes);
    this.validateTtlOptions(this.options);
    this.validateClientOptions(this.options);
  }

  /**
   * Inserts a new token record with `expiresAt` and matching `ttl`. Fails the put if `pk` already exists.
   *
   * @param params - Subject, session, and optional clock (`now`).
   * @returns Plaintext refresh token and expiration as Unix seconds.
   */
  public issue = async (params: IssueParams): Promise<IssueResult> => {
    const ddb = this.getDdb();

    const now = params.now ?? new Date();
    const nowSec = epochSec(now);
    const expiresAt = this.makeExpiresAt(nowSec);

    const refreshToken = randomToken(this.tokenBytes);
    const hash = sha256Hex(refreshToken);
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
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When the token format is invalid or no row exists.
   * @throws {@link DynamodbRefreshTokenProviderExpiredError} When `expiresAt` is not after `now`.
   * @throws {@link DynamodbRefreshTokenProviderRevokedError} When the token row has `revokedAt` set.
   * @throws {@link DynamodbRefreshTokenProviderReusedError} When the token was already rotated or the transaction
   *   indicates reuse. Includes `subjectId` and `sessionId` from the loaded row.
   */
  public rotate = async (params: RotateParams): Promise<RotateResult> => {
    // validate refresh token
    this.validateRefreshToken(params.refreshToken);

    const ddb = this.getDdb();

    const now = params.now ?? new Date();
    const nowSec = epochSec(now);

    const currentHash = sha256Hex(params.refreshToken);
    const currentPk = this.getPrimaryKey(currentHash);

    const current = await this.getTokenRecord(currentPk);
    if (!current) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }
    if (current.expiresAt <= nowSec) {
      throw new DynamodbRefreshTokenProviderExpiredError();
    }
    if (current.revokedAt) {
      throw new DynamodbRefreshTokenProviderRevokedError();
    }
    if (current.rotatedAt) {
      await this.handleRefreshTokenReuse(current, now);
    }

    const nextRefreshTokenExpiresAt = this.makeExpiresAt(nowSec);
    const nextRefreshToken = randomToken(this.tokenBytes);
    const nextHash = sha256Hex(nextRefreshToken);
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
      if (error instanceof Error && error.name === TRANSACTION_CANCELED_EXCEPTION) {
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
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When the token string format is invalid.
   */
  public revoke = async (params: RevokeParams): Promise<true> => {
    // validate refresh token
    this.validateRefreshToken(params.refreshToken);

    const ddb = this.getDdb();

    const now = params.now ?? new Date();
    const nowSec = epochSec(now);

    const hash = sha256Hex(params.refreshToken);
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
      if (error instanceof Error && error.name === CONDITIONAL_CHECK_FAILED_EXCEPTION) {
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
    const now = params.now ?? new Date();
    const nowSec = epochSec(now);
    const indexName = this.options?.sessionIdIndexName ?? DEFAULT_SESSION_ID_INDEX_NAME;

    const revokedCount = await this.revokeTokenRowsByIndexQuery({
      indexName,
      keyConditionExpression: 'sessionId = :sessionId',
      queryExpressionAttributeValues: {
        ':sessionId': params.sessionId,
      },
      nowSec,
      updateConditionExpression: params.subjectId
        ? 'attribute_exists(pk) AND subjectId = :subjectId'
        : 'attribute_exists(pk)',
      updateExpressionAttributeValues: params.subjectId
        ? { ':subjectId': params.subjectId }
        : undefined,
    });

    return { revokedCount };
  };

  /**
   * Sets `revokedAt` on every refresh token row for the given `subjectId` across all sessions.
   *
   * Queries the subject GSI (partition key `subjectId`; `KEYS_ONLY` is enough), then updates each
   * base-table item. Missing items are skipped (idempotent). Paginate with `LastEvaluatedKey`.
   *
   * @param params - Subject id and optional clock.
   * @returns Count of rows updated with `revokedAt` in this call.
   */
  public revokeSubject = async (params: RevokeSubjectParams): Promise<RevokeSubjectResult> => {
    const now = params.now ?? new Date();
    const nowSec = epochSec(now);
    const indexName = this.options?.subjectIdIndexName ?? DEFAULT_SUBJECT_ID_INDEX_NAME;

    const revokedCount = await this.revokeTokenRowsByIndexQuery({
      indexName,
      keyConditionExpression: 'subjectId = :subjectId',
      queryExpressionAttributeValues: {
        ':subjectId': params.subjectId,
      },
      nowSec,
      updateConditionExpression: 'attribute_exists(pk)',
    });

    return { revokedCount };
  };

  /**
   * Queries a GSI and sets `revokedAt` on each matching base-table row.
   *
   * @param params - GSI query parameters and per-row update conditions.
   * @returns Count of rows updated with `revokedAt` in this call.
   */
  private revokeTokenRowsByIndexQuery = async (params: {
    indexName: string;
    keyConditionExpression: string;
    queryExpressionAttributeValues: Record<string, string>;
    nowSec: number;
    updateConditionExpression: string;
    updateExpressionAttributeValues?: Record<string, string>;
  }): Promise<number> => {
    const ddb = this.getDdb();

    let revokedCount = 0;
    let exclusiveStartKey: Record<string, unknown> | undefined;

    do {
      const res = await ddb.send(
        new QueryCommand({
          TableName: this.tableName,
          IndexName: params.indexName,
          KeyConditionExpression: params.keyConditionExpression,
          ExpressionAttributeValues: params.queryExpressionAttributeValues,
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
          ':now': params.nowSec,
          ...params.updateExpressionAttributeValues,
        };

        try {
          await ddb.send(
            new UpdateCommand({
              TableName: this.tableName,
              Key: { pk },
              UpdateExpression: 'SET revokedAt = :now',
              ConditionExpression: params.updateConditionExpression,
              ExpressionAttributeValues: expressionAttributeValues,
            }),
          );
          revokedCount += 1;
        } catch (error: unknown) {
          if (error instanceof Error && error.name === CONDITIONAL_CHECK_FAILED_EXCEPTION) {
            continue;
          }
          throw error;
        }
      }

      exclusiveStartKey = res.LastEvaluatedKey as Record<string, unknown> | undefined;
    } while (hasNextPage(exclusiveStartKey));

    return revokedCount;
  };

  /**
   * Handles refresh-token reuse detection: optionally cascades {@link DynamodbRefreshTokenProvider.revokeSession}
   * when {@link StoreOptions.revokeSessionOnReuse} is true, then throws {@link DynamodbRefreshTokenProviderReusedError}
   * populated with `subjectId` / `sessionId` from `current`.
   *
   * @param current - Token row that indicated reuse (`rotatedAt` set or transaction canceled).
   * @param now - Clock used for `revokedAt` when cascading revoke is enabled.
   * @throws {@link DynamodbRefreshTokenProviderReusedError} Always (return type is `never`).
   */
  private handleRefreshTokenReuse = async (current: TokenRecord, now: Date): Promise<never> => {
    if (this.options?.revokeSessionOnReuse) {
      await this.revokeSession({
        sessionId: current.sessionId,
        subjectId: current.subjectId,
        now,
      });
    }

    throw new DynamodbRefreshTokenProviderReusedError(undefined, {
      subjectId: current.subjectId,
      sessionId: current.sessionId,
    });
  };

  /**
   * Returns the cached {@link DynamoDBDocumentClient}, creating it on first use.
   *
   * {@link StoreOptions.documentClient} is used as-is. Otherwise a client is built from
   * {@link DynamodbRefreshTokenProvider.resolveClientConfig}.
   *
   * @returns Document client used for store commands.
   */
  private getDdb = (): DynamoDBDocumentClient => {
    if (!this.ddb) {
      this.ddb = this.options?.documentClient ?? this.createDocumentClient();
    }
    return this.ddb;
  };

  /**
   * Constructs a document client from {@link StoreOptions.clientConfig} and `translateConfig`.
   *
   * @returns Document client owned by this provider.
   */
  private createDocumentClient = (): DynamoDBDocumentClient => {
    const client = new DynamoDBClient(this.resolveClientConfig());
    return DynamoDBDocumentClient.from(client, this.options?.translateConfig);
  };

  /**
   * Builds the config for an internally constructed `DynamoDBClient`.
   *
   * Starts from the constructor `region` and {@link StoreOptions.endpoint} (or the regional
   * DynamoDB endpoint). {@link StoreOptions.clientConfig} is applied last so its fields win.
   *
   * @returns Config passed to `new DynamoDBClient`.
   */
  private resolveClientConfig = (): DynamoDBClientConfig => {
    const endpoint = this.options?.endpoint ?? `https://dynamodb.${this.region}.amazonaws.com`;
    return {
      region: this.region,
      endpoint,
      ...this.options?.clientConfig,
    };
  };

  /**
   * Rejects combining an injected document client with client construction config.
   *
   * @param options - Store options from the constructor.
   * @throws {DynamodbRefreshTokenProviderValidateError} When `documentClient` and `clientConfig` are both set.
   */
  private validateClientOptions = (options?: StoreOptions): void => {
    if (options?.documentClient !== undefined && options.clientConfig !== undefined) {
      throw new DynamodbRefreshTokenProviderValidateError(
        'documentClient and clientConfig are mutually exclusive',
      );
    }
  };

  /**
   * Loads a token row by partition key.
   *
   * @param pk - Full partition key (`prefix` + hash).
   * @returns Parsed {@link TokenRecord}, or `null` if the item does not exist.
   */
  private getTokenRecord = async (pk: string): Promise<TokenRecord | null> => {
    const ddb = this.getDdb();

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
   * Computes logical expiration (`expiresAt` / `ttl`) as `nowSec` plus configured lifetime.
   *
   * @param nowSec - Current time as Unix seconds.
   * @returns Expiration timestamp in Unix seconds.
   */
  private makeExpiresAt = (nowSec: number): number => {
    const ttlSeconds = this.options?.ttlSeconds;
    if (ttlSeconds !== undefined) {
      return nowSec + ttlSeconds;
    }
    return nowSec + (this.options?.ttlDays ?? DEFAULT_TTL_DAYS) * 24 * 60 * 60;
  };

  /**
   * Resolves and validates {@link StoreOptions.tokenBytes}.
   *
   * @param tokenBytes - Optional byte length from store options.
   * @returns Positive integer byte length.
   * @throws {DynamodbRefreshTokenProviderValidateError} When `tokenBytes` is not a positive integer.
   */
  private resolveTokenBytes = (tokenBytes?: number): number => {
    const bytes = tokenBytes ?? DEFAULT_TOKEN_BYTES;
    if (!Number.isInteger(bytes) || bytes < 1) {
      throw new DynamodbRefreshTokenProviderValidateError('tokenBytes must be a positive integer');
    }
    return bytes;
  };

  /**
   * Validates TTL-related store options at construction time.
   *
   * @param options - Store options from the constructor.
   * @throws {DynamodbRefreshTokenProviderValidateError} When `ttlSeconds` or `ttlDays` is not a positive number.
   */
  private validateTtlOptions = (options?: StoreOptions): void => {
    if (options?.ttlSeconds !== undefined && options.ttlSeconds <= 0) {
      throw new DynamodbRefreshTokenProviderValidateError('ttlSeconds must be a positive number');
    }
    if (options?.ttlDays !== undefined && options.ttlDays <= 0) {
      throw new DynamodbRefreshTokenProviderValidateError('ttlDays must be a positive number');
    }
  };

  /**
   * Ensures the token is non-empty and matches the expected base64url length for `tokenBytes`.
   *
   * @param token - Plaintext refresh token from the client.
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When validation fails.
   */
  private validateRefreshToken = (token: string): void => {
    if (!token || token.length !== Math.ceil(this.tokenBytes * 8 / 6)) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }
  };

}
