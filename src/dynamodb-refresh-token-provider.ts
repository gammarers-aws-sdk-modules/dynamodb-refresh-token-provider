import { DynamoDBClient, type DynamoDBClientConfig } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';

import {
  DynamodbRefreshTokenProviderExpiredError,
  DynamodbRefreshTokenProviderInvalidError,
  DynamodbRefreshTokenProviderReusedError,
  DynamodbRefreshTokenProviderRevokedError,
  DynamodbRefreshTokenProviderRotateError,
  DynamodbRefreshTokenProviderValidateError,
} from './core/errors';
import { base64UrlLength, DEFAULT_RANDOM_TOKEN_BYTES, randomToken, sha256Hex } from './core/hash';
import { hasNextPage } from './core/paging-predicates';
import { epochSec, SECONDS_PER_DAY } from './core/time';
import { isLoadedTokenRecord, type LoadedTokenRecord } from './core/token-record-predicates';
import type {
  DynamodbRefreshTokenProviderOptions,
  RefreshTokenStore,
  StoreOptions,
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

/** Default token lifetime in days when neither ttlSeconds nor ttlDays is set. */
const DEFAULT_TTL_DAYS = 60;

/** Condition that the token row exists. */
const ITEM_EXISTS_CONDITION = 'attribute_exists(pk)';

/** Condition that no row with the new partition key exists yet. */
const ITEM_NOT_EXISTS_CONDITION = 'attribute_not_exists(pk)';

/** Condition that the current token row exists and is neither rotated nor revoked. */
const ROTATABLE_CONDITION =
  `${ITEM_EXISTS_CONDITION} AND attribute_not_exists(rotatedAt) AND attribute_not_exists(revokedAt)`;

/** Update expression that marks a token row as revoked at `:now`. */
const REVOKE_UPDATE_EXPRESSION = 'SET revokedAt = :now';

/** DynamoDB error name when a condition expression fails. */
const CONDITIONAL_CHECK_FAILED_EXCEPTION = 'ConditionalCheckFailedException';

/** DynamoDB error name when a transactional write is canceled. */
const TRANSACTION_CANCELED_EXCEPTION = 'TransactionCanceledException';

/** Cancellation reason code when an item's condition expression fails inside a transaction. */
const CONDITIONAL_CHECK_FAILED_REASON = 'ConditionalCheckFailed';

/** Index of the current-token Update in the rotate `TransactItems`. */
const ROTATE_CURRENT_TOKEN_ITEM_INDEX = 0;

/**
 * Returns whether a canceled rotate transaction failed on the current-token Update condition,
 * which means another request already rotated or revoked the token.
 *
 * @param error - `TransactionCanceledException` from the rotate transaction.
 * @returns `true` only when `CancellationReasons` marks the current-token item as `ConditionalCheckFailed`.
 */
const isCurrentTokenConditionFailed = (error: Error): boolean => {
  if (!('CancellationReasons' in error) || !Array.isArray(error.CancellationReasons)) {
    return false;
  }
  const reason: unknown = error.CancellationReasons[ROTATE_CURRENT_TOKEN_ITEM_INDEX];
  if (typeof reason !== 'object' || reason === null || !('Code' in reason)) {
    return false;
  }
  return reason.Code === CONDITIONAL_CHECK_FAILED_REASON;
};

/**
 * {@link RefreshTokenStore} implementation backed by a single DynamoDB table.
 *
 * Items use partition key `pk`, logical expiration `expiresAt`, and DynamoDB TTL attribute `ttl`
 * (Unix seconds). Enable table TTL on attribute `ttl` so expired and rotated rows are removed
 * asynchronously. Session-wide revocation requires a GSI whose partition key is `sessionId`
 * (see {@link StoreOptions.sessionIdIndexName}). Callers supply {@link DynamodbRefreshTokenProviderOptions}
 * with at least `tableName`. A document client is created lazily unless
 * {@link StoreOptions.documentClient} is provided; the AWS SDK resolves region and endpoint when they are omitted.
 */
export class DynamodbRefreshTokenProvider implements RefreshTokenStore {
  /** Lazily initialized and cached document client. */
  private ddb: DynamoDBDocumentClient | null = null;

  /** DynamoDB table name for refresh token items. */
  private readonly tableName: string;

  /** Resolved constructor options (table name, store options, and optional region). */
  private readonly options: DynamodbRefreshTokenProviderOptions;

  /** Random byte length for generated refresh tokens. */
  private readonly tokenBytes: number;

  /**
   * Creates a provider for the refresh-token table.
   *
   * @param options - Table name, optional region, and {@link StoreOptions}.
   * @throws {DynamodbRefreshTokenProviderValidateError} When `tokenBytes`, `ttlSeconds`, or `ttlDays` is invalid,
   *   or when `documentClient` and `clientConfig` are both set.
   */
  constructor(options: DynamodbRefreshTokenProviderOptions);
  /**
   * Creates a provider for the refresh-token table (positional form, kept for compatibility).
   *
   * @deprecated Use `new DynamodbRefreshTokenProvider({ tableName, region, ...options })` instead.
   * @param tableName - DynamoDB table name for refresh token items.
   * @param region - AWS region used when this class constructs the DynamoDB client.
   * @param options - Token lifetime, PK prefix, GSI names, reuse revocation, client injection, or custom endpoint.
   * @throws {DynamodbRefreshTokenProviderValidateError} When `tokenBytes`, `ttlSeconds`, or `ttlDays` is invalid,
   *   or when `documentClient` and `clientConfig` are both set.
   */
  constructor(tableName: string, region: string, options?: StoreOptions);
  constructor(
    tableNameOrOptions: string | DynamodbRefreshTokenProviderOptions,
    region?: string,
    options?: StoreOptions,
  ) {
    this.options = typeof tableNameOrOptions === 'string'
      ? { ...options, tableName: tableNameOrOptions, region }
      : tableNameOrOptions;
    this.tableName = this.options.tableName;

    this.tokenBytes = this.resolveTokenBytes(this.options.tokenBytes);
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
        ConditionExpression: ITEM_NOT_EXISTS_CONDITION,
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
   * @throws {@link DynamodbRefreshTokenProviderReusedError} When the token was already rotated, or the
   *   transaction was canceled because the current token's condition failed (concurrent rotate or revoke).
   *   Includes `subjectId` and `sessionId` from the loaded row.
   * @throws {@link DynamodbRefreshTokenProviderRotateError} When the transaction was canceled for any
   *   other reason (throttling, transaction conflict, successor insert failure). The token is not consumed.
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
              ConditionExpression: ROTATABLE_CONDITION,
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
              ConditionExpression: ITEM_NOT_EXISTS_CONDITION,
            },
          },
        ],
      }));
    } catch (error: unknown) {
      if (!(error instanceof Error) || error.name !== TRANSACTION_CANCELED_EXCEPTION) {
        throw error;
      }
      if (isCurrentTokenConditionFailed(error)) {
        await this.handleRefreshTokenReuse(current, now);
      }
      throw new DynamodbRefreshTokenProviderRotateError(undefined, { cause: error });
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
          UpdateExpression: REVOKE_UPDATE_EXPRESSION,
          ConditionExpression: ITEM_EXISTS_CONDITION,
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
    const indexName = this.options.sessionIdIndexName ?? DEFAULT_SESSION_ID_INDEX_NAME;

    const revokedCount = await this.revokeTokenRowsByIndexQuery({
      indexName,
      keyConditionExpression: 'sessionId = :sessionId',
      queryExpressionAttributeValues: {
        ':sessionId': params.sessionId,
      },
      nowSec,
      updateConditionExpression: params.subjectId
        ? `${ITEM_EXISTS_CONDITION} AND subjectId = :subjectId`
        : ITEM_EXISTS_CONDITION,
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
    const indexName = this.options.subjectIdIndexName ?? DEFAULT_SUBJECT_ID_INDEX_NAME;

    const revokedCount = await this.revokeTokenRowsByIndexQuery({
      indexName,
      keyConditionExpression: 'subjectId = :subjectId',
      queryExpressionAttributeValues: {
        ':subjectId': params.subjectId,
      },
      nowSec,
      updateConditionExpression: ITEM_EXISTS_CONDITION,
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
              UpdateExpression: REVOKE_UPDATE_EXPRESSION,
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
   * @param current - Token row that indicated reuse (`rotatedAt` set or current-token condition failed).
   * @param now - Clock used for `revokedAt` when cascading revoke is enabled.
   * @throws {@link DynamodbRefreshTokenProviderReusedError} Always (return type is `never`).
   */
  private handleRefreshTokenReuse = async (current: LoadedTokenRecord, now: Date): Promise<never> => {
    if (this.options.revokeSessionOnReuse) {
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
      this.ddb = this.options.documentClient ?? this.createDocumentClient();
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
    return DynamoDBDocumentClient.from(client, this.options.translateConfig);
  };

  /**
   * Builds the config for an internally constructed `DynamoDBClient`.
   *
   * Starts from {@link DynamodbRefreshTokenProviderOptions.region} and {@link StoreOptions.endpoint};
   * omitted values stay `undefined` so the AWS SDK resolves them. {@link StoreOptions.clientConfig}
   * is applied last so its fields win.
   *
   * @returns Config passed to `new DynamoDBClient`.
   */
  private resolveClientConfig = (): DynamoDBClientConfig => {
    return {
      region: this.options.region,
      endpoint: this.options.endpoint,
      ...this.options.clientConfig,
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
   * @returns Validated row fields, or `null` if the item does not exist.
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When the item lacks required fields or has
   *   unexpected attribute types.
   */
  private getTokenRecord = async (pk: string): Promise<LoadedTokenRecord | null> => {
    const ddb = this.getDdb();

    const res = await ddb.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { pk },
        ConsistentRead: this.options.consistentRead ?? true,
      }),
    );

    const item: Record<string, unknown> | undefined = res.Item;
    if (!item) {
      return null;
    }
    if (!isLoadedTokenRecord(item)) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }
    return item;
  };

  /**
   * Effective partition key prefix from {@link StoreOptions} or {@link DEFAULT_PRIMARY_KEY_PREFIX}.
   *
   * @returns Prefix string (e.g. `rt#`).
   */
  private getPrimaryKeyPrefix = (): string => {
    return this.options.pkPrefix ?? DEFAULT_PRIMARY_KEY_PREFIX;
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
    const ttlSeconds = this.options.ttlSeconds;
    if (ttlSeconds !== undefined) {
      return nowSec + ttlSeconds;
    }
    return nowSec + (this.options.ttlDays ?? DEFAULT_TTL_DAYS) * SECONDS_PER_DAY;
  };

  /**
   * Resolves and validates {@link StoreOptions.tokenBytes}.
   *
   * @param tokenBytes - Optional byte length from store options.
   * @returns Positive integer byte length.
   * @throws {DynamodbRefreshTokenProviderValidateError} When `tokenBytes` is not a positive integer.
   */
  private resolveTokenBytes = (tokenBytes?: number): number => {
    const bytes = tokenBytes ?? DEFAULT_RANDOM_TOKEN_BYTES;
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
    if (!token || token.length !== base64UrlLength(this.tokenBytes)) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }
  };

}
