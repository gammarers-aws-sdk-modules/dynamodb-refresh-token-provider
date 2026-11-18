import { DynamoDBClient, type DynamoDBClientConfig } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type TransactWriteCommandInput,
} from '@aws-sdk/lib-dynamodb';

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
import {
  INITIAL_SUBJECT_GENERATION,
  isSessionMarker,
  isSessionRevoked,
  isSubjectMarker,
  SESSION_NOT_REVOKED_CONDITION,
  sessionMarkerPk,
  sessionSubjectMarkerPk,
  SUBJECT_GENERATION_STEP,
  subjectGenerationCondition,
  subjectMarkerGeneration,
  subjectMarkerPk,
  tokenSubjectGeneration,
} from './core/revocation-predicates';
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

/** Update expression that marks a row revoked at `:now`. */
const REVOKE_UPDATE_EXPRESSION = 'SET revokedAt = :now';

/** Update expression that advances the subject generation, creating the marker at 1 when absent. */
const INCREMENT_SUBJECT_GENERATION_EXPRESSION =
  'SET generation = if_not_exists(generation, :zero) + :one';

/** DynamoDB error name when a condition expression fails. */
const CONDITIONAL_CHECK_FAILED_EXCEPTION = 'ConditionalCheckFailedException';

/** DynamoDB error name when a transactional write is canceled. */
const TRANSACTION_CANCELED_EXCEPTION = 'TransactionCanceledException';

/** Cancellation reason code when an item's condition expression fails inside a transaction. */
const CONDITIONAL_CHECK_FAILED_REASON = 'ConditionalCheckFailed';

/** Index of the current-token Update in the rotate `TransactItems`. */
const ROTATE_CURRENT_TOKEN_ITEM_INDEX = 0;

/**
 * Indexes of the revocation `ConditionCheck`s in an issue transaction.
 * Order is session marker, session-subject marker, subject marker. The token `Put` follows them.
 */
const ISSUE_REVOCATION_ITEM_INDEXES = [0, 1, 2] as const;

/**
 * Indexes of the revocation `ConditionCheck`s in a rotate transaction.
 * They follow the current-token Update (0) and the successor Put (1).
 */
const ROTATE_REVOCATION_ITEM_INDEXES = [2, 3, 4] as const;

/** Session and subject markers loaded before issue or rotate. */
type FamilyMarkers = {
  /** `sess#<sessionId>` has `revokedAt`. */
  sessionRevoked: boolean;
  /** `sess#<sessionId>#<subjectId>` has `revokedAt`. */
  sessionSubjectRevoked: boolean;
  /** Generation on `sub#<subjectId>`, or 0 when that row is absent. */
  subjectGeneration: number;
};

/**
 * Whether one item in a canceled transaction failed its condition.
 *
 * @param error - `TransactionCanceledException` from `TransactWriteItems`.
 * @param index - Index into `CancellationReasons` and `TransactItems`.
 * @returns `true` when that reason's `Code` is `ConditionalCheckFailed`.
 */
const isConditionFailedAt = (error: Error, index: number): boolean => {
  if (!('CancellationReasons' in error) || !Array.isArray(error.CancellationReasons)) {
    return false;
  }
  const reason: unknown = error.CancellationReasons[index];
  if (typeof reason !== 'object' || reason === null || !('Code' in reason)) {
    return false;
  }
  return reason.Code === CONDITIONAL_CHECK_FAILED_REASON;
};

/**
 * Whether `error` is a canceled transaction.
 *
 * @param error - Value caught from `TransactWriteItems`.
 * @returns `true` when `error` is an `Error` named `TransactionCanceledException`.
 */
const isTransactionCanceled = (error: unknown): error is Error =>
  error instanceof Error && error.name === TRANSACTION_CANCELED_EXCEPTION;

/**
 * Whether a canceled transaction failed a revocation `ConditionCheck`.
 *
 * A session or subject marker failure means the write must not land, even when the
 * current token's condition failed in the same transaction.
 *
 * @param error - Value caught from `TransactWriteItems`.
 * @param indexes - `TransactItems` indexes of the revocation `ConditionCheck`s.
 * @returns `true` when any of those reasons is `ConditionalCheckFailed`.
 */
const isRevocationConditionFailed = (error: unknown, indexes: readonly number[]): boolean => {
  if (!isTransactionCanceled(error)) {
    return false;
  }
  return indexes.some((index) => isConditionFailedAt(error, index));
};

/**
 * {@link RefreshTokenStore} implementation backed by a single DynamoDB table.
 *
 * Items use partition key `pk`, logical expiration `expiresAt`, and DynamoDB TTL attribute `ttl`
 * (Unix seconds). Enable table TTL on attribute `ttl` so expired and rotated rows are removed
 * asynchronously. Session-wide revocation requires a GSI whose partition key is `sessionId`
 * (see {@link StoreOptions.sessionIdIndexName}). `revokeSession` and `revokeSubject` also write
 * marker rows that `issue` and `rotate` condition-check in the same transaction, so a token the
 * GSI has not indexed yet cannot stay active. Callers supply {@link DynamodbRefreshTokenProviderOptions}
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
   * @throws {@link DynamodbRefreshTokenProviderValidateError} When `tokenBytes`, `ttlSeconds`, or `ttlDays` is invalid,
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
   * @throws {@link DynamodbRefreshTokenProviderValidateError} When `tokenBytes`, `ttlSeconds`, or `ttlDays` is invalid,
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
   * Inserts a new token record with `expiresAt`, matching `ttl`, and the current subject generation.
   *
   * The write is a transaction: revocation `ConditionCheck`s on the session marker, the
   * session-subject marker, and the subject generation marker, then the token `Put`.
   * A revoked session or session-subject pair is rejected. A prior `revokeSubject` does not
   * reject `issue`; the new token stores the generation that revocation advanced to.
   *
   * @param params - Subject, session, and optional clock (`now`).
   * @returns Plaintext refresh token and expiration as Unix seconds.
   * @throws {@link DynamodbRefreshTokenProviderRevokedError} When the session or the session-subject pair is revoked,
   *   including when that revocation wins the race inside the transaction.
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When a revocation marker has an unexpected attribute type.
   */
  public issue = async (params: IssueParams): Promise<IssueResult> => {
    const now = params.now ?? new Date();
    const nowSec = epochSec(now);
    const expiresAt = this.makeExpiresAt(nowSec);
    const generation = await this.requireIssuableSession(params.sessionId, params.subjectId);

    const refreshToken = randomToken(this.tokenBytes);
    const hash = sha256Hex(refreshToken);
    const pk = this.getPrimaryKey(hash);

    try {
      await this.getDdb().send(new TransactWriteCommand({
        TransactItems: [
          ...this.familyConditionChecks(params.sessionId, params.subjectId, generation),
          {
            Put: {
              TableName: this.tableName,
              Item: {
                pk,
                subjectId: params.subjectId,
                sessionId: params.sessionId,
                createdAt: nowSec,
                expiresAt,
                ttl: expiresAt,
                subjectGeneration: generation,
              },
              ConditionExpression: ITEM_NOT_EXISTS_CONDITION,
            },
          },
        ],
      }));
    } catch (error: unknown) {
      if (isRevocationConditionFailed(error, ISSUE_REVOCATION_ITEM_INDEXES)) {
        throw new DynamodbRefreshTokenProviderRevokedError();
      }
      throw error;
    }

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
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When the token format is invalid, no row exists,
   *   or the stored row lacks required fields or has unexpected attribute types.
   * @throws {@link DynamodbRefreshTokenProviderExpiredError} When `expiresAt` is not after `now`.
   * @throws {@link DynamodbRefreshTokenProviderRevokedError} When the token row has `revokedAt` set,
   *   the session or session-subject marker is revoked, or the token's subject generation is stale.
   *   A revocation `ConditionCheck` failure inside the transaction is the same error.
   * @throws {@link DynamodbRefreshTokenProviderReusedError} When the token was already rotated, or the
   *   transaction was canceled because the current token's condition failed (concurrent rotate or revoke)
   *   and no revocation marker condition failed. Includes `subjectId` and `sessionId` from the loaded row.
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

    const generation = tokenSubjectGeneration(current.subjectGeneration);
    await this.requireCurrentFamily(current.sessionId, current.subjectId, generation);
    if (current.rotatedAt) {
      throw await this.handleRefreshTokenReuse(current, now);
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
                subjectGeneration: generation,
              },
              ConditionExpression: ITEM_NOT_EXISTS_CONDITION,
            },
          },
          ...this.familyConditionChecks(current.sessionId, current.subjectId, generation),
        ],
      }));
    } catch (error: unknown) {
      if (!isTransactionCanceled(error)) {
        throw error;
      }
      if (isRevocationConditionFailed(error, ROTATE_REVOCATION_ITEM_INDEXES)) {
        throw new DynamodbRefreshTokenProviderRevokedError();
      }
      if (isConditionFailedAt(error, ROTATE_CURRENT_TOKEN_ITEM_INDEX)) {
        throw await this.handleRefreshTokenReuse(current, now);
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
   * Revokes a session by writing a marker, then stamping token rows the session GSI returns.
   *
   * The marker is written first (`sess#<sessionId>`, or `sess#<sessionId>#<subjectId>` when
   * `subjectId` is set). A token created around the same time can be missing from the GSI, which
   * is only eventually consistent. `issue` and `rotate` condition-check the marker, so that token
   * still cannot be used. The GSI sweep is what sets `revokedAt` on rows the index already lists.
   * `revokedCount` counts those token updates only.
   *
   * When `subjectId` is set, it is required in each token `UpdateItem` condition.
   * Missing or non-matching token items are skipped (idempotent). Paginate with `LastEvaluatedKey`.
   *
   * @param params - Session id, optional subject filter, and optional clock.
   * @returns Count of token rows updated with `revokedAt` in this call.
   */
  public revokeSession = async (params: RevokeSessionParams): Promise<RevokeSessionResult> => {
    const now = params.now ?? new Date();
    const nowSec = epochSec(now);
    const markerPk = params.subjectId
      ? sessionSubjectMarkerPk(params.sessionId, params.subjectId)
      : sessionMarkerPk(params.sessionId);
    await this.writeRevokedMarker(markerPk, nowSec);

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
   * Revokes a subject's current tokens by advancing `generation`, then stamping GSI hits.
   *
   * The generation write comes first. A successor the subject GSI has not indexed yet still fails
   * `rotate`, because the transaction requires the token's stored generation. A later `issue`
   * reads the new generation and succeeds, which is what a password change needs.
   * `revokedCount` counts token-row updates only.
   *
   * Missing token items are skipped (idempotent). Paginate with `LastEvaluatedKey`.
   *
   * @param params - Subject id and optional clock.
   * @returns Count of token rows updated with `revokedAt` in this call.
   */
  public revokeSubject = async (params: RevokeSubjectParams): Promise<RevokeSubjectResult> => {
    const now = params.now ?? new Date();
    const nowSec = epochSec(now);
    await this.incrementSubjectGeneration(params.subjectId);

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
   * when {@link StoreOptions.revokeSessionOnReuse} is true, then returns {@link DynamodbRefreshTokenProviderReusedError}
   * populated with `subjectId` / `sessionId` from `current` for the caller to throw.
   *
   * @param current - Token row that indicated reuse (`rotatedAt` set or current-token condition failed).
   * @param now - Clock used for `revokedAt` when cascading revoke is enabled.
   * @returns Reuse error to throw.
   */
  private handleRefreshTokenReuse = async (
    current: LoadedTokenRecord,
    now: Date,
  ): Promise<DynamodbRefreshTokenProviderReusedError> => {
    if (this.options.revokeSessionOnReuse) {
      await this.revokeSession({
        sessionId: current.sessionId,
        subjectId: current.subjectId,
        now,
      });
    }

    return new DynamodbRefreshTokenProviderReusedError(undefined, {
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
   * @throws {@link DynamodbRefreshTokenProviderValidateError} When `documentClient` and `clientConfig` are both set.
   */
  private validateClientOptions = (options?: StoreOptions): void => {
    if (options?.documentClient !== undefined && options.clientConfig !== undefined) {
      throw new DynamodbRefreshTokenProviderValidateError(
        'documentClient and clientConfig are mutually exclusive',
      );
    }
  };

  /**
   * Condition checks that reject a token write when a revocation marker disagrees.
   *
   * They share the transaction with the token write, so the decision sees the markers
   * with strong consistency even if `consistentRead` is false on the preceding `GetItem`s.
   *
   * @param sessionId - Session whose marker must not be revoked.
   * @param subjectId - Subject whose generation the token is bound to.
   * @param generation - Generation stored on the token.
   * @returns Items in session, session-subject, subject order.
   */
  private familyConditionChecks = (
    sessionId: string,
    subjectId: string,
    generation: number,
  ): NonNullable<TransactWriteCommandInput['TransactItems']> => {
    return [
      {
        ConditionCheck: {
          TableName: this.tableName,
          Key: { pk: sessionMarkerPk(sessionId) },
          ConditionExpression: SESSION_NOT_REVOKED_CONDITION,
        },
      },
      {
        ConditionCheck: {
          TableName: this.tableName,
          Key: { pk: sessionSubjectMarkerPk(sessionId, subjectId) },
          ConditionExpression: SESSION_NOT_REVOKED_CONDITION,
        },
      },
      {
        ConditionCheck: {
          TableName: this.tableName,
          Key: { pk: subjectMarkerPk(subjectId) },
          ConditionExpression: subjectGenerationCondition(generation),
          ExpressionAttributeValues: {
            ':generation': generation,
          },
        },
      },
    ];
  };

  /**
   * Reads the three revocation markers for a session and subject.
   *
   * @param sessionId - Session identifier.
   * @param subjectId - Subject identifier.
   * @returns Whether each session marker is revoked, and the subject generation.
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When a marker attribute has an unexpected type.
   */
  private loadFamilyMarkers = async (sessionId: string, subjectId: string): Promise<FamilyMarkers> => {
    const [sessionItem, pairItem, subjectItem] = await Promise.all([
      this.getItem(sessionMarkerPk(sessionId)),
      this.getItem(sessionSubjectMarkerPk(sessionId, subjectId)),
      this.getItem(subjectMarkerPk(subjectId)),
    ]);

    if (sessionItem !== undefined && !isSessionMarker(sessionItem)) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }
    if (pairItem !== undefined && !isSessionMarker(pairItem)) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }
    if (subjectItem !== undefined && !isSubjectMarker(subjectItem)) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }

    return {
      sessionRevoked: isSessionRevoked(sessionItem),
      sessionSubjectRevoked: isSessionRevoked(pairItem),
      subjectGeneration: subjectMarkerGeneration(subjectItem),
    };
  };

  /**
   * Requires that a new token may be issued, and returns the generation to store on it.
   *
   * Subject generation is not a lockout. After `revokeSubject`, this returns the new generation
   * so the next login can issue. A session `revokedAt` is terminal for that session id.
   *
   * @param sessionId - Session to issue into.
   * @param subjectId - Subject to issue for.
   * @returns Current subject generation.
   * @throws {@link DynamodbRefreshTokenProviderRevokedError} When the session or the session-subject pair is revoked.
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When a revocation marker has an unexpected attribute type.
   */
  private requireIssuableSession = async (sessionId: string, subjectId: string): Promise<number> => {
    const markers = await this.loadFamilyMarkers(sessionId, subjectId);
    if (markers.sessionRevoked || markers.sessionSubjectRevoked) {
      throw new DynamodbRefreshTokenProviderRevokedError();
    }
    return markers.subjectGeneration;
  };

  /**
   * Requires that a token's session is active and its subject generation is still current.
   *
   * @param sessionId - Session on the token row.
   * @param subjectId - Subject on the token row.
   * @param tokenGeneration - Generation stored on the token. Absent means 0.
   * @throws {@link DynamodbRefreshTokenProviderRevokedError} When the family is revoked.
   * @throws {@link DynamodbRefreshTokenProviderInvalidError} When a revocation marker has an unexpected attribute type.
   */
  private requireCurrentFamily = async (
    sessionId: string,
    subjectId: string,
    tokenGeneration: number,
  ): Promise<void> => {
    const markers = await this.loadFamilyMarkers(sessionId, subjectId);
    if (markers.sessionRevoked || markers.sessionSubjectRevoked) {
      throw new DynamodbRefreshTokenProviderRevokedError();
    }
    if (markers.subjectGeneration !== tokenGeneration) {
      throw new DynamodbRefreshTokenProviderRevokedError();
    }
  };

  /**
   * Upserts `revokedAt` on a session marker.
   *
   * No condition: a missing row is created. The item does not carry `sessionId`, so the session
   * GSI does not return it. `ttl` is omitted because a token chain can outlive the configured
   * lifetime through rotation, and deleting the marker would make a missed token usable again.
   *
   * @param pk - Marker partition key.
   * @param nowSec - Revocation time as Unix seconds.
   */
  private writeRevokedMarker = async (pk: string, nowSec: number): Promise<void> => {
    await this.getDdb().send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk },
      UpdateExpression: REVOKE_UPDATE_EXPRESSION,
      ExpressionAttributeValues: {
        ':now': nowSec,
      },
    }));
  };

  /**
   * Advances the subject generation marker by one, creating it at 1 when absent.
   *
   * Repeating the call keeps moving the generation forward, so tokens issued earlier stay stale.
   * The row is not given `ttl`; it is the permanent record of how far revocation has moved.
   *
   * @param subjectId - Subject whose tokens should stop rotating.
   */
  private incrementSubjectGeneration = async (subjectId: string): Promise<void> => {
    await this.getDdb().send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: subjectMarkerPk(subjectId) },
      UpdateExpression: INCREMENT_SUBJECT_GENERATION_EXPRESSION,
      ExpressionAttributeValues: {
        ':zero': INITIAL_SUBJECT_GENERATION,
        ':one': SUBJECT_GENERATION_STEP,
      },
    }));
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
    const item = await this.getItem(pk);
    if (!item) {
      return null;
    }
    if (!isLoadedTokenRecord(item)) {
      throw new DynamodbRefreshTokenProviderInvalidError();
    }
    return item;
  };

  /**
   * Loads one item by partition key.
   *
   * @param pk - Partition key.
   * @returns Unmarshalled item, or `undefined` when the row is absent.
   */
  private getItem = async (pk: string): Promise<Record<string, unknown> | undefined> => {
    const res = await this.getDdb().send(new GetCommand({
      TableName: this.tableName,
      Key: { pk },
      ConsistentRead: this.options.consistentRead ?? true,
    }));
    const item: Record<string, unknown> | undefined = res.Item;
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
   * @throws {@link DynamodbRefreshTokenProviderValidateError} When `tokenBytes` is not a positive integer.
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
   * @throws {@link DynamodbRefreshTokenProviderValidateError} When `ttlSeconds` or `ttlDays` is not a positive number.
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
