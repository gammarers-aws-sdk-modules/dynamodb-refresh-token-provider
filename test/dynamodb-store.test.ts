import { DynamoDBClient, type DynamoDBClientConfig } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { NodeHttpHandler } from '@smithy/node-http-handler';

import {
  DynamodbRefreshTokenProvider,
  DynamodbRefreshTokenProviderAbortError,
  DynamodbRefreshTokenProviderExpiredError,
  DynamodbRefreshTokenProviderInvalidError,
  DynamodbRefreshTokenProviderRevokedError,
  DynamodbRefreshTokenProviderRotateError,
  DynamodbRefreshTokenProviderValidateError,
} from '../src';

const mockSend = jest.fn();

const transactionCanceled = (reasons?: ReadonlyArray<{ Code: string }>): Error =>
  Object.assign(new Error('tx'), { name: 'TransactionCanceledException', CancellationReasons: reasons });
const mockDynamoDBClient = DynamoDBClient as unknown as jest.Mock;

jest.mock('@aws-sdk/client-dynamodb', () => {
  const actual = jest.requireActual('@aws-sdk/client-dynamodb') as typeof import('@aws-sdk/client-dynamodb');
  return {
    ...actual,
    DynamoDBClient: jest.fn().mockImplementation(() => ({})),
  };
});

jest.mock('@aws-sdk/lib-dynamodb', () => {
  const actual = jest.requireActual('@aws-sdk/lib-dynamodb') as typeof import('@aws-sdk/lib-dynamodb');
  return {
    ...actual,
    DynamoDBDocumentClient: {
      ...actual.DynamoDBDocumentClient,
      from: jest.fn(() => ({ send: mockSend })),
    },
  };
});

/** 32-byte token → base64url length 43 (matches store tokenBytes). */
const VALID_TOKEN = 'A'.repeat(43);

const fixedNow = new Date('2020-01-01T00:00:00Z');
const nowSec = Math.floor(fixedNow.getTime() / 1000);
const defaultTtlSec = 60 * 24 * 60 * 60;
const futureExpiresAt = nowSec + defaultTtlSec + 1;

/**
 * Asserts the internal client's default Node.js request handler timeouts.
 *
 * `httpHandlerConfigs()` stays empty until the first request. The constructor stores the
 * options on `configProvider`, which is the value this test reads.
 *
 * @param config - Config passed to the mocked `DynamoDBClient` constructor.
 */
const expectDefaultRequestHandler = async (config: DynamoDBClientConfig): Promise<void> => {
  expect(config.requestHandler).toBeInstanceOf(NodeHttpHandler);
  const handler = config.requestHandler as NodeHttpHandler;
  // configProvider is not on the public type. It is the constructor promise that holds the timeouts.
  const resolved = await (handler as unknown as {
    configProvider: Promise<{ connectionTimeout?: number; requestTimeout?: number }>;
  }).configProvider;
  expect(resolved.connectionTimeout).toBe(5_000);
  expect(resolved.requestTimeout).toBe(30_000);
};

beforeEach(() => {
  mockSend.mockReset();
  mockDynamoDBClient.mockClear();
  (DynamoDBDocumentClient.from as jest.Mock).mockClear();
});

describe('issue', () => {
  const issuePut = (): NonNullable<TransactWriteCommand['input']['TransactItems']>[number]['Put'] => {
    const tx = mockSend.mock.calls[3][0] as TransactWriteCommand;
    expect(tx).toBeInstanceOf(TransactWriteCommand);
    return tx.input.TransactItems?.[3]?.Put;
  };

  it('should put item with expected keys and return token metadata', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.issue({
      subjectId: 'sub-1',
      sessionId: 'sess-1',
      now: fixedNow,
    });

    expect(mockSend).toHaveBeenCalledTimes(4);
    expect((mockSend.mock.calls[0][0] as GetCommand).input.Key).toEqual({ pk: 'sess#sess-1' });
    expect((mockSend.mock.calls[1][0] as GetCommand).input.Key).toEqual({ pk: 'sess#sess-1#sub-1' });
    expect((mockSend.mock.calls[2][0] as GetCommand).input.Key).toEqual({ pk: 'sub#sub-1' });

    const put = issuePut();
    expect(put?.TableName).toBe('tbl');
    expect(put?.ConditionExpression).toBe('attribute_not_exists(pk)');
    expect(put?.Item).toMatchObject({
      subjectId: 'sub-1',
      sessionId: 'sess-1',
      createdAt: nowSec,
      expiresAt: nowSec + defaultTtlSec,
      ttl: nowSec + defaultTtlSec,
      subjectGeneration: 0,
    });
    expect(typeof (put?.Item as { pk: string }).pk).toBe('string');
    const tx = mockSend.mock.calls[3][0] as TransactWriteCommand;
    expect(tx.input.TransactItems?.[0]?.ConditionCheck?.ConditionExpression).toBe(
      'attribute_not_exists(revokedAt)',
    );
    expect(tx.input.TransactItems?.[2]?.ConditionCheck?.ConditionExpression).toBe(
      'attribute_not_exists(pk) OR generation = :generation',
    );
    expect(result.refreshToken.length).toBe(43);
    expect(result.refreshTokenExpiresAt).toBe(nowSec + defaultTtlSec);
  });

  it('should respect ttlDays and pkPrefix options', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 't',
      ttlDays: 7,
      pkPrefix: 'custom#',
    });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const put = issuePut();
    expect(put?.Item).toMatchObject({
      expiresAt: nowSec + 7 * 24 * 60 * 60,
      ttl: nowSec + 7 * 24 * 60 * 60,
    });
    expect((put?.Item as { pk: string }).pk.startsWith('custom#')).toBe(true);
  });

  it('should respect ttlSeconds over ttlDays', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 't',
      ttlDays: 7,
      ttlSeconds: 3600,
    });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const put = issuePut();
    expect(put?.Item).toMatchObject({
      expiresAt: nowSec + 3600,
      ttl: nowSec + 3600,
    });
  });

  it('should generate tokens with custom tokenBytes length', async () => {
    mockSend.mockResolvedValue({});

    const tokenBytes = 16;
    const store = new DynamodbRefreshTokenProvider({ tableName: 't', tokenBytes });
    const result = await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    expect(result.refreshToken.length).toBe(Math.ceil(tokenBytes * 8 / 6));
  });
});

describe('rotate', () => {
  it('should throw DynamodbRefreshTokenProviderInvalidError for malformed token before calling DynamoDB', async () => {
    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(store.rotate({ refreshToken: '' })).rejects.toThrow(DynamodbRefreshTokenProviderInvalidError);
    await expect(store.rotate({ refreshToken: 'short' })).rejects.toThrow(DynamodbRefreshTokenProviderInvalidError);
    expect(mockSend).not.toHaveBeenCalled();
  });

  it('should throw DynamodbRefreshTokenProviderInvalidError when item is missing', async () => {
    mockSend.mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderInvalidError);
    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(mockSend.mock.calls[0][0]).toBeInstanceOf(GetCommand);
  });

  it.each([
    ['missing subjectId', { pk: 'rt#x', sessionId: 'sess', createdAt: 1, expiresAt: futureExpiresAt }],
    ['non-numeric expiresAt', { pk: 'rt#x', subjectId: 's', sessionId: 'sess', expiresAt: 'soon' }],
    ['non-numeric rotatedAt', { pk: 'rt#x', subjectId: 's', sessionId: 's', expiresAt: futureExpiresAt, rotatedAt: 'x' }],
    ['non-numeric subjectGeneration', { pk: 'rt#x', subjectId: 's', sessionId: 's', expiresAt: futureExpiresAt, subjectGeneration: '0' }],
  ])('should throw DynamodbRefreshTokenProviderInvalidError for a row with %s', async (_label, item) => {
    mockSend.mockResolvedValueOnce({ Item: item });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderInvalidError);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should rotate a row written before ttl was introduced', async () => {
    mockSend
      .mockResolvedValueOnce({
        Item: { pk: 'rt#legacy', subjectId: 'sub', sessionId: 'sess', expiresAt: futureExpiresAt },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const out = await store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow });

    expect(out.subjectId).toBe('sub');
    expect(mockSend).toHaveBeenCalledTimes(5);
  });

  it('should throw DynamodbRefreshTokenProviderExpiredError when expiresAt is not after now', async () => {
    mockSend.mockResolvedValueOnce({
      Item: {
        pk: 'rt#x',
        subjectId: 's',
        sessionId: 'sess',
        createdAt: 1,
        expiresAt: nowSec,
      },
    });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderExpiredError);
  });

  it('should throw DynamodbRefreshTokenProviderRevokedError when revokedAt is set', async () => {
    mockSend.mockResolvedValueOnce({
      Item: {
        pk: 'rt#x',
        subjectId: 's',
        sessionId: 'sess',
        createdAt: 1,
        expiresAt: futureExpiresAt,
        revokedAt: 1,
      },
    });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderRevokedError);
  });

  it('should throw DynamodbRefreshTokenProviderReusedError when rotatedAt is set', async () => {
    mockSend
      .mockResolvedValueOnce({
        Item: {
          pk: 'rt#x',
          subjectId: 's',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
          rotatedAt: 1,
        },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'DynamodbRefreshTokenProviderReusedError',
      subjectId: 's',
      sessionId: 'sess',
    });
    expect(mockSend).toHaveBeenCalledTimes(4);
  });

  it('should revoke session then throw when revokeSessionOnReuse and rotatedAt is set', async () => {
    mockSend
      .mockResolvedValueOnce({
        Item: {
          pk: 'rt#x',
          subjectId: 'sub',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
          rotatedAt: 1,
        },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#x' }, { pk: 'rt#y' }],
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      revokeSessionOnReuse: true,
    });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'DynamodbRefreshTokenProviderReusedError',
      subjectId: 'sub',
      sessionId: 'sess',
    });

    expect(mockSend).toHaveBeenCalledTimes(8);
    const marker = mockSend.mock.calls[4][0] as UpdateCommand;
    expect(marker).toBeInstanceOf(UpdateCommand);
    expect(marker.input.Key).toEqual({ pk: 'sess#sess#sub' });
    expect(mockSend.mock.calls[5][0]).toBeInstanceOf(QueryCommand);
    expect(mockSend.mock.calls[6][0]).toBeInstanceOf(UpdateCommand);
    expect(mockSend.mock.calls[7][0]).toBeInstanceOf(UpdateCommand);
  });

  it('should run transact write and return new token on success', async () => {
    mockSend
      .mockResolvedValueOnce({
        Item: {
          pk: 'rt#current',
          subjectId: 'sub',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
        },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const out = await store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow });

    expect(mockSend).toHaveBeenCalledTimes(5);
    const txCmd = mockSend.mock.calls[4][0] as TransactWriteCommand;
    expect(txCmd).toBeInstanceOf(TransactWriteCommand);
    const update = txCmd.input.TransactItems?.[0]?.Update;
    const put = txCmd.input.TransactItems?.[1]?.Put;
    expect(update?.UpdateExpression).toContain('#ttl');
    expect(update?.ExpressionAttributeValues).toMatchObject({
      ':ttl': futureExpiresAt,
    });
    expect(put?.Item).toMatchObject({
      expiresAt: nowSec + defaultTtlSec,
      ttl: nowSec + defaultTtlSec,
      subjectGeneration: 0,
    });
    expect(txCmd.input.TransactItems?.[2]?.ConditionCheck?.Key).toEqual({ pk: 'sess#sess' });
    expect(txCmd.input.TransactItems?.[3]?.ConditionCheck?.Key).toEqual({ pk: 'sess#sess#sub' });
    expect(txCmd.input.TransactItems?.[4]?.ConditionCheck?.Key).toEqual({ pk: 'sub#sub' });
    expect(out.subjectId).toBe('sub');
    expect(out.sessionId).toBe('sess');
    expect(out.refreshToken.length).toBe(43);
    expect(out.refreshTokenExpiresAt).toBe(nowSec + defaultTtlSec);
  });

  it('should map current-token ConditionalCheckFailed to DynamodbRefreshTokenProviderReusedError', async () => {
    mockSend
      .mockResolvedValueOnce({
        Item: {
          pk: 'rt#current',
          subjectId: 'sub',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
        },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(transactionCanceled([{ Code: 'ConditionalCheckFailed' }, { Code: 'None' }]));

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'DynamodbRefreshTokenProviderReusedError',
      subjectId: 'sub',
      sessionId: 'sess',
    });
  });

  it.each([
    ['throttling', [{ Code: 'ThrottlingError' }, { Code: 'None' }]],
    ['transaction conflict', [{ Code: 'TransactionConflict' }, { Code: 'None' }]],
    ['successor insert condition', [{ Code: 'None' }, { Code: 'ConditionalCheckFailed' }]],
    ['missing reasons', undefined],
    ['empty reasons', []],
  ] as const)('should map %s cancellation to DynamodbRefreshTokenProviderRotateError', async (_label, reasons) => {
    const txError = transactionCanceled(reasons);
    mockSend
      .mockResolvedValueOnce({
        Item: {
          pk: 'rt#current',
          subjectId: 'sub',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
        },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(txError);

    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      revokeSessionOnReuse: true,
    });
    const promise = store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow });
    await expect(promise).rejects.toThrow(DynamodbRefreshTokenProviderRotateError);
    await expect(promise).rejects.toMatchObject({ cause: txError });
    expect(mockSend).toHaveBeenCalledTimes(5);
  });

  it('should revoke session on current-token ConditionalCheckFailed when revokeSessionOnReuse is true', async () => {
    mockSend
      .mockResolvedValueOnce({
        Item: {
          pk: 'rt#current',
          subjectId: 'sub',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
        },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(transactionCanceled([{ Code: 'ConditionalCheckFailed' }, { Code: 'None' }]))
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ Items: [{ pk: 'rt#current' }] })
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      revokeSessionOnReuse: true,
    });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'DynamodbRefreshTokenProviderReusedError',
      subjectId: 'sub',
      sessionId: 'sess',
    });

    expect(mockSend.mock.calls[6][0]).toBeInstanceOf(QueryCommand);
    expect(mockSend.mock.calls[7][0]).toBeInstanceOf(UpdateCommand);
  });

  it('should rethrow non-TransactionCanceledException from transact write', async () => {
    mockSend
      .mockResolvedValueOnce({
        Item: {
          pk: 'rt#current',
          subjectId: 'sub',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
        },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(Object.assign(new Error('throttled'), { name: 'ProvisionedThroughputExceededException' }));

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'ProvisionedThroughputExceededException',
      message: 'throttled',
    });
  });
});

describe('revoke', () => {
  it('should throw DynamodbRefreshTokenProviderInvalidError for invalid token string', async () => {
    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(store.revoke({ refreshToken: 'x' })).rejects.toThrow(DynamodbRefreshTokenProviderInvalidError);
    expect(mockSend).not.toHaveBeenCalled();
  });

  it('should send update and return true on success', async () => {
    mockSend.mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const ok = await store.revoke({ refreshToken: VALID_TOKEN, now: fixedNow });

    expect(ok).toBe(true);
    const cmd = mockSend.mock.calls[0][0] as UpdateCommand;
    expect(cmd).toBeInstanceOf(UpdateCommand);
    expect(cmd.input.UpdateExpression).toBe('SET revokedAt = :now');
    expect(cmd.input.ExpressionAttributeValues).toEqual({ ':now': nowSec });
  });

  it('should return true when conditional check fails (missing row)', async () => {
    mockSend.mockRejectedValueOnce(
      Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' }),
    );

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const ok = await store.revoke({ refreshToken: VALID_TOKEN, now: fixedNow });
    expect(ok).toBe(true);
  });

  it('should rethrow unexpected errors from update', async () => {
    mockSend.mockRejectedValueOnce(
      Object.assign(new Error('boom'), { name: 'InternalServerError' }),
    );

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.revoke({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'InternalServerError',
      message: 'boom',
    });
  });
});

describe('revokeSession', () => {
  it('should write the session-subject marker, then query the session GSI and revoke each token row', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#a' }, { pk: 'rt#b' }],
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.revokeSession({
      sessionId: 'sess-1',
      subjectId: 'sub-1',
      now: fixedNow,
    });

    expect(result.revokedCount).toBe(2);
    const marker = mockSend.mock.calls[0][0] as UpdateCommand;
    expect(marker).toBeInstanceOf(UpdateCommand);
    expect(marker.input.Key).toEqual({ pk: 'sess#sess-1#sub-1' });
    expect(marker.input.UpdateExpression).toBe('SET revokedAt = :now');
    expect(marker.input.ExpressionAttributeValues).toEqual({ ':now': nowSec });

    const query = mockSend.mock.calls[1][0] as QueryCommand;
    expect(query).toBeInstanceOf(QueryCommand);
    expect(query.input.IndexName).toBe('sessionId-index');
    expect(query.input.KeyConditionExpression).toBe('sessionId = :sessionId');
    expect(query.input.ExpressionAttributeValues).toEqual({
      ':sessionId': 'sess-1',
    });

    const updateA = mockSend.mock.calls[2][0] as UpdateCommand;
    expect(updateA.input.Key).toEqual({ pk: 'rt#a' });
    expect(updateA.input.ConditionExpression).toBe(
      'attribute_exists(pk) AND subjectId = :subjectId',
    );
    expect(updateA.input.ExpressionAttributeValues).toEqual({
      ':now': nowSec,
      ':subjectId': 'sub-1',
    });
  });

  it('should use custom sessionIdIndexName and page through results', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#1' }],
        LastEvaluatedKey: { sessionId: 'sess', pk: 'rt#1' },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#2' }],
      })
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      sessionIdIndexName: 'custom-session-index',
    });
    const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });

    expect(result.revokedCount).toBe(2);
    expect((mockSend.mock.calls[0][0] as UpdateCommand).input.Key).toEqual({ pk: 'sess#sess' });
    expect((mockSend.mock.calls[1][0] as QueryCommand).input.IndexName).toBe(
      'custom-session-index',
    );
    expect((mockSend.mock.calls[3][0] as QueryCommand).input.ExclusiveStartKey).toEqual({
      sessionId: 'sess',
      pk: 'rt#1',
    });
  });

  it('should skip rows that fail conditional update', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#gone' }, { pk: 'rt#ok' }],
      })
      .mockRejectedValueOnce(
        Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' }),
      )
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });
    expect(result.revokedCount).toBe(1);
  });

  it('should skip items whose pk is not a string and treat missing Items as empty', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 123 }, { pk: 'rt#ok' }],
      })
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });

    expect(result.revokedCount).toBe(1);
    expect(mockSend).toHaveBeenCalledTimes(3);
    expect((mockSend.mock.calls[2][0] as UpdateCommand).input.Key).toEqual({ pk: 'rt#ok' });
  });

  it('should treat undefined Items as empty and return zero revoked', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });
    expect(result.revokedCount).toBe(0);
    expect(mockSend).toHaveBeenCalledTimes(2);
    expect((mockSend.mock.calls[0][0] as UpdateCommand).input.Key).toEqual({ pk: 'sess#sess' });
  });

  it('should rethrow unexpected errors from session token update', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#a' }],
      })
      .mockRejectedValueOnce(
        Object.assign(new Error('denied'), { name: 'AccessDeniedException' }),
      );

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.revokeSession({ sessionId: 'sess', now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'AccessDeniedException',
      message: 'denied',
    });
  });
});

describe('revokeSubject', () => {
  it('should increment subject generation, then query the subject GSI and revoke each token row', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#a' }, { pk: 'rt#b' }],
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.revokeSubject({
      subjectId: 'sub-1',
      now: fixedNow,
    });

    expect(result.revokedCount).toBe(2);
    const marker = mockSend.mock.calls[0][0] as UpdateCommand;
    expect(marker.input.Key).toEqual({ pk: 'sub#sub-1' });
    expect(marker.input.UpdateExpression).toBe(
      'SET generation = if_not_exists(generation, :zero) + :one',
    );
    expect(marker.input.ExpressionAttributeValues).toEqual({ ':zero': 0, ':one': 1 });

    const query = mockSend.mock.calls[1][0] as QueryCommand;
    expect(query).toBeInstanceOf(QueryCommand);
    expect(query.input.IndexName).toBe('subjectId-index');
    expect(query.input.KeyConditionExpression).toBe('subjectId = :subjectId');
    expect(query.input.ExpressionAttributeValues).toEqual({
      ':subjectId': 'sub-1',
    });

    const updateA = mockSend.mock.calls[2][0] as UpdateCommand;
    expect(updateA.input.Key).toEqual({ pk: 'rt#a' });
    expect(updateA.input.ConditionExpression).toBe('attribute_exists(pk)');
    expect(updateA.input.ExpressionAttributeValues).toEqual({
      ':now': nowSec,
    });
  });

  it('should use custom subjectIdIndexName and page through results', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#1' }],
        LastEvaluatedKey: { subjectId: 'sub', pk: 'rt#1' },
      })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#2' }],
      })
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      subjectIdIndexName: 'custom-subject-index',
    });
    const result = await store.revokeSubject({ subjectId: 'sub', now: fixedNow });

    expect(result.revokedCount).toBe(2);
    expect((mockSend.mock.calls[1][0] as QueryCommand).input.IndexName).toBe(
      'custom-subject-index',
    );
    expect((mockSend.mock.calls[3][0] as QueryCommand).input.ExclusiveStartKey).toEqual({
      subjectId: 'sub',
      pk: 'rt#1',
    });
  });

  it('should skip rows that fail conditional update', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#gone' }, { pk: 'rt#ok' }],
      })
      .mockRejectedValueOnce(
        Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' }),
      )
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.revokeSubject({ subjectId: 'sub', now: fixedNow });
    expect(result.revokedCount).toBe(1);
  });

  it('should treat undefined Items as empty and return zero revoked', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const result = await store.revokeSubject({ subjectId: 'sub', now: fixedNow });
    expect(result.revokedCount).toBe(0);
    expect(mockSend).toHaveBeenCalledTimes(2);
  });

  it('should rethrow unexpected errors from subject token update', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        Items: [{ pk: 'rt#a' }],
      })
      .mockRejectedValueOnce(
        Object.assign(new Error('denied'), { name: 'AccessDeniedException' }),
      );

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.revokeSubject({ subjectId: 'sub', now: fixedNow }),
    ).rejects.toMatchObject({
      name: 'AccessDeniedException',
      message: 'denied',
    });
  });
});

describe('options', () => {
  it('should throw DynamodbRefreshTokenProviderValidateError for invalid tokenBytes', () => {
    expect(() => new DynamodbRefreshTokenProvider({ tableName: 'tbl', tokenBytes: 0 }))
      .toThrow(new DynamodbRefreshTokenProviderValidateError('tokenBytes must be a positive integer'));
    expect(() => new DynamodbRefreshTokenProvider({ tableName: 'tbl', tokenBytes: 1.5 }))
      .toThrow(new DynamodbRefreshTokenProviderValidateError('tokenBytes must be a positive integer'));
  });

  it('should throw DynamodbRefreshTokenProviderValidateError for invalid ttlSeconds or ttlDays', () => {
    expect(() => new DynamodbRefreshTokenProvider({ tableName: 'tbl', ttlSeconds: 0 }))
      .toThrow(new DynamodbRefreshTokenProviderValidateError('ttlSeconds must be a positive number'));
    expect(() => new DynamodbRefreshTokenProvider({ tableName: 'tbl', ttlDays: -1 }))
      .toThrow(new DynamodbRefreshTokenProviderValidateError('ttlDays must be a positive number'));
  });

  it('should pass translateConfig to DynamoDBDocumentClient.from', async () => {
    mockSend.mockResolvedValue({});

    const translateConfig = {
      marshallOptions: { removeUndefinedValues: true },
    };
    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl', translateConfig });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    expect(DynamoDBDocumentClient.from).toHaveBeenCalledWith(
      expect.anything(),
      translateConfig,
    );
  });

  it('should use custom endpoint when constructing the DynamoDB client', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      endpoint: 'http://localhost:8000',
    });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const config = mockDynamoDBClient.mock.calls[0][0] as DynamoDBClientConfig;
    expect(config.endpoint).toBe('http://localhost:8000');
    expect(config.region).toBeUndefined();
    await expectDefaultRequestHandler(config);
    expect(DynamoDBDocumentClient.from).toHaveBeenCalled();
    expect(mockSend).toHaveBeenCalledTimes(4);
  });

  it('should leave region and endpoint unset so the AWS SDK resolves them', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const config = mockDynamoDBClient.mock.calls[0][0] as DynamoDBClientConfig;
    expect(config.region).toBeUndefined();
    expect(config.endpoint).toBeUndefined();
    expect(config.maxAttempts).toBeUndefined();
    await expectDefaultRequestHandler(config);
  });

  it('should pass the region option to DynamoDBClient', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl', region: 'ap-northeast-1' });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const config = mockDynamoDBClient.mock.calls[0][0] as DynamoDBClientConfig;
    expect(config.region).toBe('ap-northeast-1');
    expect(config.endpoint).toBeUndefined();
    await expectDefaultRequestHandler(config);
  });

  it('should accept the positional constructor form for compatibility', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider('legacy-tbl', 'eu-west-1', { ttlDays: 7 });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const tx = mockSend.mock.calls[3][0] as TransactWriteCommand;
    const put = tx.input.TransactItems?.[3]?.Put;
    expect(put?.TableName).toBe('legacy-tbl');
    expect(put?.Item).toMatchObject({ expiresAt: nowSec + 7 * 24 * 60 * 60 });
    const config = mockDynamoDBClient.mock.calls[0][0] as DynamoDBClientConfig;
    expect(config.region).toBe('eu-west-1');
    await expectDefaultRequestHandler(config);
  });

  it('should reuse the document client across calls', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });
    await store.issue({ subjectId: 'c', sessionId: 'd', now: fixedNow });

    expect(mockDynamoDBClient).toHaveBeenCalledTimes(1);
    expect(DynamoDBDocumentClient.from).toHaveBeenCalledTimes(1);
    expect(mockSend).toHaveBeenCalledTimes(8);
  });

  it('should send commands through an injected document client', async () => {
    const send = jest.fn().mockResolvedValue({});
    // Test double: the store only calls `send` on an injected client.
    const documentClient = { send } as unknown as DynamoDBDocumentClient;

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl', documentClient });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });
    await store.issue({ subjectId: 'c', sessionId: 'd', now: fixedNow });

    expect(send).toHaveBeenCalledTimes(8);
    expect(mockDynamoDBClient).not.toHaveBeenCalled();
    expect(DynamoDBDocumentClient.from).not.toHaveBeenCalled();
  });

  it('should pass clientConfig to DynamoDBClient with region and endpoint as the base', async () => {
    mockSend.mockResolvedValue({});

    const credentials = {
      accessKeyId: 'access-key',
      secretAccessKey: 'secret-key',
    };
    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      endpoint: 'http://localhost:8000',
      clientConfig: {
        region: 'eu-west-1',
        credentials,
        maxAttempts: 5,
      },
    });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const config = mockDynamoDBClient.mock.calls[0][0] as DynamoDBClientConfig;
    expect(config).toMatchObject({
      region: 'eu-west-1',
      endpoint: 'http://localhost:8000',
      credentials,
      maxAttempts: 5,
    });
    await expectDefaultRequestHandler(config);
    expect(DynamoDBDocumentClient.from).toHaveBeenCalledTimes(1);
  });

  it('should let clientConfig.endpoint override the endpoint option', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      endpoint: 'http://localhost:8000',
      clientConfig: {
        endpoint: 'http://localhost:4566',
      },
    });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const config = mockDynamoDBClient.mock.calls[0][0] as DynamoDBClientConfig;
    expect(config.endpoint).toBe('http://localhost:4566');
    await expectDefaultRequestHandler(config);
  });

  it('should let clientConfig.requestHandler replace the default request handler', async () => {
    mockSend.mockResolvedValue({});

    const requestHandler = new NodeHttpHandler({
      connectionTimeout: 1_000,
      requestTimeout: 2_000,
    });
    const store = new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      clientConfig: { requestHandler },
    });
    await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

    const config = mockDynamoDBClient.mock.calls[0][0] as DynamoDBClientConfig;
    expect(config.requestHandler).toBe(requestHandler);
  });

  it('should throw DynamodbRefreshTokenProviderValidateError when documentClient and clientConfig are both set', () => {
    const documentClient = { send: jest.fn() } as unknown as DynamoDBDocumentClient;

    expect(() => new DynamodbRefreshTokenProvider({
      tableName: 'tbl',
      documentClient,
      clientConfig: { maxAttempts: 2 },
    })).toThrow(new DynamodbRefreshTokenProviderValidateError(
      'documentClient and clientConfig are mutually exclusive',
    ));
    expect(mockDynamoDBClient).not.toHaveBeenCalled();
    expect(DynamoDBDocumentClient.from).not.toHaveBeenCalled();
  });

  it('should default now to current Date when omitted', async () => {
    const expiresAt = Math.floor(Date.now() / 1000) + defaultTtlSec;
    mockSend.mockImplementation((command: unknown) => {
      if (command instanceof GetCommand) {
        const pk = command.input.Key?.pk;
        if (typeof pk === 'string' && pk.startsWith('rt#')) {
          return Promise.resolve({
            Item: {
              pk,
              subjectId: 's',
              sessionId: 'sess',
              createdAt: 1,
              expiresAt,
            },
          });
        }
      }
      if (command instanceof QueryCommand) {
        return Promise.resolve({ Items: [] });
      }
      return Promise.resolve({});
    });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await store.issue({ subjectId: 'a', sessionId: 'b' });
    await store.rotate({ refreshToken: VALID_TOKEN });
    await store.revoke({ refreshToken: VALID_TOKEN });
    await store.revokeSession({ sessionId: 'sess' });
    await store.revokeSubject({ subjectId: 'sub' });

    expect(mockSend).toHaveBeenCalledTimes(14);
  });
});

describe('abortSignal', () => {
  it('should throw AbortError before issue sends when the signal is already aborted', async () => {
    const controller = new AbortController();
    const reason = new Error('stopped');
    controller.abort(reason);
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const error = await store.issue({
      subjectId: 'a',
      sessionId: 'b',
      now: fixedNow,
      abortSignal: controller.signal,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(DynamodbRefreshTokenProviderAbortError);
    expect(error).toMatchObject({ cause: reason });
    expect(mockSend).not.toHaveBeenCalled();
  });

  it('should wrap a failed issue transaction as AbortError when the signal aborts during the request', async () => {
    const controller = new AbortController();
    const cause = transactionCanceled([
      { Code: 'ConditionalCheckFailed' },
      { Code: 'None' },
      { Code: 'None' },
      { Code: 'None' },
    ]);
    mockSend.mockImplementation(async (command: unknown) => {
      if (command instanceof TransactWriteCommand) {
        controller.abort();
        throw cause;
      }
      return {};
    });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    const error = await store.issue({
      subjectId: 'a',
      sessionId: 'b',
      now: fixedNow,
      abortSignal: controller.signal,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(DynamodbRefreshTokenProviderAbortError);
    expect(error).toMatchObject({ cause });
    expect(mockSend.mock.calls.filter((call) => call[0] instanceof TransactWriteCommand)).toHaveLength(1);
    expect(mockSend.mock.calls.at(-1)?.[1]).toEqual({ abortSignal: controller.signal });
  });

  it('should stop revokeSubject before the next page when the signal aborts after the first query', async () => {
    const controller = new AbortController();
    mockSend.mockImplementation(async (command: unknown) => {
      if (command instanceof QueryCommand) {
        controller.abort();
        return {
          Items: [{ pk: 'rt#1' }],
          LastEvaluatedKey: { subjectId: 'sub', pk: 'rt#1' },
        };
      }
      return {};
    });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(store.revokeSubject({
      subjectId: 'sub',
      now: fixedNow,
      abortSignal: controller.signal,
    })).rejects.toBeInstanceOf(DynamodbRefreshTokenProviderAbortError);

    const queries = mockSend.mock.calls.filter((call) => call[0] instanceof QueryCommand);
    expect(queries).toHaveLength(1);
    const updates = mockSend.mock.calls.filter((call) => call[0] instanceof UpdateCommand);
    expect(updates).toHaveLength(1);
    expect((updates[0][0] as UpdateCommand).input.Key).toEqual({ pk: 'sub#sub' });
  });
});
