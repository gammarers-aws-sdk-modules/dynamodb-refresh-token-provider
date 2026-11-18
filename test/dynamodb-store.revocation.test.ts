import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';

import {
  DynamodbRefreshTokenProvider,
  DynamodbRefreshTokenProviderInvalidError,
  DynamodbRefreshTokenProviderRevokedError,
} from '../src';

const mockSend = jest.fn();

const transactionCanceled = (reasons?: ReadonlyArray<{ Code: string }>): Error =>
  Object.assign(new Error('tx'), { name: 'TransactionCanceledException', CancellationReasons: reasons });

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

const VALID_TOKEN = 'A'.repeat(43);
const fixedNow = new Date('2020-01-01T00:00:00Z');
const nowSec = Math.floor(fixedNow.getTime() / 1000);
const futureExpiresAt = nowSec + 60 * 24 * 60 * 60 + 1;

const tokenItem = (extra: Record<string, unknown> = {}): { Item: Record<string, unknown> } => ({
  Item: {
    pk: 'rt#current',
    subjectId: 'sub',
    sessionId: 'sess',
    createdAt: 1,
    expiresAt: futureExpiresAt,
    ...extra,
  },
});

describe('revocation markers', () => {
  beforeEach(() => {
    mockSend.mockReset();
    (DynamoDBClient as unknown as jest.Mock).mockClear();
    (DynamoDBDocumentClient.from as jest.Mock).mockClear();
  });

  it.each([
    ['session', 0],
    ['session-subject', 1],
  ] as const)('should reject issue when the %s marker is revoked', async (_label, index) => {
    const responses: Array<Record<string, unknown>> = [{}, {}, {}];
    responses[index] = { Item: { revokedAt: 9 } };
    responses.forEach((response) => {
      mockSend.mockResolvedValueOnce(response);
    });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderRevokedError);
    expect(mockSend).toHaveBeenCalledTimes(3);
    expect(mockSend.mock.calls.some((call) => call[0] instanceof TransactWriteCommand)).toBe(false);
  });

  it('should store the subject generation and require that generation in the transaction', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ Item: { generation: 4 } })
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow });

    const tx = mockSend.mock.calls[3][0] as TransactWriteCommand;
    expect(tx.input.TransactItems?.[2]?.ConditionCheck?.ConditionExpression).toBe(
      'attribute_exists(pk) AND generation = :generation',
    );
    expect(tx.input.TransactItems?.[2]?.ConditionCheck?.ExpressionAttributeValues).toEqual({
      ':generation': 4,
    });
    expect(tx.input.TransactItems?.[3]?.Put?.Item).toMatchObject({ subjectGeneration: 4 });
  });

  it('should map an issue revocation condition failure to DynamodbRefreshTokenProviderRevokedError', async () => {
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(transactionCanceled([
        { Code: 'ConditionalCheckFailed' },
        { Code: 'None' },
        { Code: 'None' },
        { Code: 'None' },
      ]));

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderRevokedError);
  });

  it('should rethrow an issue cancellation that is not a revocation condition', async () => {
    const txError = transactionCanceled([
      { Code: 'None' },
      { Code: 'None' },
      { Code: 'None' },
      { Code: 'ConditionalCheckFailed' },
    ]);
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(txError);

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow }),
    ).rejects.toBe(txError);
  });

  it('should rethrow a non-cancellation error from issue', async () => {
    const throttled = Object.assign(new Error('throttled'), { name: 'ProvisionedThroughputExceededException' });
    mockSend
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(throttled);

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow }),
    ).rejects.toBe(throttled);
  });

  it.each([
    ['session', 0, { revokedAt: 'x' }],
    ['session-subject', 1, { revokedAt: true }],
    ['subject', 2, { generation: '1' }],
  ] as const)('should reject issue when the %s marker has an unexpected attribute', async (_label, index, item) => {
    const responses: Array<Record<string, unknown>> = [{}, {}, {}];
    responses[index] = { Item: item };
    responses.forEach((response) => {
      mockSend.mockResolvedValueOnce(response);
    });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderInvalidError);
  });

  it('should propagate a marker read failure from issue', async () => {
    const denied = Object.assign(new Error('denied'), { name: 'AccessDeniedException' });
    mockSend
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(denied)
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow }),
    ).rejects.toBe(denied);
  });

  it('should send marker reads with consistentRead disabled when that option is false', async () => {
    mockSend.mockResolvedValue({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl', consistentRead: false });
    await store.issue({ subjectId: 'sub', sessionId: 'sess', now: fixedNow });

    const read = mockSend.mock.calls[0][0] as GetCommand;
    expect(read).toBeInstanceOf(GetCommand);
    expect(read.input.ConsistentRead).toBe(false);
  });

  it.each([
    ['session', 1],
    ['session-subject', 2],
  ] as const)('should reject rotate when the %s marker is revoked', async (_label, callIndex) => {
    mockSend.mockResolvedValueOnce(tokenItem());
    for (let index = 1; index <= 3; index += 1) {
      mockSend.mockResolvedValueOnce(index === callIndex ? { Item: { revokedAt: 3 } } : {});
    }

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl', revokeSessionOnReuse: true });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderRevokedError);
    expect(mockSend).toHaveBeenCalledTimes(4);
  });

  it('should reject rotate when the subject generation moved', async () => {
    mockSend
      .mockResolvedValueOnce(tokenItem({ subjectGeneration: 1 }))
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ Item: { generation: 2 } });

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderRevokedError);
    expect(mockSend).toHaveBeenCalledTimes(4);
  });

  it('should copy the token generation onto the successor', async () => {
    mockSend
      .mockResolvedValueOnce(tokenItem({ subjectGeneration: 3 }))
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ Item: { generation: 3 } })
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow });

    const tx = mockSend.mock.calls[4][0] as TransactWriteCommand;
    expect(tx.input.TransactItems?.[1]?.Put?.Item).toMatchObject({ subjectGeneration: 3 });
    expect(tx.input.TransactItems?.[4]?.ConditionCheck?.ExpressionAttributeValues).toEqual({
      ':generation': 3,
    });
    expect(tx.input.TransactItems?.[4]?.ConditionCheck?.ConditionExpression).toBe(
      'attribute_exists(pk) AND generation = :generation',
    );
  });

  it('should treat a null subjectGeneration as generation 0', async () => {
    mockSend
      .mockResolvedValueOnce(tokenItem({ subjectGeneration: null }))
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({});

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow });

    const tx = mockSend.mock.calls[4][0] as TransactWriteCommand;
    expect(tx.input.TransactItems?.[1]?.Put?.Item).toMatchObject({ subjectGeneration: 0 });
    expect(tx.input.TransactItems?.[4]?.ConditionCheck?.ConditionExpression).toBe(
      'attribute_not_exists(pk) OR generation = :generation',
    );
  });

  it('should map a rotate revocation condition failure to DynamodbRefreshTokenProviderRevokedError', async () => {
    mockSend
      .mockResolvedValueOnce(tokenItem())
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(transactionCanceled([
        { Code: 'None' },
        { Code: 'None' },
        { Code: 'ConditionalCheckFailed' },
        { Code: 'None' },
        { Code: 'None' },
      ]));

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl', revokeSessionOnReuse: true });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderRevokedError);
    expect(mockSend).toHaveBeenCalledTimes(5);
  });

  it('should prefer revocation over reuse when both conditions fail', async () => {
    mockSend
      .mockResolvedValueOnce(tokenItem())
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(transactionCanceled([
        { Code: 'ConditionalCheckFailed' },
        { Code: 'None' },
        { Code: 'None' },
        { Code: 'None' },
        { Code: 'ConditionalCheckFailed' },
      ]));

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl', revokeSessionOnReuse: true });
    await expect(
      store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
    ).rejects.toThrow(DynamodbRefreshTokenProviderRevokedError);
    expect(mockSend).toHaveBeenCalledTimes(5);
  });

  it('should propagate a session marker write failure before querying', async () => {
    const denied = Object.assign(new Error('denied'), { name: 'AccessDeniedException' });
    mockSend.mockRejectedValueOnce(denied);

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.revokeSession({ sessionId: 'sess', now: fixedNow }),
    ).rejects.toBe(denied);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should propagate a subject generation write failure before querying', async () => {
    const denied = Object.assign(new Error('denied'), { name: 'AccessDeniedException' });
    mockSend.mockRejectedValueOnce(denied);

    const store = new DynamodbRefreshTokenProvider({ tableName: 'tbl' });
    await expect(
      store.revokeSubject({ subjectId: 'sub', now: fixedNow }),
    ).rejects.toBe(denied);
    expect(mockSend).toHaveBeenCalledTimes(1);
  });
});
