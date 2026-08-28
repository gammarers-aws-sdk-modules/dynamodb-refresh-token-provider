import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';

import {
  DynamodbRefreshTokenProvider,
  RefreshTokenExpiredError,
  RefreshTokenInvalidError,
  RefreshTokenRevokedError,
} from '../src';

const mockSend = jest.fn();

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

describe('DynamodbRefreshTokenProvider', () => {
  beforeEach(() => {
    mockSend.mockReset();
    (DynamoDBDocumentClient.from as jest.Mock).mockClear();
  });

  describe('issue', () => {
    it('should put item with expected keys and return token metadata', async () => {
      mockSend.mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.issue({
        subjectId: 'sub-1',
        sessionId: 'sess-1',
        now: fixedNow,
      });

      expect(mockSend).toHaveBeenCalledTimes(1);
      const cmd = mockSend.mock.calls[0][0] as PutCommand;
      expect(cmd).toBeInstanceOf(PutCommand);
      expect(cmd.input.TableName).toBe('tbl');
      expect(cmd.input.ConditionExpression).toBe('attribute_not_exists(pk)');
      expect(cmd.input.Item).toMatchObject({
        subjectId: 'sub-1',
        sessionId: 'sess-1',
        createdAt: nowSec,
        expiresAt: nowSec + defaultTtlSec,
        ttl: nowSec + defaultTtlSec,
      });
      expect(typeof (cmd.input.Item as { pk: string }).pk).toBe('string');
      expect(result.refreshToken.length).toBe(43);
      expect(result.refreshTokenExpiresAt).toBe(nowSec + defaultTtlSec);
    });

    it('should respect ttlDays and pkPrefix options', async () => {
      mockSend.mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('t', 'eu-west-1', {
        ttlDays: 7,
        pkPrefix: 'custom#',
      });
      await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

      const cmd = mockSend.mock.calls[0][0] as PutCommand;
      expect(cmd.input.Item).toMatchObject({
        expiresAt: nowSec + 7 * 24 * 60 * 60,
        ttl: nowSec + 7 * 24 * 60 * 60,
      });
      expect((cmd.input.Item as { pk: string }).pk.startsWith('custom#')).toBe(true);
    });
  });

  describe('rotate', () => {
    it('should throw RefreshTokenInvalidError for malformed token before calling DynamoDB', async () => {
      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(store.rotate({ refreshToken: '' })).rejects.toThrow(RefreshTokenInvalidError);
      await expect(store.rotate({ refreshToken: 'short' })).rejects.toThrow(RefreshTokenInvalidError);
      expect(mockSend).not.toHaveBeenCalled();
    });

    it('should throw RefreshTokenInvalidError when item is missing', async () => {
      mockSend.mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toThrow(RefreshTokenInvalidError);
      expect(mockSend).toHaveBeenCalledTimes(1);
      expect(mockSend.mock.calls[0][0]).toBeInstanceOf(GetCommand);
    });

    it('should throw RefreshTokenExpiredError when expiresAt is not after now', async () => {
      mockSend.mockResolvedValueOnce({
        Item: {
          pk: 'rt#x',
          subjectId: 's',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: nowSec,
        },
      });

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toThrow(RefreshTokenExpiredError);
    });

    it('should throw RefreshTokenRevokedError when revokedAt is set', async () => {
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

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toThrow(RefreshTokenRevokedError);
    });

    it('should throw RefreshTokenReusedError when rotatedAt is set', async () => {
      mockSend.mockResolvedValueOnce({
        Item: {
          pk: 'rt#x',
          subjectId: 's',
          sessionId: 'sess',
          createdAt: 1,
          expiresAt: futureExpiresAt,
          rotatedAt: 1,
        },
      });

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'RefreshTokenReusedError',
        subjectId: 's',
        sessionId: 'sess',
      });
      expect(mockSend).toHaveBeenCalledTimes(1);
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
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#x' }, { pk: 'rt#y' }],
        })
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1', {
        revokeSessionOnReuse: true,
      });
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'RefreshTokenReusedError',
        subjectId: 'sub',
        sessionId: 'sess',
      });

      expect(mockSend).toHaveBeenCalledTimes(4);
      expect(mockSend.mock.calls[1][0]).toBeInstanceOf(QueryCommand);
      expect(mockSend.mock.calls[2][0]).toBeInstanceOf(UpdateCommand);
      expect(mockSend.mock.calls[3][0]).toBeInstanceOf(UpdateCommand);
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
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const out = await store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow });

      expect(mockSend).toHaveBeenCalledTimes(2);
      const txCmd = mockSend.mock.calls[1][0] as TransactWriteCommand;
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
      });
      expect(out.subjectId).toBe('sub');
      expect(out.sessionId).toBe('sess');
      expect(out.refreshToken.length).toBe(43);
      expect(out.refreshTokenExpiresAt).toBe(nowSec + defaultTtlSec);
    });

    it('should map TransactionCanceledException to RefreshTokenReusedError', async () => {
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
        .mockRejectedValueOnce(Object.assign(new Error('tx'), { name: 'TransactionCanceledException' }));

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'RefreshTokenReusedError',
        subjectId: 'sub',
        sessionId: 'sess',
      });
    });

    it('should revoke session on TransactionCanceledException when revokeSessionOnReuse is true', async () => {
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
        .mockRejectedValueOnce(Object.assign(new Error('tx'), { name: 'TransactionCanceledException' }))
        .mockResolvedValueOnce({ Items: [{ pk: 'rt#current' }] })
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1', {
        revokeSessionOnReuse: true,
      });
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'RefreshTokenReusedError',
        subjectId: 'sub',
        sessionId: 'sess',
      });

      expect(mockSend.mock.calls[2][0]).toBeInstanceOf(QueryCommand);
      expect(mockSend.mock.calls[3][0]).toBeInstanceOf(UpdateCommand);
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
        .mockRejectedValueOnce(Object.assign(new Error('throttled'), { name: 'ProvisionedThroughputExceededException' }));

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.rotate({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'ProvisionedThroughputExceededException',
        message: 'throttled',
      });
    });
  });

  describe('revoke', () => {
    it('should throw RefreshTokenInvalidError for invalid token string', async () => {
      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(store.revoke({ refreshToken: 'x' })).rejects.toThrow(RefreshTokenInvalidError);
      expect(mockSend).not.toHaveBeenCalled();
    });

    it('should send update and return true on success', async () => {
      mockSend.mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
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

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const ok = await store.revoke({ refreshToken: VALID_TOKEN, now: fixedNow });
      expect(ok).toBe(true);
    });

    it('should rethrow unexpected errors from update', async () => {
      mockSend.mockRejectedValueOnce(
        Object.assign(new Error('boom'), { name: 'InternalServerError' }),
      );

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.revoke({ refreshToken: VALID_TOKEN, now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'InternalServerError',
        message: 'boom',
      });
    });
  });

  describe('revokeSession', () => {
    it('should query session GSI and revoke each token row', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#a' }, { pk: 'rt#b' }],
        })
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.revokeSession({
        sessionId: 'sess-1',
        subjectId: 'sub-1',
        now: fixedNow,
      });

      expect(result.revokedCount).toBe(2);
      const query = mockSend.mock.calls[0][0] as QueryCommand;
      expect(query).toBeInstanceOf(QueryCommand);
      expect(query.input.IndexName).toBe('sessionId-index');
      expect(query.input.KeyConditionExpression).toBe('sessionId = :sessionId');
      expect(query.input.ExpressionAttributeValues).toEqual({
        ':sessionId': 'sess-1',
      });

      const updateA = mockSend.mock.calls[1][0] as UpdateCommand;
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
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#1' }],
          LastEvaluatedKey: { sessionId: 'sess', pk: 'rt#1' },
        })
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#2' }],
        })
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1', {
        sessionIdIndexName: 'custom-session-index',
      });
      const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });

      expect(result.revokedCount).toBe(2);
      expect((mockSend.mock.calls[0][0] as QueryCommand).input.IndexName).toBe(
        'custom-session-index',
      );
      expect((mockSend.mock.calls[2][0] as QueryCommand).input.ExclusiveStartKey).toEqual({
        sessionId: 'sess',
        pk: 'rt#1',
      });
    });

    it('should skip rows that fail conditional update', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#gone' }, { pk: 'rt#ok' }],
        })
        .mockRejectedValueOnce(
          Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' }),
        )
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });
      expect(result.revokedCount).toBe(1);
    });

    it('should skip items whose pk is not a string and treat missing Items as empty', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 123 }, { pk: 'rt#ok' }],
        })
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });

      expect(result.revokedCount).toBe(1);
      expect(mockSend).toHaveBeenCalledTimes(2);
      expect((mockSend.mock.calls[1][0] as UpdateCommand).input.Key).toEqual({ pk: 'rt#ok' });
    });

    it('should treat undefined Items as empty and return zero revoked', async () => {
      mockSend.mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.revokeSession({ sessionId: 'sess', now: fixedNow });
      expect(result.revokedCount).toBe(0);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should rethrow unexpected errors from session token update', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#a' }],
        })
        .mockRejectedValueOnce(
          Object.assign(new Error('denied'), { name: 'AccessDeniedException' }),
        );

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.revokeSession({ sessionId: 'sess', now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'AccessDeniedException',
        message: 'denied',
      });
    });
  });

  describe('revokeSubject', () => {
    it('should query subject GSI and revoke each token row', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#a' }, { pk: 'rt#b' }],
        })
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.revokeSubject({
        subjectId: 'sub-1',
        now: fixedNow,
      });

      expect(result.revokedCount).toBe(2);
      const query = mockSend.mock.calls[0][0] as QueryCommand;
      expect(query).toBeInstanceOf(QueryCommand);
      expect(query.input.IndexName).toBe('subjectId-index');
      expect(query.input.KeyConditionExpression).toBe('subjectId = :subjectId');
      expect(query.input.ExpressionAttributeValues).toEqual({
        ':subjectId': 'sub-1',
      });

      const updateA = mockSend.mock.calls[1][0] as UpdateCommand;
      expect(updateA.input.Key).toEqual({ pk: 'rt#a' });
      expect(updateA.input.ConditionExpression).toBe('attribute_exists(pk)');
      expect(updateA.input.ExpressionAttributeValues).toEqual({
        ':now': nowSec,
      });
    });

    it('should use custom subjectIdIndexName and page through results', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#1' }],
          LastEvaluatedKey: { subjectId: 'sub', pk: 'rt#1' },
        })
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#2' }],
        })
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1', {
        subjectIdIndexName: 'custom-subject-index',
      });
      const result = await store.revokeSubject({ subjectId: 'sub', now: fixedNow });

      expect(result.revokedCount).toBe(2);
      expect((mockSend.mock.calls[0][0] as QueryCommand).input.IndexName).toBe(
        'custom-subject-index',
      );
      expect((mockSend.mock.calls[2][0] as QueryCommand).input.ExclusiveStartKey).toEqual({
        subjectId: 'sub',
        pk: 'rt#1',
      });
    });

    it('should skip rows that fail conditional update', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#gone' }, { pk: 'rt#ok' }],
        })
        .mockRejectedValueOnce(
          Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' }),
        )
        .mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.revokeSubject({ subjectId: 'sub', now: fixedNow });
      expect(result.revokedCount).toBe(1);
    });

    it('should treat undefined Items as empty and return zero revoked', async () => {
      mockSend.mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      const result = await store.revokeSubject({ subjectId: 'sub', now: fixedNow });
      expect(result.revokedCount).toBe(0);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should rethrow unexpected errors from subject token update', async () => {
      mockSend
        .mockResolvedValueOnce({
          Items: [{ pk: 'rt#a' }],
        })
        .mockRejectedValueOnce(
          Object.assign(new Error('denied'), { name: 'AccessDeniedException' }),
        );

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await expect(
        store.revokeSubject({ subjectId: 'sub', now: fixedNow }),
      ).rejects.toMatchObject({
        name: 'AccessDeniedException',
        message: 'denied',
      });
    });
  });

  describe('options', () => {
    it('should use custom endpoint when constructing the DynamoDB client', async () => {
      mockSend.mockResolvedValueOnce({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1', {
        endpoint: 'http://localhost:8000',
      });
      await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });

      expect(DynamoDBDocumentClient.from).toHaveBeenCalled();
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should reuse the document client across calls', async () => {
      mockSend.mockResolvedValue({});

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await store.issue({ subjectId: 'a', sessionId: 'b', now: fixedNow });
      await store.issue({ subjectId: 'c', sessionId: 'd', now: fixedNow });

      expect(DynamoDBDocumentClient.from).toHaveBeenCalledTimes(1);
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it('should default now to current Date when omitted', async () => {
      mockSend
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({
          Item: {
            pk: 'rt#x',
            subjectId: 's',
            sessionId: 'sess',
            createdAt: 1,
            expiresAt: Math.floor(Date.now() / 1000) + defaultTtlSec,
          },
        })
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({ Items: [] });

      const store = new DynamodbRefreshTokenProvider('tbl', 'us-east-1');
      await store.issue({ subjectId: 'a', sessionId: 'b' });
      await store.rotate({ refreshToken: VALID_TOKEN });
      await store.revoke({ refreshToken: VALID_TOKEN });
      await store.revokeSession({ sessionId: 'sess' });

      expect(mockSend).toHaveBeenCalledTimes(5);
    });
  });
});
