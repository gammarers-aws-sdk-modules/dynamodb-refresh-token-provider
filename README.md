# DynamoDB Refresh Token Provider

[![npm version](https://img.shields.io/npm/v/dynamodb-refresh-token-provider.svg)](https://www.npmjs.com/package/dynamodb-refresh-token-provider)
[![License](https://img.shields.io/npm/l/dynamodb-refresh-token-provider.svg)](https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider/blob/main/LICENSE)
[![build](https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider/actions/workflows/build.yml/badge.svg)](https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider/actions/workflows/build.yml)

TypeScript library that stores **opaque refresh tokens** in **Amazon DynamoDB** using AWS SDK for JavaScript v3. Tokens are persisted under a hash of the plaintext value; **issue**, **rotate** (with reuse detection via a transactional write), **revoke** (idempotent), and **revokeSession** (session-wide family revocation) are supported.

## Features

- **`RefreshTokenStore` interface** — swap implementations while keeping the same API.
- **`DynamodbRefreshTokenProvider`** — single-table design with string partition key `pk` and strongly consistent reads by default.
- **DynamoDB TTL** — writes `ttl` (Unix seconds) on `Put` and `TransactWriteItems` so expired and rotated rows can be removed automatically when table TTL is enabled.
- **Logical expiration** — `expiresAt` drives validation; `ttl` is for storage cleanup only.
- **Rotation safety** — marks the old row as rotated and inserts the successor in one transaction; detects reuse and conflicting updates.
- **Session revocation (OAuth 2.0 BCP)** — `revokeSession({ sessionId })` revokes all tokens for a session via a `sessionId` GSI; optional `revokeSessionOnReuse` cascades on reuse detection.
- **Structured errors** — `RefreshTokenError`, `RefreshTokenInvalidError`, `RefreshTokenExpiredError`, `RefreshTokenRevokedError`, `RefreshTokenReusedError` (with optional `subjectId` / `sessionId`), and `RefreshTokenRotateFailedError` for `instanceof` handling.
- **Utilities** — `sha256hex` and `randomtoken` for hashing and token generation aligned with the store.

## Installation

```bash
npm install dynamodb-refresh-token-provider
```

```bash
yarn add dynamodb-refresh-token-provider
```

## Usage

Create a store with your table name, AWS region, and optional `StoreOptions`. Your DynamoDB table needs a **string partition key** named `pk`, **TTL enabled** on attribute `ttl` (see [DynamoDB TTL](#dynamodb-ttl)), and a **GSI** on `sessionId` for session revocation (see [Session GSI](#session-gsi)).

```typescript
import {
  DynamodbRefreshTokenProvider,
  RefreshTokenExpiredError,
  RefreshTokenInvalidError,
  RefreshTokenReusedError,
  RefreshTokenRevokedError,
} from 'dynamodb-refresh-token-provider';

const store = new DynamodbRefreshTokenProvider('your-refresh-token-table', 'us-east-1', {
  ttlDays: 60,
  pkPrefix: 'rt#',
  // Optional: revoke every token in the session when reuse is detected (OAuth 2.0 BCP)
  // revokeSessionOnReuse: true,
  // sessionIdIndexName: 'sessionId-index',
});

// Issue a new refresh token for a subject/session
const issued = await store.issue({
  subjectId: 'user-123',
  sessionId: 'session-456',
});
// issued.refreshToken — send to the client (plaintext)
// issued.refreshTokenExpiresAt — Unix seconds (same as expiresAt / ttl on the item)

// Rotate: exchange the current token for a new one
try {
  const rotated = await store.rotate({ refreshToken: issued.refreshToken });
  // rotated.refreshToken, rotated.refreshTokenExpiresAt, rotated.subjectId, rotated.sessionId
} catch (e) {
  if (e instanceof RefreshTokenReusedError) {
    // already rotated or lost a transactional race
    // e.sessionId / e.subjectId are set when the store row was loaded
    if (e.sessionId) {
      await store.revokeSession({ sessionId: e.sessionId, subjectId: e.subjectId });
    }
  }
  if (e instanceof RefreshTokenInvalidError) {
    // unknown or malformed token
  }
  if (e instanceof RefreshTokenExpiredError) {
    // past expiresAt
  }
  if (e instanceof RefreshTokenRevokedError) {
    // revokedAt is set
  }
  throw e;
}

// Revoke one token: idempotent; succeeds even if the row does not exist
await store.revoke({ refreshToken: issued.refreshToken });

// Revoke all tokens for a session (requires sessionId GSI)
await store.revokeSession({ sessionId: 'session-456', subjectId: 'user-123' });
```

### DynamoDB TTL

Each item includes:

| Attribute | Purpose |
|-----------|---------|
| `expiresAt` | Logical expiration (Unix seconds); used by the library for validation. |
| `ttl` | DynamoDB TTL attribute (Unix seconds); enable table TTL on this name for automatic deletion. |

On **issue**, both are set to the same value. On **rotate**, the successor `Put` sets both to the new expiration; the previous row’s `ttl` is updated to its existing `expiresAt`. **Revoke** / **revokeSession** do not change `ttl` (the value from issue/rotate still applies).

Enable TTL on your table once (per table/region). The TTL attribute name must be **`ttl`**.

**AWS CLI**

```bash
aws dynamodb update-time-to-live \
  --table-name your-refresh-token-table \
  --time-to-live-specification "Enabled=true, AttributeName=ttl"
```

**AWS Console**

1. Open the table → **Additional settings** → **Time to Live (TTL)**.
2. Turn TTL on and set the attribute name to **`ttl`**.

DynamoDB deletes items asynchronously, typically within 48 hours after `ttl` is in the past.

### Session GSI

`revokeSession` (and `revokeSessionOnReuse`) query token rows by `sessionId`. Create a GSI whose **partition key** is the attribute **`sessionId`** (String). `KEYS_ONLY` projection is enough (base-table `pk` is always projected).

| Setting | Value |
|---------|--------|
| Index name | `sessionId-index` (override with `sessionIdIndexName`) |
| Partition key | `sessionId` (S) |
| Projection | `KEYS_ONLY` (or `ALL`) |

**AWS CLI** (example; adjust billing mode / capacity as needed)

```bash
aws dynamodb update-table \
  --table-name your-refresh-token-table \
  --attribute-definitions AttributeName=sessionId,AttributeType=S \
  --global-secondary-index-updates '[{
    "Create": {
      "IndexName": "sessionId-index",
      "KeySchema": [{"AttributeName": "sessionId", "KeyType": "HASH"}],
      "Projection": {"ProjectionType": "KEYS_ONLY"}
    }
  }]'
```

## Options

Constructor: `new DynamodbRefreshTokenProvider(tableName, region, options?)`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ttlDays` | `number` | `60` | Token lifetime in days; added to `now` when computing `expiresAt` and `ttl` (Unix seconds). |
| `pkPrefix` | `string` | `'rt#'` | Partition key prefix; full `pk` is `prefix` + SHA-256 hex of the plaintext token. |
| `consistentRead` | `boolean` | `true` | Use strongly consistent reads on `GetItem` when loading a token row. |
| `endpoint` | `string` | (none) | Custom DynamoDB API endpoint (e.g. LocalStack or DynamoDB Local). |
| `sessionIdIndexName` | `string` | `'sessionId-index'` | GSI name whose partition key is `sessionId` (required for `revokeSession`). |
| `revokeSessionOnReuse` | `boolean` | `false` | When true, `rotate` calls `revokeSession` for the token’s session before throwing `RefreshTokenReusedError`. |

`issue`, `rotate`, `revoke`, and `revokeSession` accept an optional `now?: Date` for testing or clock injection.

## Requirements

- **Node.js** 20.0.0 or later.
- A **DynamoDB table** with a string partition key **`pk`**, **TTL enabled** on attribute **`ttl`** (see [DynamoDB TTL](#dynamodb-ttl)), and a **GSI** on **`sessionId`** for session revocation (see [Session GSI](#session-gsi)).
- **AWS credentials** and permissions for `PutItem`, `GetItem`, `UpdateItem`, `Query`, and `TransactWriteItems` on that table (and the configured `endpoint` if used).

## License

This project is licensed under the Apache-2.0 License.
