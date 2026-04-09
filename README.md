# DynamoDB Refresh Token Provider

[![npm version](https://img.shields.io/npm/v/dynamodb-refresh-token-provider.svg)](https://www.npmjs.com/package/dynamodb-refresh-token-provider)
[![License](https://img.shields.io/npm/l/dynamodb-refresh-token-provider.svg)](https://github.com/gammarers-aws-sdk-extensions/athena-query-result-collector/blob/main/LICENSE)
[![build](https://github.com/gammarers-aws-sdk-extensions/athena-query-result-collector/actions/workflows/build.yml/badge.svg)](https://github.com/gammarers-aws-sdk-extensions/athena-query-result-collector/actions/workflows/build.yml)

TypeScript library that stores **opaque refresh tokens** in **Amazon DynamoDB** using AWS SDK for JavaScript v3. Tokens are persisted under a hash of the plaintext value; **issue**, **rotate** (with reuse detection via a transactional write), and **revoke** (idempotent) are supported.

## Features

- **`RefreshTokenStore` interface** — swap implementations while keeping the same API.
- **`DynamodbRefreshTokenProvider`** — single-table design with partition key `pk` (string), strongly consistent reads by default.
- **Rotation safety** — marks the old row as rotated and inserts the successor in one DynamoDB transaction; detects reuse and conflicting updates.
- **Structured errors** — `RefreshTokenInvalidError`, `RefreshTokenExpiredError`, `RefreshTokenRevokedError`, `RefreshTokenReusedError`, and related types for `instanceof` handling.
- **Utilities** — `sha256hex` and `randomtoken` for hashing and token generation aligned with the store.

## Installation

```bash
npm install dynamodb-refresh-token-provider
```

```bash
yarn add dynamodb-refresh-token-provider
```

## Usage

Create a store with your table name, AWS region, and optional `StoreOptions`. Ensure your DynamoDB table has a **string partition key** named `pk` (same attribute name the library uses for items).

```typescript
import {
  DynamodbRefreshTokenProvider,
  RefreshTokenInvalidError,
  RefreshTokenReusedError,
} from 'dynamodb-refresh-token-provider';

const store = new DynamodbRefreshTokenProvider('your-refresh-token-table', 'us-east-1', {
  ttlDays: 60,
  pkPrefix: 'rt#',
});

// Issue a new refresh token for a subject/session
const issued = await store.issue({
  subjectId: 'user-123',
  sessionId: 'session-456',
});
// issued.refreshToken — send to the client (plaintext)
// issued.refreshTokenExpiresAt — Unix seconds

// Rotate: exchange current token for a new one
try {
  const rotated = await store.rotate({ refreshToken: issued.refreshToken });
  // rotated.refreshToken, rotated.refreshTokenExpiresAt, rotated.subjectId, rotated.sessionId
} catch (e) {
  if (e instanceof RefreshTokenReusedError) {
    // token was already rotated or transaction lost the race
  }
  if (e instanceof RefreshTokenInvalidError) {
    // unknown or malformed token
  }
  throw e;
}

// Revoke: idempotent; succeeds even if the row does not exist
await store.revoke({ refreshToken: issued.refreshToken });
```

## Options

Constructor: `new DynamodbRefreshTokenProvider(tableName, region, options?)`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ttlDays` | `number` | `60` | Lifetime of issued/rotated tokens in days (added to `now` in seconds). |
| `pkPrefix` | `string` | `'rt#'` | Prefix for the partition key; full `pk` is `prefix` + SHA-256 hex of the plaintext token. |
| `consistentRead` | `boolean` | `true` | Use strongly consistent reads on `GetItem` when loading a token row. |
| `endpoint` | `string` | (none) | Custom DynamoDB API endpoint (e.g. LocalStack or DynamoDB Local). |

Method parameters also accept an optional `now?: Date` on `issue`, `rotate`, and `revoke` for testing or clock injection.

## Requirements

- **Node.js** 20.0.0 or later.
- A **DynamoDB table** with a string partition key attribute **`pk`**.
- **AWS credentials** and permissions for `PutItem`, `GetItem`, `UpdateItem`, and `TransactWriteItems` on that table (and the configured `endpoint` if used).

## License

This project is licensed under the Apache-2.0 License.
