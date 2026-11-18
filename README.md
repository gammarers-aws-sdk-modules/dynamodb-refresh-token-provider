# DynamoDB Refresh Token Provider

[![npm version](https://img.shields.io/npm/v/dynamodb-refresh-token-provider?style=flat-square)](https://www.npmjs.com/package/dynamodb-refresh-token-provider)
[![license](https://img.shields.io/npm/l/dynamodb-refresh-token-provider?style=flat-square)](https://www.npmjs.com/package/dynamodb-refresh-token-provider)
[![Node.js](https://img.shields.io/node/v/dynamodb-refresh-token-provider?style=flat-square)](https://www.npmjs.com/package/dynamodb-refresh-token-provider)
[![build](https://img.shields.io/github/actions/workflow/status/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider/build.yml?label=build&style=flat-square)](https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider/actions/workflows/build.yml)

TypeScript library that stores **opaque refresh tokens** in **Amazon DynamoDB** using AWS SDK for JavaScript v3. Tokens are persisted under a hash of the plaintext value; **issue**, **rotate** (with reuse detection via a transactional write), **revoke** (idempotent), **revokeSession** (session-wide family revocation), and **revokeSubject** (subject-wide revocation across all sessions) are supported. Session and subject revocation also write marker rows that `issue` and `rotate` check in the same transaction, so a token the GSI has not indexed yet cannot stay active.

## Features

- **`RefreshTokenStore` interface** — swap implementations while keeping the same API.
- **`DynamodbRefreshTokenProvider`** — single-table design with string partition key `pk` and strongly consistent reads by default.
- **DynamoDB TTL** — writes `ttl` (Unix seconds) on `Put` and `TransactWriteItems` so expired and rotated rows can be removed automatically when table TTL is enabled.
- **Logical expiration** — `expiresAt` drives validation; `ttl` is for storage cleanup only.
- **Rotation safety** — marks the old row as rotated and inserts the successor in one transaction; detects reuse and conflicting updates.
- **Session revocation (OAuth 2.0 BCP)** — `revokeSession({ sessionId })` writes `revokedAt` on `sess#<sessionId>` (or `sess#<sessionId>#<subjectId>` when `subjectId` is set) and stamps token rows returned by the `sessionId` GSI. `issue` rejects a revoked session. Optional `revokeSessionOnReuse` cascades on reuse detection.
- **Subject revocation** — `revokeSubject({ subjectId })` increments `generation` on `sub#<subjectId>` and stamps token rows returned by the `subjectId` GSI (logout all devices, password change, account suspension). A later `issue` stores the new generation and succeeds. Older tokens cannot be rotated.
- **Structured errors** — `DynamodbRefreshTokenProviderValidateError` (invalid constructor options), `DynamodbRefreshTokenProviderInvalidError`, `DynamodbRefreshTokenProviderExpiredError`, `DynamodbRefreshTokenProviderRevokedError` (token, session, or subject generation), `DynamodbRefreshTokenProviderReusedError` (with optional `subjectId` / `sessionId`), and `DynamodbRefreshTokenProviderRotateError` (non-reuse rotate failure such as throttling or a transaction conflict; the token is not consumed and may be retried). All extend `DynamodbRefreshTokenProviderError`. Check a subclass before the base.
- **Utilities** — `sha256Hex` and `randomToken` for hashing and token generation aligned with the store.
- **Injectable DynamoDB client** — pass an existing `DynamoDBDocumentClient`, or a `DynamoDBClientConfig` for credentials, retries, and request handlers.

## How it works

1. `issue` reads `sess#<sessionId>`, `sess#<sessionId>#<subjectId>`, and `sub#<subjectId>`. It stores that subject's `generation` (0 until the first `revokeSubject`) on the new token. The token row is written only when those markers still allow it.
2. `rotate` checks the same markers against the generation stored on the current token, and copies that generation onto the successor.
3. `revokeSession` writes `revokedAt` on the session marker (or the session-subject marker when `subjectId` is set), then stamps `revokedAt` on token rows the session GSI returns. `revokedCount` counts those token updates only. A session marker stays revoked for that session id.
4. `revokeSubject` adds 1 to `generation` on the subject marker, then stamps token rows the subject GSI returns. The next `issue` for that subject takes the new generation.
5. A GSI query can miss a token written a moment earlier. The marker write does not. If revocation wins the race inside the transaction, `issue` and `rotate` throw `DynamodbRefreshTokenProviderRevokedError` and the token write is rolled back.

Marker items do not set `sessionId` or `subjectId`, so the GSIs do not return them. They have no `ttl`: a rotated token chain can outlive the configured lifetime, and removing a session marker would let a missed token rotate again. Partition-key prefixes `sess#` and `sub#` are reserved. Do not use them as `pkPrefix`.

Concurrent `rotate` calls for the same subject condition-check one subject marker and can cancel with a transaction conflict. That failure is `DynamodbRefreshTokenProviderRotateError`. The presented token is not consumed.

## Installation

### npm

```bash
npm install dynamodb-refresh-token-provider
```

### yarn

```bash
yarn add dynamodb-refresh-token-provider
```

### pnpm

```bash
pnpm add dynamodb-refresh-token-provider
```

## Usage

Create a store with an options object containing your table name and any `StoreOptions`. The AWS SDK resolves the region (for example from `AWS_REGION`, shared config, or the Lambda runtime). Your DynamoDB table needs a **string partition key** named `pk`, **TTL enabled** on attribute `ttl` (see [DynamoDB TTL](#dynamodb-ttl)), a **GSI** on `sessionId` for session revocation (see [Session GSI](#session-gsi)), and a **GSI** on `subjectId` for subject-wide revocation (see [Subject GSI](#subject-gsi)).

```typescript
import {
  DynamodbRefreshTokenProvider,
  DynamodbRefreshTokenProviderExpiredError,
  DynamodbRefreshTokenProviderInvalidError,
  DynamodbRefreshTokenProviderReusedError,
  DynamodbRefreshTokenProviderRevokedError,
  DynamodbRefreshTokenProviderRotateError,
} from 'dynamodb-refresh-token-provider';

const store = new DynamodbRefreshTokenProvider({
  tableName: 'your-refresh-token-table',
  ttlDays: 60,
  // ttlSeconds: 3600, // alternative to ttlDays; takes precedence when both are set
  // tokenBytes: 32,
  pkPrefix: 'rt#',
  // translateConfig: { marshallOptions: { removeUndefinedValues: true } },
  // documentClient: existingDocumentClient,
  // clientConfig: { maxAttempts: 3 },
  // Optional: revoke every token in the session when reuse is detected (OAuth 2.0 BCP)
  // revokeSessionOnReuse: true,
  // sessionIdIndexName: 'sessionId-index',
  // subjectIdIndexName: 'subjectId-index',
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
  if (e instanceof DynamodbRefreshTokenProviderReusedError) {
    // already rotated, or a concurrent rotate/revoke won the race
    // e.sessionId / e.subjectId are set when the store row was loaded
    if (e.sessionId) {
      await store.revokeSession({ sessionId: e.sessionId, subjectId: e.subjectId });
    }
  }
  if (e instanceof DynamodbRefreshTokenProviderRotateError) {
    // not reuse (throttling, transaction conflict, ...); the token was not consumed
    // retry rotate with the same token or return a retryable error; e.cause holds the SDK error
  }
  if (e instanceof DynamodbRefreshTokenProviderInvalidError) {
    // unknown or malformed token, or a stored row with missing or mistyped fields
  }
  if (e instanceof DynamodbRefreshTokenProviderExpiredError) {
    // past expiresAt
  }
  if (e instanceof DynamodbRefreshTokenProviderRevokedError) {
    // the token, its session, or its subject generation is revoked
  }
  throw e;
}

// Revoke one token: idempotent; succeeds even if the row does not exist
await store.revoke({ refreshToken: issued.refreshToken });

// Revoke all tokens for a session (requires sessionId GSI)
await store.revokeSession({ sessionId: 'session-456', subjectId: 'user-123' });

// Revoke all tokens for a subject across every session (requires subjectId GSI)
await store.revokeSubject({ subjectId: 'user-123' });
```

### DynamoDB client

By default the provider builds a `DynamoDBClient` from the optional `region` and `endpoint` options, then wraps it with `DynamoDBDocumentClient.from`. When they are omitted, the AWS SDK resolves the region and the matching endpoint (including FIPS, dual-stack, and China partitions). That client uses a Node.js request handler with a **5 second connection timeout** and a **30 second request timeout**. Retries stay at the AWS SDK default (`maxAttempts` 3, standard retry mode) unless `clientConfig` sets them. `clientConfig.requestHandler` replaces the default handler. Pass `documentClient` to reuse an existing document client, including one created from an X-Ray-wrapped client; `region`, `endpoint`, and these timeouts are not applied in that case. Pass `clientConfig` to supply credentials, retries, or a request handler to the client this provider constructs. Do not set `documentClient` and `clientConfig` together.

```typescript
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { DynamodbRefreshTokenProvider } from 'dynamodb-refresh-token-provider';

const documentClient = DynamoDBDocumentClient.from(
  new DynamoDBClient({ maxAttempts: 3 }),
);

const store = new DynamodbRefreshTokenProvider({
  tableName: 'your-refresh-token-table',
  documentClient,
});

const storeWithConfig = new DynamodbRefreshTokenProvider({
  tableName: 'your-refresh-token-table',
  clientConfig: {
    maxAttempts: 3,
  },
});
```

### DynamoDB TTL

Each item includes:

| Attribute | Purpose |
|-----------|---------|
| `expiresAt` | Logical expiration (Unix seconds); used by the library for validation. |
| `ttl` | DynamoDB TTL attribute (Unix seconds); enable table TTL on this name for automatic deletion. |

On **issue**, both are set to the same value. On **rotate**, the successor `Put` sets both to the new expiration; the previous row’s `ttl` is updated to its existing `expiresAt`. **Revoke**, **revokeSession**, and **revokeSubject** do not change a token’s `ttl` (the value from issue/rotate still applies). Session and subject marker rows are not given `ttl`.

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

`revokeSession` (and `revokeSessionOnReuse`) write a session marker, then query token rows by `sessionId` to stamp the ones the index already lists. Create a GSI whose **partition key** is the attribute **`sessionId`** (String). `KEYS_ONLY` projection is enough (base-table `pk` is always projected). The marker, not the GSI, is what blocks a token the index has not caught up to.

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

### Subject GSI

`revokeSubject` increments the subject generation marker, then queries token rows by `subjectId` to stamp every refresh token the index already lists (e.g. logout all devices, password change, account suspension). Create a GSI whose **partition key** is the attribute **`subjectId`** (String). `KEYS_ONLY` projection is enough (base-table `pk` is always projected). Tokens issued earlier keep their old `subjectGeneration` and fail `rotate` even when the GSI missed them. A later `issue` stores the new generation.

| Setting | Value |
|---------|--------|
| Index name | `subjectId-index` (override with `subjectIdIndexName`) |
| Partition key | `subjectId` (S) |
| Projection | `KEYS_ONLY` (or `ALL`) |

**AWS CLI** (example; adjust billing mode / capacity as needed)

```bash
aws dynamodb update-table \
  --table-name your-refresh-token-table \
  --attribute-definitions AttributeName=subjectId,AttributeType=S \
  --global-secondary-index-updates '[{
    "Create": {
      "IndexName": "subjectId-index",
      "KeySchema": [{"AttributeName": "subjectId", "KeyType": "HASH"}],
      "Projection": {"ProjectionType": "KEYS_ONLY"}
    }
  }]'
```

## Options

Constructor: `new DynamodbRefreshTokenProvider(options)` with `DynamodbRefreshTokenProviderOptions` (`tableName` plus every `StoreOptions` field).

Invalid `tokenBytes`, `ttlSeconds`, or `ttlDays`, or setting both `documentClient` and `clientConfig`, throws `DynamodbRefreshTokenProviderValidateError`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tableName` | `string` | (required) | DynamoDB table name for refresh token items. |
| `region` | `string` | (resolved by the AWS SDK) | AWS region for the client this provider constructs. Overridden by `clientConfig.region` when both are set. Ignored when `documentClient` is set. |
| `ttlDays` | `number` | `60` | Token lifetime in days; added to `now` when computing `expiresAt` and `ttl` (Unix seconds). Ignored when `ttlSeconds` is set. |
| `ttlSeconds` | `number` | (none) | Token lifetime in seconds; takes precedence over `ttlDays` when both are set. |
| `tokenBytes` | `number` | `32` | Random byte length for generated refresh tokens (e.g. `32` → 256-bit). |
| `translateConfig` | `DocumentClientTranslateConfig` | (none) | Pass-through to `DynamoDBDocumentClient.from` (e.g. `marshallOptions.removeUndefinedValues`). Ignored when `documentClient` is set. |
| `pkPrefix` | `string` | `'rt#'` | Partition key prefix; full `pk` is `prefix` + SHA-256 hex of the plaintext token. |
| `consistentRead` | `boolean` | `true` | Use strongly consistent reads on every `GetItem`, including token rows and revocation marker rows (`sess#…`, `sub#…`). Transaction `ConditionCheck`s stay strongly consistent when this is `false`. |
| `endpoint` | `string` | (resolved by the AWS SDK) | Custom DynamoDB API endpoint (e.g. LocalStack or DynamoDB Local). Ignored when `documentClient` is set. Overridden by `clientConfig.endpoint` when both are set. |
| `documentClient` | `DynamoDBDocumentClient` | (none) | Existing document client. When set, the provider does not construct a client. `clientConfig`, `region`, `endpoint`, and `translateConfig` are not applied. Mutually exclusive with `clientConfig`. |
| `clientConfig` | `DynamoDBClientConfig` | (none) | Passed to `new DynamoDBClient` after `region`, `endpoint`, and the default request handler (connection timeout 5 seconds, request timeout 30 seconds). Fields here override those. `requestHandler` replaces that default handler. Mutually exclusive with `documentClient`. |
| `sessionIdIndexName` | `string` | `'sessionId-index'` | GSI name whose partition key is `sessionId` (required for `revokeSession`). |
| `subjectIdIndexName` | `string` | `'subjectId-index'` | GSI name whose partition key is `subjectId` (required for `revokeSubject`). |
| `revokeSessionOnReuse` | `boolean` | `false` | When true, `rotate` calls `revokeSession` for the token’s session before throwing `DynamodbRefreshTokenProviderReusedError`. |

The positional form `new DynamodbRefreshTokenProvider(tableName, region, options?)` still works but is deprecated.

`issue`, `rotate`, `revoke`, `revokeSession`, and `revokeSubject` accept an optional `now?: Date` for testing or clock injection.

## Requirements

- **Node.js** 20.0.0 or later.
- A **DynamoDB table** with a string partition key **`pk`**, **TTL enabled** on attribute **`ttl`** (see [DynamoDB TTL](#dynamodb-ttl)), a **GSI** on **`sessionId`** for session revocation (see [Session GSI](#session-gsi)), and a **GSI** on **`subjectId`** for subject-wide revocation (see [Subject GSI](#subject-gsi)).
- **AWS credentials** and permissions for `GetItem`, `UpdateItem`, `Query`, `PutItem`, `ConditionCheckItem`, and `TransactWriteItems` on that table (and the configured `endpoint` if used). `issue` and `rotate` use `TransactWriteItems` (`PutItem` or `UpdateItem` plus `ConditionCheckItem` on the marker rows). Do not use `sess#` or `sub#` as `pkPrefix`; those prefixes are the revocation markers.

## License

This project is licensed under the (Apache-2.0) License.
