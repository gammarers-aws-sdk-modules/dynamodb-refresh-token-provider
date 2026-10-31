import { ProjenTypeScriptProject } from '@gammarers/projen-projects';
const project = new ProjenTypeScriptProject({
  name: 'dynamodb-refresh-token-provider',
  repositoryUrl: 'https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider.git',
  description: 'TypeScript library that stores opaque refresh tokens in Amazon DynamoDB under a hash of the plaintext value using AWS SDK for JavaScript v3, with issue, rotate (reuse detection via a transactional write), idempotent revoke, revokeSession (OAuth 2.0 BCP family revocation), and revokeSubject (subject-wide revocation across all sessions).',
  deps: [
    '@aws-sdk/client-dynamodb@^3.777.0',
    '@aws-sdk/lib-dynamodb@^3.777.0',
  ],
  devDeps: [
    '@gammarers/projen-projects@^0.6.2',
  ],
  releaseToNpm: true,
  npmTrustedPublishing: true,
});
project.synth();