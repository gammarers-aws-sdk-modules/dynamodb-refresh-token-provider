import { ProjenTypeScriptProject } from '@gammarers/projen-projects';
const project = new ProjenTypeScriptProject({
  name: 'dynamodb-refresh-token-provider',
  repositoryUrl: 'https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider.git',
  description: 'TypeScript library that stores opaque refresh tokens in Amazon DynamoDB under a hash of the plaintext value using AWS SDK for JavaScript v3, with issue, rotate (reuse detection via a transactional write), idempotent revoke, and strongly consistent revokeSession and revokeSubject via session and subject marker rows so a GSI cannot leave a successor token active.',
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