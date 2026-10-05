import { ProjenTypeScriptProject } from '@gammarers/projen-projects';
const project = new ProjenTypeScriptProject({
  name: 'dynamodb-refresh-token-provider',
  repositoryUrl: 'https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider.git',
  description: 'TypeScript library that stores opaque refresh tokens in Amazon DynamoDB using AWS SDK for JavaScript v3. Tokens are persisted under a hash of the plaintext value; issue, rotate (with reuse detection via a transactional write), revoke (idempotent), revokeSession (OAuth 2.0 BCP family revocation), and revokeSubject (subject-wide revocation across all sessions) are supported.',
  deps: [
    '@aws-sdk/client-dynamodb@^3.777.0',
    '@aws-sdk/lib-dynamodb@^3.777.0',
  ],
  devDeps: [
    '@gammarers/projen-projects@^0.5.1',
  ],
  releaseToNpm: true,
  npmTrustedPublishing: true,
});
project.synth();