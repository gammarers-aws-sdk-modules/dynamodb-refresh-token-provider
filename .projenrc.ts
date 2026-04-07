import { javascript, typescript, github } from 'projen';
const project = new typescript.TypeScriptProject({
  defaultReleaseBranch: 'main',
  name: 'dynamodb-refresh-token-provider',
  packageManager: javascript.NodePackageManager.YARN_CLASSIC,
  projenrcTs: true,
  authorName: 'yicr',
  authorEmail: 'yicr@users.noreply.github.com',
  typescriptVersion: '5.9.x',
  repository: 'https://github.com/gammarers-aws-sdk-modules/dynamodb-refresh-token-provider.git',
  description: 'TypeScript library that stores **opaque refresh tokens** in **Amazon DynamoDB** using AWS SDK for JavaScript v3. Tokens are persisted under a hash of the plaintext value; **issue**, **rotate** (with reuse detection via a transactional write), and **revoke** (idempotent) are supported.',
  deps: [
    '@aws-sdk/client-dynamodb@^3.777.0',
    '@aws-sdk/lib-dynamodb@^3.777.0',
    '@aws-sdk/util-dynamodb@^3.777.0',
  ],
  releaseToNpm: true,
  npmTrustedPublishing: true,
  npmAccess: javascript.NpmAccess.PUBLIC,
  minNodeVersion: '20.0.0',
  workflowNodeVersion: '24.x',
  depsUpgradeOptions: {
    workflowOptions: {
      labels: ['auto-approve', 'auto-merge'],
      schedule: javascript.UpgradeDependenciesSchedule.WEEKLY,
    },
  },
  githubOptions: {
    projenCredentials: github.GithubCredentials.fromApp({
      permissions: {
        pullRequests: github.workflows.AppPermission.WRITE,
        contents: github.workflows.AppPermission.WRITE,
        workflows: github.workflows.AppPermission.WRITE,
      },
    }),
  },
  autoApproveOptions: {
    allowedUsernames: [
      'gammarers-projen-upgrade-bot[bot]',
      'yicr',
    ],
  },
});
// Corepack は devEngines の `<2.0.0` だけだと `yarn@<2.0.0` となり失敗するため、Yarn 1 の具体版を指定する
project.package.addField('packageManager', 'yarn@1.22.22');
// package ignore .devcontainer directory
project.addPackageIgnore('/.devcontainer');

project.synth();