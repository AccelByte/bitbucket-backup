# Backup Bitbucket Repos

## Backups are in git's bundle format
Git bundles are single files treated as repos, simply clone directly from them as if they were repos:

    % git clone justice-ue4-sdk.bundle justice-ue4-sdk-restore
    Cloning into 'justice-ue4-sdk-restore'...
    Receiving objects: 100% (1114/1114), 615.87 MiB | 108.32 MiB/s, done.
    Resolving deltas: 100% (494/494), done.
    % cd justice-ue4-sdk-restore
    justice-ue4-sdk-restore% git status
    On branch master
    Your branch is up to date with 'origin/master'.
    nothing to commit, working tree clean

## Features
- Repos are backed up in Git bundles to reduce the time to recovery and only git is needed
- Git branches are added to the metadata on S3 objects for tracking
- Only repos that have changed are uploaded to S3
- Runs from a Bitbucket Pipelines project, no servers to setup
- Relies on S3 bucket versioning and retention policies to track and expire backups 

## Settings
| Environment Variable           | Description                                      |
| ------------------------------| ------------------------------------------------- |
| BITBUCKET_OAUTH_CLIENT_ID     | Bitbucket OAuth Client ID                         |
| BITBUCKET_OAUTH_CLEINT_SECRET | Bitbucket OAuth Secret                            |
| BITBUCKET_TEAM                | Bitbucket Team Name                               |
| AWS_S3BUCKET_NAME             | S3 Bucket (defaults to: _team_-bitbucket-backups) |
| AWS_REGION                    | AWS Region (defaults to: us-west-2)               |
| LOG_LEVEL_NUMBER              | Logrus log level (Debug=5, Info=4, Warn=3, ...)   |

