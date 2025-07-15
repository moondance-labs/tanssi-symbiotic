# Migration

This file contains history of changes made to the codebase that require migration steps. So each time there is a breaking change that require a migration, it should be documented here.

The format to follow is:

```
## [<version>] - <date>
Commit: [<commit_hash>]

Steps to migrate:
- <step 1>
...
- <step n>
```

## [TBD]

## Steps to migrate:

- Deploy new OBaseMiddlewareReader implementation
- Deploy new Middleware implementation
- Upgrade to new Middleware implementation
- Call Middleware.setReader with the new reader address.
