# Migration

This file contains history of changes made to the codebase that require migration steps. So each time there is a breaking change that require a migration, it should be documented here.

The format to follow is:

```
## [<version>]

Steps to migrate:
- <step 1>
...
- <step n>
```

## [1.2.0]

## Steps to migrate:

- Deploy new `ODefaultStakerRewardsFactory` contract.
- Deploy new `Middleware` contract.
- Upgrade the `Middleware` contract to the new version `upgradeToAndCall`.
- Once deployed the new `Middleware` call `reinitializeRewards` to set the new `operatorRewards` and `stakerRewardsFactory` addresses.
- Deploy new `ODefaultStakerRewards` contracts implementation.
- Set the new implementation in the `ODefaultStakerRewardsFactory` contract.
- Call for each `ODefaultStakerRewards` contract deployed the new `setVault` function to set the new vault address, since that is taken out of the constructor.
- In v1.2.1, deployed instantly after, upgrade the implementation of the `ODefaultStakerRewards` contracts to a version without `setVault`.
