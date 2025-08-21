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

## [1.2.2]

## Steps to migrate:

- Deploy new `ODefaultStakerRewards` contract implementation.
- Upgrade each `ODefaultStakerRewards` to this new implementation via `upgradeToAndCall`
- Set the new implementation in the `ODefaultStakerRewardsFactory` contract.

## [1.2.1]

## Steps to migrate:

- Deploy new `Middleware` contract.
- Deploy new `MiddlewareReader` contract.
- Upgrade the `Middleware` contract to the new version `upgradeToAndCall`, with the call being `reinitializeRewards` to the current `operatorRewards` proxy and the current `stakerRewardsFactory` addresses.
- Set the new `MiddlewareReader` address in the `Middleware` contract via `setReader`.
- Deploy new `ODefaultOperatorRewards` contract implementation.
- Upgrade the `ODefaultOperatorRewards` contract to the new version `upgradeToAndCall`.
- Deploy new `ODefaultStakerRewards` contract implementation.
- Set the new implementation in the `ODefaultStakerRewardsFactory` contract.
- Upgrade each `ODefaultStakerRewards` to this new implementation via `upgradeToAndCall`
- Only in Stagelight/Dancelight, deploy new `RewardsHintsBuilder` contract
- In v1.2.2, deployed instantly after, upgrade the implementation of the `ODefaultStakerRewards` contracts to a version without `setVault`.
- In v1.2.2, upgrades in mainnet fork tests should be removed since they are no longer needed. They are marked with TODO.

## [1.2.0]

## Steps to migrate:

- Deploy new `ODefaultStakerRewardsFactory` contract.
- Deploy new `Middleware` contract.
- Deploy new `MiddlewareReader` contract.
- Upgrade the `Middleware` contract to the new version `upgradeToAndCall`.
- Once deployed the new `Middleware` call `reinitializeRewards` to set the new `operatorRewards` and `stakerRewardsFactory` addresses.
- Set the new `MiddlewareReader` address in the `Middleware` contract via `setReader`.
- Deploy new `ODefaultOperatorRewards` contract implementation.
- Upgrade the `ODefaultOperatorRewards` contract to the new version `upgradeToAndCall`.
- Deploy new `ODefaultStakerRewards` contract implementation.
- Set the new implementation in the `ODefaultStakerRewardsFactory` contract.
- Upgrade each `ODefaultStakerRewards` to this new implementation via `upgradeToAndCall`
- Call for each `ODefaultStakerRewards` contract deployed the new `setVault` function to set the new vault address, since that is taken out of the constructor.
- Deploy `AggregatorV3DIAProxy` with TANSSI/USD pair symbol to support the new vault.
- Deploy `RewardsHintsBuilder` to be able to get the hints to call `claimRewards` on `ODefaultOperatorRewards` contract.
- Call `setCollateralToOracle` in the Middleware to set the new `AggregatorV3DIAProxy` address.
- In v1.2.1, deployed instantly after, upgrade the implementation of the `ODefaultStakerRewards` contracts to a version without `setVault`.
- In v1.2.1, upgrades in mainnet fork tests should be removed since they are no longer needed. They are marked with TODO.
