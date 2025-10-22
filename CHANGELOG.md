# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [1.2.3] - 2025-10-17

### Changed

- Reduces the number operators to process in an upkeep batch from 20 to 10.

## [1.2.2] - 2025-08-15

### Removed

- On ODefaultStakerRewards. Removed `setVault` method.

## [1.2.1] - 2025-08-07

Commit: [e87bb61b74f982344bece33d7173ce99481ee8e8](https://github.com/moondance-labs/tanssi-symbiotic/commit/e87bb61b74f982344bece33d7173ce99481ee8e8)

### Added

- On ODefaultOperatorRewards. Adds `batchClaimRewards` method.
- On ODefaultStakerRewards. Adds `batchClaimRewards` method.
- On RewardsHintsBuilder. Adds `batchGetDataForOperatorClaimRewards`, `getHintsForStakerClaimRewards`, and `batchGetHintsForStakerClaimRewards` methods.

### Changed

- On Middleware. `operatorRewards` and `stakerRewardsFactory` are now saved on the storage.
- On Middleware and OBaseMiddlewareReader. `checkUpkeep` now includes epoch in the `performData`, `performUpkeep` validates it matches the current one.
- On Middleware and OBaseMiddlewareReader. Gas optimization for `checkUpkeep` and `performUpkeep` by processing all operators and checking for active ones only within each batch.
- On OBaseMiddlewareReader. `checkUpkeep` now sends at most `MAX_OPERATORS_TO_SEND`, that is 58 operators. This is to prevent the performData from being over the 2000 bytes limit imposed by Chainlink.
- On OBaseMiddlewareReader. `getOperatorToPower` was renamed to `getOperatorToPowerCached`, since it only returns cached values.
- On OBaseMiddlewareReader. `sortOperatorsByPower` now ignores operators with power zero.
- On OBaseMiddlewareReader. `getOperatorToPower` now returns 0 if the operator is not found.
- On ODefaultStakerRewards. Admin address is now mandatory on `initialize`, otherwise upgrading would be impossible.
- Updates ownership and rewards diagrams.

## [1.2.0] - 2025-07-22

Commit: [48f23a960775c1630b4b4ef384e2a2075a633ecd](https://github.com/moondance-labs/tanssi-symbiotic/commit/48f23a960775c1630b4b4ef384e2a2075a633ecd)

This release includes several breaking changes.

### Added

- On StakerRewards. Added method to `claimRewards` with custom data.
- On Middleware. Added a new independent storage location only for caching operator power.
- AggregatorV3DIAProxy was added to be able to use DIA as a price feed without changing the middleware, by implementing the Chainlink's AggregatorV3 interface.
- Contract addresses and deployment logs for each environment: stagelight, dancelight, moonlight and tanssi.
- Adds RewardsHintsBuilder. This is a helper contract to easily build hints data for the `OperatorRewards.claimRewards` method.
- Prepares script and tests deploying a Tanssi vault.

### Changed

- On StakerRewardsFactory. It now uses a single implementation for all staker rewards contracts, setting addresses for operator rewards and vault on initialization. **Breaking change**.
- On StakerRewardsFactory. It now implements `Ownable2Step`. The ownership is used to set the implementation.
- On Middleware. Constructor no longer includes operator rewards and staker rewards factory addresses. A `reinitializeRewards` method was added to set them. **Breaking change**.
- On Middleware. `checkUpkeep` and `performUpkeep` were refactored to not go over the Chainlink's max gas limit nor max perform data size. Multiple calls might be needed to complete the upkeep depending on the number of operators.
- On Middleware. Added 2 commands for `checkUpkeep` and `performUpkeep` to understand if the execution should cache or send data. This is to prevent any double "spending".
- On Middleware. `checkUpkeep` and `sortOperatorsByPower` were optimized to consume less gas.
- On Middleware. The implementation of `checkUpkeep` and `stakeToPower` methods were delegated to the `OBaseMiddlewareReader` contract to reduce `Middleware` contract size.
- On Middleware. Stake to power immediately returns 0 if the stake is 0, this saves gas on most operator-vault pairs which don't have any stake.
- On Middleware. Operator keys are now checked to have 32 bytes length.
- On Middleware. When registering a shared vault, it now reverts if there are already 80 shared vaults registered. This is to prevent over gas limit errors later on rewards distribution and slashing.
- On Middleware. When getting the sorted keys, we check for each operator if its operator specific vaults plus the shared vaults are over the 80 limit. If that's the case, we set their power to 0 to prevent the same error above.
- On OperatorRewards. Reverts with custom error when no staker rewards contract is set for a vault. Previously it would revert with a panic error making debugging harder.
- On OperatorRewards. `claimRewards` can now receive hints for each of the vaults, this produces gas savings from up to 25% in the call. This also fixes the bug of using the same hint for all vaults. **Breaking change**.

## [1.1.1] - 2025-07-02

Commit: [9c3b9c6ebc0905d930845bf1d5e11640b073b4dc](https://github.com/moondance-labs/tanssi-symbiotic/commit/9c3b9c6ebc0905d930845bf1d5e11640b073b4dc)

### Changed

- Updates submodule dependency for bridge relayer

## [1.1.0] - 2025-06-04

Commit: [4886d16a42a7f33f51ba9328a0f4566feb0c92d3](https://github.com/moondance-labs/tanssi-symbiotic/commit/4886d16a42a7f33f51ba9328a0f4566feb0c92d3)

### Added

- On Middleware. We can now register operator specific vaults. The vault to collateral is now set via `_beforeRegisterOperatorVault` hook. We still need to deploy the staker rewards contract manually for operator specific vaults and set it on middleware.
- On Middleware. Includes method to `setReader`.

### Changed

- Getting sorted operators ignores the ones with power zero.

## [1.0.1] - 2025-05-28.

Migration code removed.

Commit: [341db12320916c01efc81a64c6106b3f5ed8c9cd](https://github.com/moondance-labs/tanssi-symbiotic/commit/341db12320916c01efc81a64c6106b3f5ed8c9cd)

### Added

- Script to deploy on production.

### Removed

- On OperatorRewards. Removed migration code.
- On Middleware. Removes method to `setReader
- Previous temporary versions of OperatorRewards.

## [1.0.0] - 2025-05-26.

Commit: [4c9ea084d0183b8c9e5fb81e65e5f369d824fa67](https://github.com/moondance-labs/tanssi-symbiotic/commit/4c9ea084d0183b8c9e5fb81e65e5f369d824fa67)

Most important audit findings fixed. Includes breaking changes and migration code.

### Added

- On Middleware. Includes method to `executeSlash`.
- On Middleware. Includes method to `setReader`.
- On StakerRewards. On `claimAdminFee`, includes `epoch` in the `ClaimAdminFee` event.
- On OperatorRewards. Adds method to `migrate` storage for the 2 breaking changes.

### Changed

- On Middleware. `sendCurrentOperatorsKeys` will not call gateway if called too recently (last 10 minutes), to prevent spamming.
- **[BREAKING]** On OperatorRewards. Claimed rewards are now tracked by Operator Key instead of their EVM address, to prevent double claiming. This affects also the `claimed` view method.
- **[BREAKING]** On OperatorRewards. `EraRoot.tokensPerPoint` was replaced by `EraRoot.totalPoints`. This allows us to calculate rewards per vault with higher precision.

### Fixed

- On MiddlewareReader. `getOperatorVaultPairs`, the length of the resulting array is adjusted to the number of operators with at least one vault. Leaving no empty slots.
- On MiddlewareReader. `getEpochAtTs` when timestamp is just at the end of an epoch, it now returns the correct one instead of the next.
- On OperatorRewards. When distributing rewards to vaults, the ones with power zero are ignored. They would revert otherwise on later checks.
- On StakerRewards. When distributing rewards, it no longer reverts if the epoch timestamp is same as current timestamp, only if it's greater.
