# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [1.1.0] - 2025-06-04

Commit: 4886d16a42a7f33f51ba9328a0f4566feb0c92d3

### Added

  - On Middleware. We can now register operator specific vaults. The vault to collateral is now set via `_beforeRegisterOperatorVault` hook. We still need to deploy the staker rewards contract manually for operator specific vaults and set it on middleware.
  - On Middleware. Includes method to `setReader`.


### Changed

  - Getting sorted operators ignores the ones with power zero.


## [1.0.1] - 2025-05-28.

Migration code removed.

Commit: 341db12320916c01efc81a64c6106b3f5ed8c9cd

### Added

  - Script to deploy on production.

### Removed

  - On OperatorRewards. Removed migration code.
  - On Middleware. Removes method to `setReader
  - Previous temporary versions of OperatorRewards.

## [1.0.0] - 2025-05-26.

Commit: 4c9ea084d0183b8c9e5fb81e65e5f369d824fa67

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
