// SPDX-License-Identifier: BUSL-1.1

pragma solidity 0.8.25;

interface IVaultHints {
    function activeStakeHint(address vault, uint48 timestamp) external view returns (bytes memory);

    function activeSharesHint(address vault, uint48 timestamp) external view returns (bytes memory);

    function activeSharesOfHint(
        address vault,
        address account,
        uint48 timestamp
    ) external view returns (bytes memory hint);
}
