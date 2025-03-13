// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";

abstract contract MiddlewareStorage {
    uint256 public constant VERSION = 1;

    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;

    /**
     * @notice Get the operator rewards contract address
     * @return operator rewards contract address
     */
    address public immutable OPERATORS_REWARDS;

    /**
     * @notice Get the staker rewards factory contract address
     * @return staker rewards factory contract address
     */
    address public immutable STAKER_REWARDS_FACTORY;

    /// @custom:storage-location erc7201:tanssi.middleware.MiddlewareStorage.v1
    struct StorageMiddleware {
        IOGateway gateway;
        mapping(uint48 epoch => uint256 amount) totalStakeCache;
        mapping(uint48 epoch => bool) totalStakeIsCached;
        mapping(uint48 epoch => mapping(address operator => uint256 amount)) operatorStakeCache;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.middleware.MiddlewareStorage.v1")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant MIDDLEWARE_STORAGE_LOCATION =
        0x744f79b1118793e0a060dca4f01184704394f6e567161215b3d2c3126631e700;

    function _getMiddlewareStorage() internal pure returns (StorageMiddleware storage $v1) {
        assembly {
            $v1.slot := MIDDLEWARE_STORAGE_LOCATION
        }
    }

    /**
     * @notice Get the gateway contract
     * @return gateway contract
     */
    function getGateway() public view returns (IOGateway) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.gateway;
    }

    /**
     * @notice Get the cached total stake amount for an epoch
     * @param epoch epoch of which to get the total stake
     * @return amount total stake amount
     */
    function totalStakeCache(
        uint48 epoch
    ) public view returns (uint256) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.totalStakeCache[epoch];
    }

    /**
     * @notice Get the total stake cache status for an epoch
     * @param epoch epoch of which to get the cache status
     * @return true if the total stake is cached, false otherwise
     */
    function totalStakeIsCached(
        uint48 epoch
    ) public view returns (bool) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.totalStakeIsCached[epoch];
    }

    /**
     * @notice Get the operator's stake amount cached for an epoch
     * @param epoch epoch of the related operator's stake
     * @param operator operator's address
     * @return operator's stake amount
     */
    function operatorStakeCache(uint48 epoch, address operator) public view returns (uint256) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.operatorStakeCache[epoch][operator];
    }
}
