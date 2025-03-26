// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
/**
 * @title IOERC20
 * @notice Interface for managing ERC20 tokens, including decimals
 */

interface IOERC20 is IERC20 {
    /**
     * @notice Returns the decimals of the token
     * @return The number of decimals
     */
    function decimals() external view returns (uint8);
}
