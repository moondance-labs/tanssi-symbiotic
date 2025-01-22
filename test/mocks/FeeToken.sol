// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Moondance Labs Ltd.
// This file is part of Tanssi.
// Tanssi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// Tanssi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with Tanssi.  If not, see <http://www.gnu.org/licenses/>

pragma solidity 0.8.25;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockFeeToken is ERC20 {
    uint256 public fee;

    constructor(string memory name_, uint256 _fee) ERC20(name_, "") {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
        fee = _fee;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        address spender = _msgSender();
        uint256 feeAmount = (value * fee) / 100;
        _spendAllowance(from, spender, value);
        _transfer(from, to, value - feeAmount);
        return true;
    }
}
