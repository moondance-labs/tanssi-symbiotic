//SPDX-License-Identifier: GPL-3.0-or-later

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

import {console2} from "forge-std/console2.sol";
import {BeefyClient} from "@snowbridge/src/BeefyClient.sol";
import {ScaleCodec} from "@snowbridge/src/utils/ScaleCodec.sol";
import {OSubstrateTypes} from "./libraries/OSubstrateTypes.sol";
import {MultiAddress, Ticket, Costs, ParaID} from "@snowbridge/src/Types.sol";

import {IOGateway} from "src/interfaces/snowbridge-override/IOGateway.sol";

library Operators {
    error Operators__OperatorsLengthTooLong();
    error Operators__OperatorsKeysCannotBeEmpty();

    uint16 private constant MAX_OPERATORS = 1000;

    function encodeOperatorsData(
        bytes32[] calldata operatorsKeys,
        ParaID dest
    ) internal returns (Ticket memory ticket) {
        if (operatorsKeys.length == 0) {
            revert Operators__OperatorsKeysCannotBeEmpty();
        }
        uint256 validatorsKeysLength = operatorsKeys.length;

        if (validatorsKeysLength > MAX_OPERATORS) {
            revert Operators__OperatorsLengthTooLong();
        }

        ticket.dest = dest;
        //TODO For now mock it to 0
        ticket.costs = Costs(0, 0);

        ticket.payload = OSubstrateTypes.EncodedOperatorsData(operatorsKeys, uint32(validatorsKeysLength));
        emit IOGateway.OperatorsDataCreated(validatorsKeysLength, ticket.payload);
    }
}