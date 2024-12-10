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

import {ParaID, Ticket, ChannelID, Channel} from "@snowbridge/src/Types.sol";
import {Gateway} from "@snowbridge/src/Gateway.sol";
import {IGateway} from "@snowbridge/src/interfaces/IGateway.sol";

import {Operators} from "./Operators.sol";
import {IOGateway} from "./interfaces/IOGateway.sol";

contract OGateway is Gateway {
    constructor(
        address beefyClient,
        address agentExecutor,
        ParaID bridgeHubParaID,
        bytes32 bridgeHubAgentID,
        uint8 foreignTokenDecimals,
        uint128 maxDestinationFee
    ) Gateway(beefyClient, agentExecutor, bridgeHubParaID, bridgeHubAgentID, foreignTokenDecimals, maxDestinationFee) {}

    function sendOperatorsData(bytes32[] calldata data, ParaID destinationChain) external {
        Ticket memory ticket = Operators.encodeOperatorsData(data, destinationChain);
        _oSubmitOutbound(ticket);
    }

    // Submit an outbound message to Polkadot, after taking fees
    function _oSubmitOutbound(
        Ticket memory ticket
    ) internal {
        ChannelID channelID = ticket.dest.into();
        Channel storage channel = _ensureChannel(channelID);
        // Ensure outbound messaging is allowed
        _ensureOutboundMessagingEnabled(channel);

        // // Destination fee always in DOT
        // uint256 fee = _calculateFee(ticket.costs);

        // // Ensure the user has enough funds for this message to be accepted
        // if (msg.value < fee) {
        //     revert FeePaymentToLow();
        // }

        channel.outboundNonce = channel.outboundNonce + 1;

        // // Deposit total fee into agent's contract
        // payable(channel.agent).safeNativeTransfer(fee);

        // // Reimburse excess fee payment
        // if (msg.value > fee) {
        //     payable(msg.sender).safeNativeTransfer(msg.value - fee);
        // }

        // Generate a unique ID for this message
        bytes32 messageID = keccak256(abi.encodePacked(channelID, channel.outboundNonce));

        emit IGateway.OutboundMessageAccepted(channelID, channel.outboundNonce, messageID, ticket.payload);
    }
}
