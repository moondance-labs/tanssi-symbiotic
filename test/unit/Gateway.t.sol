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

import {Test, console2} from "forge-std/Test.sol";
import {
    AgentExecuteCommand,
    InboundMessage,
    OperatingMode,
    ParaID,
    ChannelID,
    Command,
    multiAddressFromBytes32,
    multiAddressFromBytes20
} from "@snowbridge/src/Types.sol";
import {IGateway} from "@snowbridge/src/interfaces/IGateway.sol";
import {MockGateway} from "@snowbridge/test/mocks/MockGateway.sol";
import {CreateAgentParams, CreateChannelParams} from "@snowbridge/src/Params.sol";
import {OperatingMode, ParaID, Command} from "@snowbridge/src/Types.sol";
import {GatewayProxy} from "@snowbridge/src/GatewayProxy.sol";
import {MultiAddress} from "@snowbridge/src/MultiAddress.sol";
import {AgentExecutor} from "@snowbridge/src/AgentExecutor.sol";
import {SetOperatingModeParams} from "@snowbridge/src/Params.sol";

import {Strings} from "openzeppelin/utils/Strings.sol";

import {Gateway} from "../../src/snowbridge-override/Gateway.sol";
import {IOGateway} from "../../src/snowbridge-override/interfaces/IOGateway.sol";
import {Operators} from "../../src/snowbridge-override/Operators.sol";
import {MockOGateway} from "../../test/mocks/snowbridge-override/MockOGateway.sol";

//NEW
import {WETH9} from "canonical-weth/WETH9.sol";
import {UD60x18, ud60x18, convert} from "prb/math/src/UD60x18.sol";

contract GatewayTest is Test {
    // Emitted when token minted/burnt/transfered
    event Transfer(address indexed from, address indexed to, uint256 value);

    ParaID public bridgeHubParaID = ParaID.wrap(1013);
    bytes32 public bridgeHubAgentID = 0x03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314;
    address public bridgeHubAgent;

    ParaID public assetHubParaID = ParaID.wrap(1000);
    bytes32 public assetHubAgentID = 0x81c5ab2571199e3188135178f3c2c8e2d268be1313d029b30f534fa579b69b79;
    address public assetHubAgent;

    address public relayer;

    bytes32[] public proof = [bytes32(0x2f9ee6cfdf244060dc28aa46347c5219e303fc95062dd672b4e406ca5c29764b)];
    bytes public parachainHeaderProof = bytes("validProof");

    MockOGateway public gatewayLogic;
    GatewayProxy public gateway;

    WETH9 public token;

    address public account1;
    address public account2;

    uint64 public maxDispatchGas = 500_000;
    uint256 public maxRefund = 1 ether;
    uint256 public reward = 1 ether;
    bytes32 public messageID = keccak256("cabbage");

    // remote fees in DOT
    uint128 public outboundFee = 1e10;
    uint128 public registerTokenFee = 0;
    uint128 public sendTokenFee = 1e10;
    uint128 public createTokenFee = 1e10;
    uint128 public maxDestinationFee = 1e11;

    MultiAddress public recipientAddress32;
    MultiAddress public recipientAddress20;

    // For DOT
    uint8 public foreignTokenDecimals = 10;

    // ETH/DOT exchange rate
    UD60x18 public exchangeRate = ud60x18(0.0025e18);
    UD60x18 public multiplier = ud60x18(1e18);

    // tokenID for DOT
    bytes32 public dotTokenID;

    ChannelID internal constant PRIMARY_GOVERNANCE_CHANNEL_ID = ChannelID.wrap(bytes32(uint256(1)));
    ChannelID internal constant SECONDARY_GOVERNANCE_CHANNEL_ID = ChannelID.wrap(bytes32(uint256(2)));

    function setUp() public {
        AgentExecutor executor = new AgentExecutor();
        gatewayLogic = new MockOGateway(
            address(0), address(executor), bridgeHubParaID, bridgeHubAgentID, foreignTokenDecimals, maxDestinationFee
        );
        Gateway.Config memory config = Gateway.Config({
            mode: OperatingMode.Normal,
            deliveryCost: outboundFee,
            registerTokenFee: registerTokenFee,
            assetHubParaID: assetHubParaID,
            assetHubAgentID: assetHubAgentID,
            assetHubCreateAssetFee: createTokenFee,
            assetHubReserveTransferFee: sendTokenFee,
            exchangeRate: exchangeRate,
            multiplier: multiplier,
            rescueOperator: 0x4B8a782D4F03ffcB7CE1e95C5cfe5BFCb2C8e967
        });
        gateway = new GatewayProxy(address(gatewayLogic), abi.encode(config));
        MockGateway(address(gateway)).setCommitmentsAreVerified(true);

        SetOperatingModeParams memory params = SetOperatingModeParams({mode: OperatingMode.Normal});
        MockGateway(address(gateway)).setOperatingModePublic(abi.encode(params));

        bridgeHubAgent = IGateway(address(gateway)).agentOf(bridgeHubAgentID);
        assetHubAgent = IGateway(address(gateway)).agentOf(assetHubAgentID);

        // fund the message relayer account
        relayer = makeAddr("relayer");

        // Features

        token = new WETH9();

        account1 = makeAddr("account1");
        account2 = makeAddr("account2");

        // create tokens for account 1
        hoax(account1);
        token.deposit{value: 500}();

        // create tokens for account 2
        token.deposit{value: 500}();

        recipientAddress32 = multiAddressFromBytes32(keccak256("recipient"));
        recipientAddress20 = multiAddressFromBytes20(bytes20(keccak256("recipient")));

        dotTokenID = bytes32(uint256(1));
    }

    bytes private constant FINAL_VALIDATORS_PAYLOAD =
        hex"7015003800000cd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe228eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a480100000000000000";

    bytes32[] private VALIDATORS_DATA = [
        bytes32(0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d),
        bytes32(0x90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22),
        bytes32(0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48)
    ];

    function createLongOperatorsData() public view returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](1001);

        for (uint256 i = 0; i <= 1000; i++) {
            result[i] = VALIDATORS_DATA[i % 3];
        }

        return result;
    }

    function _createParaIDAndAgent() public returns (ParaID) {
        ParaID paraID = ParaID.wrap(1);
        bytes32 agentID = keccak256("1");

        MockGateway(address(gateway)).createAgentPublic(abi.encode(CreateAgentParams({agentID: agentID})));

        CreateChannelParams memory params =
            CreateChannelParams({channelID: paraID.into(), agentID: agentID, mode: OperatingMode.Normal});

        MockGateway(address(gateway)).createChannelPublic(abi.encode(params));
        return paraID;
    }

    function testSendOperatorsDataX() public {
        // Create mock agent and paraID
        vm.expectEmit(true, false, false, true);
        emit IGateway.OutboundMessageAccepted(PRIMARY_GOVERNANCE_CHANNEL_ID, 1, messageID, FINAL_VALIDATORS_PAYLOAD);

        IOGateway(address(gateway)).sendOperatorsData(VALIDATORS_DATA);
    }

    function testShouldNotSendOperatorsDataBecauseOperatorsTooLong() public {
        bytes32[] memory longOperatorsData = createLongOperatorsData();

        vm.expectRevert(Operators.Operators__OperatorsLengthTooLong.selector);
        IOGateway(address(gateway)).sendOperatorsData(longOperatorsData);
    }

    function testSendOperatorsDataWith50Entries() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/snowbridge-data/test_vector_message_validator_50.json");
        string memory json = vm.readFile(path);

        // Get payload
        bytes memory final_payload = vm.parseJsonBytes(json, "$.payload");

        // Get accounts array
        bytes32[] memory accounts = abi.decode(vm.parseJson(json, "$.accounts"), (bytes32[]));

        vm.expectEmit(true, false, false, true);
        emit IGateway.OutboundMessageAccepted(PRIMARY_GOVERNANCE_CHANNEL_ID, 1, messageID, final_payload);

        IOGateway(address(gateway)).sendOperatorsData(accounts);
    }

    function testSendOperatorsDataWith400Entries() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/snowbridge-data/test_vector_message_validator_400.json");
        string memory json = vm.readFile(path);

        // Get payload
        bytes memory final_payload = vm.parseJsonBytes(json, "$.payload");

        // Get accounts array
        bytes32[] memory accounts = abi.decode(vm.parseJson(json, "$.accounts"), (bytes32[]));

        vm.expectEmit(true, false, false, true);
        emit IGateway.OutboundMessageAccepted(PRIMARY_GOVERNANCE_CHANNEL_ID, 1, messageID, final_payload);

        IOGateway(address(gateway)).sendOperatorsData(accounts);
    }

    function testSendOperatorsDataWith1000Entries() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/snowbridge-data/test_vector_message_validator_1000.json");
        string memory json = vm.readFile(path);

        // Get payload
        bytes memory final_payload = vm.parseJsonBytes(json, "$.payload");

        // Get accounts array
        bytes32[] memory accounts = abi.decode(vm.parseJson(json, "$.accounts"), (bytes32[]));

        vm.expectEmit(true, false, false, true);
        emit IGateway.OutboundMessageAccepted(PRIMARY_GOVERNANCE_CHANNEL_ID, 1, messageID, final_payload);

        IOGateway(address(gateway)).sendOperatorsData(accounts);
    }
}
