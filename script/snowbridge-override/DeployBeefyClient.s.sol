// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";

//****************************************************************************************
//                                  SNOWBRIDGE
//****************************************************************************************
import {BeefyClient} from "@snowbridge/src/BeefyClient.sol";
import {IGateway} from "@snowbridge/src/interfaces/IGateway.sol";
import {GatewayProxy} from "@snowbridge/src/GatewayProxy.sol";
import {MockGatewayV2} from "@snowbridge/test/mocks/MockGatewayV2.sol";
import {Agent} from "@snowbridge/src/Agent.sol";
import {AgentExecutor} from "@snowbridge/src/AgentExecutor.sol";
import {ChannelID, ParaID, OperatingMode} from "@snowbridge/src/Types.sol";
import {SafeNativeTransfer} from "@snowbridge/src/utils/SafeTransfer.sol";

import {UD60x18, ud60x18} from "prb/math/src/UD60x18.sol";

import {Gateway} from "../../src/snowbridge-override/Gateway.sol";

contract DeployBeefyClient is Script {
    using SafeNativeTransfer for address payable;
    using stdJson for string;

    function setUp() public {}

    function run() public {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privateKey);
        vm.startBroadcast(deployer);

        // BeefyClient
        // Seems `fs_permissions` explicitly configured as absolute path does not work and only allowed from project root
        string memory root = vm.projectRoot();
        string memory beefyCheckpointFile = string.concat(root, "/beefy-state.json");
        string memory beefyCheckpointRaw = vm.readFile(beefyCheckpointFile);
        uint64 startBlock = uint64(beefyCheckpointRaw.readUint(".startBlock"));

        BeefyClient.ValidatorSet memory current = BeefyClient.ValidatorSet(
            uint128(beefyCheckpointRaw.readUint(".current.id")),
            uint128(beefyCheckpointRaw.readUint(".current.length")),
            beefyCheckpointRaw.readBytes32(".current.root")
        );
        BeefyClient.ValidatorSet memory next = BeefyClient.ValidatorSet(
            uint128(beefyCheckpointRaw.readUint(".next.id")),
            uint128(beefyCheckpointRaw.readUint(".next.length")),
            beefyCheckpointRaw.readBytes32(".next.root")
        );

        uint256 randaoCommitDelay = vm.envUint("RANDAO_COMMIT_DELAY");
        uint256 randaoCommitExpiration = vm.envUint("RANDAO_COMMIT_EXP");
        uint256 minimumSignatures = vm.envUint("MINIMUM_REQUIRED_SIGNATURES");
        BeefyClient beefyClient =
            new BeefyClient(randaoCommitDelay, randaoCommitExpiration, minimumSignatures, startBlock, current, next);

        console2.log("BeefyClient: ", address(beefyClient));

        vm.stopBroadcast();
    }
}
