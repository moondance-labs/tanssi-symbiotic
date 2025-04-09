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

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {OperatorRegistry} from "@symbiotic/contracts/OperatorRegistry.sol";
import {NetworkRegistry} from "@symbiotic/contracts/NetworkRegistry.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {MetadataService} from "@symbiotic/contracts/service/MetadataService.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {IOzAccessControl} from "@symbiotic-middleware/interfaces/extensions/managers/access/IOzAccessControl.sol";
import {PauseableEnumerableSet} from "@symbiotic-middleware/libraries/PauseableEnumerableSet.sol";
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {OperatorManager} from "@symbiotic-middleware/managers/OperatorManager.sol";

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {MockV3Aggregator} from "@chainlink/tests/MockV3Aggregator.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Errors} from "@openzeppelin/contracts/utils/Errors.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {RegisterForeignTokenParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {
    OperatingMode, ParaID, Command, InboundMessage
} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Types.sol";
import {MockGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockGateway.sol";
import {GatewayProxy} from "@tanssi-bridge-relayer/snowbridge/contracts/src/GatewayProxy.sol";
import {Verification} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Verification.sol";
import {AgentExecutor} from "@tanssi-bridge-relayer/snowbridge/contracts/src/AgentExecutor.sol";
import {SetOperatingModeParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";
import {IGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IGateway.sol";
import {Gateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Gateway.sol";

import {UD60x18, ud60x18} from "prb/math/src/UD60x18.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {Token} from "test/mocks/Token.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {IODefaultStakerRewardsFactory} from "src/interfaces/rewarder/IODefaultStakerRewardsFactory.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";

contract RewardsTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 8 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint48 public constant OPERATOR_SHARE = 2000; // 20%
    uint256 public constant ONE_DAY = 86_400;

    // We use pregenerated keys and proofs for the operators, alice becomes operator 3
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    bytes32 public OPERATOR2_KEY;
    bytes32 public OPERATOR3_KEY;
    bytes32 public OPERATOR3_PROOF;
    bytes32 public REWARDS_ROOT;
    bytes public REWARDS_ADDITIONAL_DATA;
    bytes public CLAIM_REWARDS_ADDITIONAL_DATA;

    uint256 public constant AMOUNT_TO_DISTRIBUTE = 100 ether;
    uint32 public constant AMOUNT_TO_CLAIM = 20;
    uint256 public constant TOKENS_PER_POINT = 1;
    uint256 public constant EXPECTED_CLAIMABLE = uint256(AMOUNT_TO_CLAIM) * TOKENS_PER_POINT;

    uint256 public constant OPERATOR_STAKE_ST_ETH = 90 ether;
    uint256 public constant OPERATOR_STAKE_R_ETH = 90 ether;
    uint256 public constant OPERATOR_STAKE_BTC = 2 ether;

    uint8 public constant ORACLE_DECIMALS = 16;
    int256 public constant ORACLE_CONVERSION_ST_ETH = 3000 ether;
    int256 public constant ORACLE_CONVERSION_R_ETH = 3000 ether;
    int256 public constant ORACLE_CONVERSION_W_BTC = 90_000 ether;

    struct VaultAddresses {
        address vault;
        address delegator;
        address slasher;
        address vaultSlashable;
        address delegatorSlashable;
        address slasherSlashable;
        address vaultVetoed;
        address delegatorVetoed;
        address slasherVetoed;
    }

    struct GatewayParams {
        OperatingMode operatingMode;
        ParaID assetHubParaID;
        bytes32 assetHubAgentID;
        uint128 outboundFee;
        uint128 registerTokenFee;
        uint128 sendTokenFee;
        uint128 createTokenFee;
        uint128 maxDestinationFee;
        uint8 foreignTokenDecimals;
        UD60x18 exchangeRate;
        UD60x18 multiplier;
    }

    Middleware public middleware;
    DelegatorFactory public delegatorFactory;
    SlasherFactory public slasherFactory;
    VaultFactory public vaultFactory;
    OperatorRegistry public operatorRegistry;
    NetworkRegistry public networkRegistry;
    OptInService public operatorVaultOptInService;
    OptInService public operatorNetworkOptInService;
    ODefaultOperatorRewards public operatorRewards;

    MetadataService public operatorMetadataService;
    MetadataService public networkMetadataService;
    NetworkMiddlewareService public networkMiddlewareService;
    Token public stETH;
    Token public rETH;
    Token public wBTC;
    VaultConfigurator public vaultConfigurator;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public owner = vm.addr(ownerPrivateKey);

    address public operator = makeAddr("operator");
    address public operator2 = makeAddr("operator2");
    address public operator3 = makeAddr("operator3");

    address public resolver1 = makeAddr("resolver1");
    address public resolver2 = makeAddr("resolver2");

    address tanssi;
    address otherNetwork;

    VaultAddresses public vaultAddresses;
    Vault vault;
    Vault vaultSlashable;
    Vault vaultVetoed;
    Vault[] public vaults;

    VetoSlasher vetoSlasher;

    // GATEWAY

    MockGateway public gatewayLogic;
    GatewayProxy public gateway;

    // remote fees in DOT
    uint128 public outboundFee = 1e10;
    uint128 public registerTokenFee = 0;
    uint128 public sendTokenFee = 1e10;
    uint128 public createTokenFee = 1e10;
    uint128 public maxDestinationFee = 1e11;

    ParaID public bridgeHubParaID = ParaID.wrap(1013);
    bytes32 public bridgeHubAgentID = 0x03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314;
    address public bridgeHubAgent;

    ParaID public assetHubParaID = ParaID.wrap(1000);
    bytes32 public assetHubAgentID = 0x81c5ab2571199e3188135178f3c2c8e2d268be1313d029b30f534fa579b69b79;
    address public assetHubAgent;

    bytes32[] public proof = [bytes32(0x2f9ee6cfdf244060dc28aa46347c5219e303fc95062dd672b4e406ca5c29764b)];
    address public relayer;

    uint64 public maxDispatchGas = 500_000;
    uint256 public maxRefund = 1 ether;
    uint256 public reward = 1 ether;
    bytes32 public messageID = keccak256("cabbage");

    // For DOT
    uint8 public foreignTokenDecimals = 10;

    // ETH/DOT exchange rate
    UD60x18 public exchangeRate = ud60x18(0.0025e18);
    UD60x18 public multiplier = ud60x18(1e18);

    // Scripts
    DeployVault deployVault;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/unit/rewards_data.json");
        string memory json = vm.readFile(path);

        // Get payload
        OPERATOR3_KEY = vm.parseJsonBytes32(json, "$.alice_key");
        OPERATOR2_KEY = vm.parseJsonBytes32(json, "$.bob_key");
        REWARDS_ROOT = vm.parseJsonBytes32(json, "$.root");
        OPERATOR3_PROOF = vm.parseJsonBytes32(json, "$.alice_rewards_proof");
        REWARDS_ADDITIONAL_DATA = vm.parseJsonBytes(json, "$.rewards_additional_data");
        CLAIM_REWARDS_ADDITIONAL_DATA = vm.parseJsonBytes(json, "$.claim_rewards_additional_data");

        DeployCollateral deployCollateral = new DeployCollateral();

        vm.startPrank(owner);
        address stETHAddress = deployCollateral.deployCollateral("stETH");
        stETH = Token(stETHAddress);
        stETH.mint(owner, 1_000_000 ether);
        address rETHAddress = deployCollateral.deployCollateral("rETH");
        rETH = Token(rETHAddress);
        rETH.mint(owner, 1_000_000 ether);
        address wBTCAddress = deployCollateral.deployCollateral("wBTC");
        wBTC = Token(wBTCAddress);
        wBTC.mint(owner, 1_000_000 ether);
        vm.stopPrank();

        address stEthOracle = _deployOracle(ORACLE_DECIMALS, ORACLE_CONVERSION_ST_ETH);
        address rEthOracle = _deployOracle(ORACLE_DECIMALS, ORACLE_CONVERSION_R_ETH);
        address wBtcOracle = _deployOracle(ORACLE_DECIMALS, ORACLE_CONVERSION_W_BTC);

        deployVault = new DeployVault();
        DeploySymbiotic deploySymbiotic = new DeploySymbiotic();

        owner = tanssi = deploySymbiotic.owner();

        DeploySymbiotic.SymbioticAddresses memory symbioticAddresses = deploySymbiotic.deploy(owner);
        vaultFactory = VaultFactory(symbioticAddresses.vaultFactory);
        delegatorFactory = DelegatorFactory(symbioticAddresses.delegatorFactory);
        slasherFactory = SlasherFactory(symbioticAddresses.slasherFactory);
        networkRegistry = NetworkRegistry(symbioticAddresses.networkRegistry);
        operatorRegistry = OperatorRegistry(symbioticAddresses.operatorRegistry);
        operatorVaultOptInService = OptInService(symbioticAddresses.operatorVaultOptInService);
        operatorNetworkOptInService = OptInService(symbioticAddresses.operatorNetworkOptInService);
        operatorMetadataService = MetadataService(symbioticAddresses.operatorMetadataService);
        networkMetadataService = MetadataService(symbioticAddresses.networkMetadataService);
        networkMiddlewareService = NetworkMiddlewareService(symbioticAddresses.networkMiddlewareService);
        vaultConfigurator = VaultConfigurator(symbioticAddresses.vaultConfigurator);

        vm.startPrank(tanssi);
        // Send initial collateral to the operators
        stETH.transfer(operator, OPERATOR_INITIAL_BALANCE);

        rETH.transfer(operator2, OPERATOR_INITIAL_BALANCE);
        wBTC.transfer(operator2, OPERATOR_INITIAL_BALANCE);

        stETH.transfer(operator3, OPERATOR_INITIAL_BALANCE);
        rETH.transfer(operator3, OPERATOR_INITIAL_BALANCE);
        wBTC.transfer(operator3, OPERATOR_INITIAL_BALANCE);

        _deployVaults(tanssi);

        DeployRewards deployRewards = new DeployRewards(true);
        address operatorRewardsAddress = deployRewards.deployOperatorRewardsContract(
            tanssi, address(networkMiddlewareService), OPERATOR_SHARE, owner
        );
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            address(vaultFactory), address(networkMiddlewareService), operatorRewardsAddress, tanssi
        );
        middleware = _deployMiddlewareWithProxy(tanssi, owner, address(operatorRewards), stakerRewardsFactoryAddress);

        middleware.setCollateralToOracle(address(stETH), stEthOracle);
        middleware.setCollateralToOracle(address(rETH), rEthOracle);
        middleware.setCollateralToOracle(address(wBTC), wBtcOracle);

        vetoSlasher = VetoSlasher(vaultAddresses.slasherVetoed);

        vetoSlasher.setResolver(0, resolver1, hex"");
        vetoSlasher.setResolver(0, resolver2, hex"");
        vm.stopPrank();

        vault = Vault(vaultAddresses.vault);
        vaultSlashable = Vault(vaultAddresses.vaultSlashable);
        vaultVetoed = Vault(vaultAddresses.vaultVetoed);
        vaults.push(vault);
        vaults.push(vaultSlashable);
        vaults.push(vaultVetoed);

        _registerOperator(operator, tanssi, address(vault));
        _registerOperator(operator3, tanssi, address(vaultSlashable));
        _registerOperator(operator2, tanssi, address(vaultVetoed));

        _registerEntitiesToMiddleware(owner);
        _setOperatorsNetworkShares(tanssi);

        _setLimitForNetworkAndOperators(tanssi);

        vm.startPrank(operator);
        _depositToVault(vault, operator, OPERATOR_STAKE_ST_ETH, stETH);

        vm.startPrank(operator2);
        _depositToVault(vaultSlashable, operator2, OPERATOR_STAKE_R_ETH, rETH);
        _depositToVault(vaultVetoed, operator2, OPERATOR_STAKE_BTC, wBTC);
        operatorVaultOptInService.optIn(address(vaultSlashable));
        vm.stopPrank();

        vm.startPrank(operator3);
        _depositToVault(vault, operator3, OPERATOR_STAKE_ST_ETH, stETH);
        _depositToVault(vaultSlashable, operator3, OPERATOR_STAKE_R_ETH, rETH);
        _depositToVault(vaultVetoed, operator3, OPERATOR_STAKE_BTC, wBTC);
        operatorVaultOptInService.optIn(address(vault));
        operatorVaultOptInService.optIn(address(vaultVetoed));

        vm.stopPrank();

        vm.startPrank(tanssi);
        _setupGateway();
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        HELPERS
    // ************************************************************************************************

    function _deployMiddlewareWithProxy(
        address _network,
        address _owner,
        address _operatorRewardsAddress,
        address _stakerRewardsFactoryAddress
    ) public returns (Middleware _middleware) {
        Middleware _middlewareImpl = new Middleware(_operatorRewardsAddress, _stakerRewardsFactoryAddress);
        _middleware = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: _network,
            operatorRegistry: address(operatorRegistry),
            vaultRegistry: address(vaultFactory),
            operatorNetworkOptIn: address(operatorNetworkOptInService),
            owner: _owner,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: address(new OBaseMiddlewareReader())
        });
        _middleware.initialize(params);

        networkMiddlewareService.setMiddleware(address(_middleware));
    }

    function _deployVaults(
        address _owner
    ) public {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DeployVault.DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(stETH),
            owner: _owner
        });

        (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) = deployVault.createBaseVault(params);

        params.collateral = address(rETH);
        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            deployVault.createSlashableVault(params);

        params.collateral = address(wBTC);
        params.delegatorIndex = DeployVault.DelegatorIndex.FULL_RESTAKE;
        (vaultAddresses.vaultVetoed, vaultAddresses.delegatorVetoed, vaultAddresses.slasherVetoed) =
            deployVault.createVaultVetoed(params, 1 days);
    }

    function _depositToVault(Vault _vault, address _operator, uint256 _amount, Token collateral) public {
        collateral.approve(address(_vault), _amount);
        _vault.deposit(_operator, _amount);
    }

    function _registerEntitiesToMiddleware(
        address _owner
    ) public {
        vm.startPrank(_owner);
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: _owner,
            adminFeeClaimRoleHolder: _owner,
            adminFeeSetRoleHolder: _owner
        });
        middleware.registerSharedVault(vaultAddresses.vault, stakerRewardsParams);
        middleware.registerSharedVault(vaultAddresses.vaultSlashable, stakerRewardsParams);
        middleware.registerSharedVault(vaultAddresses.vaultVetoed, stakerRewardsParams);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerOperator(operator2, abi.encode(OPERATOR2_KEY), address(0));
        middleware.registerOperator(operator3, abi.encode(OPERATOR3_KEY), address(0));
        vm.stopPrank();
    }

    function _registerOperator(address _operator, address _network, address _vault) public {
        vm.startPrank(_operator);
        operatorRegistry.registerOperator();
        operatorVaultOptInService.optIn(address(_vault));
        operatorNetworkOptInService.optIn(_network);
        vm.stopPrank();
    }

    function _setOperatorsNetworkShares(
        address _owner
    ) public {
        vm.startPrank(_owner);
        //The total shares are 3 (TOTAL_NETWORK_SHARE), so each operator has 1 share (OPERATOR_SHARE)
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator2, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR_SHARE
        );

        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator2, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR_SHARE
        );
        vm.stopPrank();
    }

    function _setLimitForNetworkAndOperators(
        address _owner
    ) public {
        vm.startPrank(_owner);
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setMaxNetworkLimit(0, 1000 ether);

        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);

        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator2, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, 300 ether
        );
        vm.stopPrank();
    }

    function _setupGateway() public {
        AgentExecutor executor = new AgentExecutor();
        gatewayLogic = new MockGateway(
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

        IOGateway(address(gateway)).setMiddleware(address(middleware));
        middleware.setGateway(address(gateway));

        relayer = makeAddr("relayer");
    }

    function _makeReportRewardsCommand(
        uint256 amount
    ) public returns (Command, bytes memory, address) {
        uint256 epoch = 1;
        uint256 eraIndex = 1;
        uint256 totalPointsToken = amount;
        uint256 tokensInflatedToken = amount;
        bytes32 rewardsRoot = bytes32(uint256(1));
        bytes32 foreignTokenId = bytes32(uint256(1));

        RegisterForeignTokenParams memory params =
            RegisterForeignTokenParams({foreignTokenID: foreignTokenId, name: "Test", symbol: "TST", decimals: 10});

        vm.expectEmit(true, true, false, false);
        emit IGateway.ForeignTokenRegistered(foreignTokenId, address(0));
        MockGateway(address(gateway)).registerForeignTokenPublic(abi.encode(params));

        address tokenAddress = MockGateway(address(gateway)).tokenAddressOf(foreignTokenId);

        return (
            Command.ReportRewards,
            abi.encode(epoch, eraIndex, totalPointsToken, tokensInflatedToken, rewardsRoot, foreignTokenId),
            tokenAddress
        );
    }

    function makeMockProof() public pure returns (Verification.Proof memory) {
        return Verification.Proof({
            leafPartial: Verification.MMRLeafPartial({
                version: 0,
                parentNumber: 0,
                parentHash: bytes32(0),
                nextAuthoritySetID: 0,
                nextAuthoritySetLen: 0,
                nextAuthoritySetRoot: 0
            }),
            leafProof: new bytes32[](0),
            leafProofOrder: 0,
            parachainHeadsRoot: bytes32(0)
        });
    }

    // ************************************************************************************************
    // *                                        BASE TESTS
    // ************************************************************************************************

    function testInitialState() public view {
        assertEq(OBaseMiddlewareReader(address(middleware)).NETWORK(), tanssi);
        assertEq(OBaseMiddlewareReader(address(middleware)).OPERATOR_REGISTRY(), address(operatorRegistry));
        assertEq(OBaseMiddlewareReader(address(middleware)).VAULT_REGISTRY(), address(vaultFactory));
        assertEq(EpochCapture(address(middleware)).getEpochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(OBaseMiddlewareReader(address(middleware)).SLASHING_WINDOW(), SLASHING_WINDOW);
        assertEq(OBaseMiddlewareReader(address(middleware)).subnetworksLength(), 1);
    }

    function testSubmitRewards() public {
        vm.warp(64_000);

        deal(assetHubAgent, 50 ether);

        uint256 amount = 1.2 ether;
        (Command command, bytes memory params, address tokenAddress) = _makeReportRewardsCommand(amount);

        (uint256 epoch, uint256 eraIndex,,,,) =
            abi.decode(params, (uint256, uint256, uint256, uint256, bytes32, bytes32));

        vm.expectEmit(false, true, true, true);
        emit IODefaultOperatorRewards.DistributeRewards(
            uint48(epoch), uint48(eraIndex), tokenAddress, 1, amount, bytes32(uint256(1))
        );

        // Expect the gateway to emit `InboundMessageDispatched`
        vm.expectEmit(true, true, true, true);
        emit IGateway.InboundMessageDispatched(assetHubParaID.into(), 1, messageID, true);

        hoax(relayer, 1 ether);
        IGateway(address(gateway)).submitV1(
            InboundMessage(assetHubParaID.into(), 1, command, params, maxDispatchGas, maxRefund, reward, messageID),
            proof,
            makeMockProof()
        );

        assert(Token(tokenAddress).balanceOf(address(operatorRewards)) == amount);
    }

    function testSubmitRewardsWithBogusToken() public {
        deal(assetHubAgent, 50 ether);

        uint256 amount = 1.2 ether;
        (Command command, bytes memory params, address tokenAddress) = _makeReportRewardsCommand(amount);

        // Expect the gateway to emit error event.
        vm.expectEmit(true, true, true, false);
        emit IOGateway.UnableToProcessRewardsMessageB(
            abi.encodeWithSelector(
                Gateway.EUnableToProcessRewardsB.selector,
                ONE_DAY * 3,
                0,
                tokenAddress,
                amount,
                amount,
                bytes32(uint256(1)),
                abi.encodeWithSelector(Errors.InsufficientBalance.selector, 0, amount)
            )
        );

        // Expect the gateway to emit `InboundMessageDispatched`
        vm.expectEmit(true, true, true, true);
        emit IGateway.InboundMessageDispatched(assetHubParaID.into(), 1, messageID, false); // false because failed

        // Mock mint to not actually mint tokens, which means gateway will try to send more that it owns.
        vm.mockCall(tokenAddress, abi.encodeWithSelector(Token.mint.selector), abi.encode());

        hoax(relayer, 1 ether);
        IGateway(address(gateway)).submitV1(
            InboundMessage(assetHubParaID.into(), 1, command, params, maxDispatchGas, maxRefund, reward, messageID),
            proof,
            makeMockProof()
        );
    }

    function testClaimRewardsWithMultipleVaults() public {
        uint48 epoch = 1;
        uint48 eraIndex = 0;
        uint48 epochStartTs = middleware.getEpochStart(epoch);

        vm.warp(NETWORK_EPOCH_DURATION * 2 + 1);

        Token rewardsToken = new Token("Rewards", 18);
        rewardsToken.mint(address(middleware), AMOUNT_TO_DISTRIBUTE);

        vm.startPrank(address(gateway));
        middleware.distributeRewards(
            epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT, address(rewardsToken)
        );
        vm.stopPrank();

        bytes32[] memory operatator3Proof = new bytes32[](1);
        // Create a valid proof that matches the root we set
        operatator3Proof[0] = OPERATOR3_PROOF;

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: OPERATOR3_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: operatator3Proof,
            data: REWARDS_ADDITIONAL_DATA
        });

        // 40% of the staker rewards are distributed to the first vault. Order is important due to rounding.
        uint256 expectedAmountStakers = (EXPECTED_CLAIMABLE * 80) / 100;
        uint256[] memory expectedRewardsPerVault =
            _getExpectedRewardsPerVault(operator3, epochStartTs, expectedAmountStakers);

        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.DistributeRewards(
            tanssi, address(rewardsToken), eraIndex, epoch, expectedRewardsPerVault[0], REWARDS_ADDITIONAL_DATA
        );
        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.DistributeRewards(
            tanssi, address(rewardsToken), eraIndex, epoch, expectedRewardsPerVault[1], REWARDS_ADDITIONAL_DATA
        );
        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.DistributeRewards(
            tanssi, address(rewardsToken), eraIndex, epoch, expectedRewardsPerVault[2], REWARDS_ADDITIONAL_DATA
        );

        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.ClaimRewards(
            operator3, address(rewardsToken), eraIndex, epoch, address(this), EXPECTED_CLAIMABLE
        );

        {
            uint256 gasBefore = gasleft();
            operatorRewards.claimRewards(claimRewardsData);
            uint256 gasAfter = gasleft();

            uint256 gasClaiming = gasBefore - gasAfter;
            console2.log("Total gas used: ", gasClaiming);
        }

        uint256 amountClaimed_ = operatorRewards.claimed(eraIndex, operator3);
        assertEq(amountClaimed_, EXPECTED_CLAIMABLE);

        _checkStakerRewardsBalanceForVault(rewardsToken, address(vault), expectedRewardsPerVault[0]);
        _checkStakerRewardsBalanceForVault(rewardsToken, address(vaultSlashable), expectedRewardsPerVault[1]);
        _checkStakerRewardsBalanceForVault(rewardsToken, address(vaultVetoed), expectedRewardsPerVault[2]);
    }

    function _getExpectedRewardsPerVault(
        address operator_,
        uint48 epochStartTs,
        uint256 expectedAmountStakers
    ) private view returns (uint256[] memory rewards) {
        uint256 powerVault1 = IOBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(
            epochStartTs, operator_, address(vault), uint96(0)
        );
        uint256 powerVault2 = IOBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(
            epochStartTs, operator_, address(vaultSlashable), uint96(0)
        );
        uint256 powerVault3 = IOBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(
            epochStartTs, operator_, address(vaultVetoed), uint96(0)
        );

        uint256 totalPower = powerVault1 + powerVault2 + powerVault3;
        rewards = new uint256[](3);

        rewards[0] = expectedAmountStakers.mulDiv(powerVault1, totalPower);
        rewards[1] = expectedAmountStakers.mulDiv(powerVault2, totalPower);
        rewards[2] = expectedAmountStakers - rewards[0] - rewards[1];
    }

    function _checkStakerRewardsBalanceForVault(Token token, address vault_, uint256 expectedAmount) private view {
        address stakerRewards = operatorRewards.vaultToStakerRewardsContract(vault_);
        uint256 stakerRewardsVault1Balance = token.balanceOf(stakerRewards);
        assertEq(stakerRewardsVault1Balance, expectedAmount);
    }

    function _deployOracle(uint8 decimals, int256 answer) public returns (address) {
        MockV3Aggregator oracle = new MockV3Aggregator(decimals, answer);
        return address(oracle);
    }
}
