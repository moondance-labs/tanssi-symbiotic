// // SPDX-License-Identifier: BUSL-1.1
// pragma solidity 0.8.25;

// import {Script, console2} from "forge-std/Script.sol";

// import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
// import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
// import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
// import {Middleware} from "src/contracts/middleware/Middleware.sol";
// import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";

// contract VaultsInfo is Script {
//     function run(address middleware, address operatorRewards) public view {
//         _checkVault(0x446970400e1787814CA050A4b45AE9d21B3f7EA7, operatorRewards);
//         _checkVault(0x4e0554959A631B3D3938ffC158e0a7b2124aF9c5, operatorRewards);
//         _checkVault(0xa88e91cEF50b792f9449e2D4C699b6B3CcE1D19F, operatorRewards);
//         _checkVault(0x7b276aAD6D2ebfD7e270C5a2697ac79182D9550E, operatorRewards);
//         _checkVault(0x3D93b33f5E5fe74D54676720e70EA35210cdD46E, operatorRewards);
//         _checkVault(0x82c304aa105fbbE2aA368A83D7F8945d41f6cA54, operatorRewards);
//         _checkVault(0xc10A7f0AC6E3944F4860eE97a937C51572e3a1Da, operatorRewards);
//         _checkVault(0x65B560d887c010c4993C8F8B36E595C171d69D63, operatorRewards);
//         _checkVault(0x81bb35c4152B605574BAbD320f8EABE2871CE8C6, operatorRewards);
//         _checkVault(0xaF07131C497E06361dc2F75de63dc1d3e113f7cb, operatorRewards);
//         _checkVault(0xB8Fd82169a574eB97251bF43e443310D33FF056C, operatorRewards);
//         _checkVault(0x108784D6B93A010f62b652b2356697dAEF3D7341, operatorRewards);
//         _checkVault(0x450a90fdEa8B87a6448Ca1C87c88Ff65676aC45b, operatorRewards);
//         _checkVault(0xEa0F2EA61998346aD39dddeF7513ae90915AFb3c, operatorRewards);

//         // _checkCollateral(0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0, middleware);
//         // _checkCollateral(0x8c1BEd5b9a0928467c9B1341Da1D7BD5e10b6549, middleware);
//         // _checkCollateral(0xa2E3356610840701BDf5611a53974510Ae27E2e1, middleware);
//         // _checkCollateral(0xae78736Cd615f374D3085123A210448E74Fc6393, middleware);
//         // _checkCollateral(0xBe9895146f7AF43049ca1c1AE358B0541Ea49704, middleware);
//         // _checkCollateral(0xf951E335afb289353dc249e82926178EaC7DEd78, middleware);
//     }

//     // function _checkCollateral(address collateral, address middleware) internal view {
//     //     address oracle = Middleware(middleware).collateralToOracle(collateral);
//     //     string memory name = IERC20Metadata(collateral).name();
//     //     string memory symbol = IERC20Metadata(collateral).symbol();

//     //     console2.log("collateral:", collateral);
//     //     console2.log("oracle:", oracle);
//     //     console2.log("name:", name);
//     //     console2.log("symbol:", symbol);
//     // }

//     function _checkVault(address vault, address operatorRewards) internal view {
//         address slasher = IVault(vault).slasher();
//         address delegator = IVault(vault).delegator();
//         address stakerRewards = IODefaultOperatorRewards(operatorRewards).vaultToStakerRewardsContract(vault);
//         // Get using EIP-1967:
//         address stakerRewardsImplementation = address(
//             uint160(
//                 uint256(
//                     vm.load(
//                         stakerRewards,
//                         bytes32(uint256(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc))
//                     )
//                 )
//             )
//         );
//         console2.log("vault:", vault);
//         console2.log("slasher:", slasher);
//         console2.log("delegator:", delegator);
//         console2.log("stakerRewards:", stakerRewards);
//         console2.log("stakerRewardsImplementation:", stakerRewardsImplementation);
//     }
// }
