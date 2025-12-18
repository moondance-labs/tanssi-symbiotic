// //SPDX-License-Identifier: GPL-3.0-or-later

// // Copyright (C) Moondance Labs Ltd.
// // This file is part of Tanssi.
// // Tanssi is free software: you can redistribute it and/or modify
// // it under the terms of the GNU General Public License as published by
// // the Free Software Foundation, either version 3 of the License, or
// // (at your option) any later version.
// // Tanssi is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// // GNU General Public License for more details.
// // You should have received a copy of the GNU General Public License
// // along with Tanssi.  If not, see <http://www.gnu.org/licenses/>
// pragma solidity 0.8.25;

// import {Script, console2} from "forge-std/Script.sol";

// //**************************************************************************************************
// //                                      SYMBIOTIC
// //**************************************************************************************************
// import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
// import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
// import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
// import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
// import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
// import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
// import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
// import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

// contract Checks is Script {
//     using Subnetwork for address;
//     using Subnetwork for bytes32;

//     function run(
//         address middleware
//     ) public view {
//         address tanssi = 0xdaD051447C4452e15B35B7F831ceE8DEb890f1a4;
//         address danceVaultAddress = 0x08e89DC0bae29eE531C07BEf6Fd322AF04C32F43;

//         IOBaseMiddlewareReader reader = IOBaseMiddlewareReader(middleware);
//         uint48 currentEpoch = reader.getCurrentEpoch();
//         uint48 epochStartTs = reader.getEpochStart(currentEpoch + 1);
//         console2.log("Middleware address", middleware);
//         console2.log("Current Middleware epoch", currentEpoch);
//         console2.log("Epoch start timestamp", epochStartTs);
//         address[] memory activeOperators = reader.activeOperatorsAt(epochStartTs);
//         console2.log("Active operators length", activeOperators.length);

//         IVault danceVault = IVault(danceVaultAddress);
//         uint256 currentVaultEpoch = danceVault.currentEpoch();
//         uint256 epochStartTsVault = danceVault.currentEpochStart();
//         console2.log("Current DANCE vault epoch start timestamp", epochStartTsVault);
//         console2.log("Current DANCE vault epoch", currentVaultEpoch);

//         IMiddleware.OperatorVaultPair[] memory operatorVaultPairs = reader.getOperatorVaultPairs(currentEpoch);
//         console2.log("Operator vault pairs length", operatorVaultPairs.length);
//         // for (uint256 i; i < operatorVaultPairs.length; i++) {
//         //     console2.log("Operator vault pair", i);
//         //     console2.log(operatorVaultPairs[i].operator);
//         //     console2.log(operatorVaultPairs[i].vaults.length);
//         // }
//         IMiddleware.ValidatorData[] memory validators = reader.getValidatorSet(currentEpoch + 1);
//         console2.log("Validators length", validators.length);
//         for (uint256 i; i < validators.length; i++) {
//             console2.log("Validator", i);
//             console2.logBytes32(validators[i].key);
//             console2.log("power", validators[i].power);
//             console2.log(reader.operatorByKey(abi.encode(validators[i].key)));
//         }

//         // activeOperators = reader.activeOperators();
//         // console2.log("Active operators length", activeOperators.length);
//         // // for (uint256 i; i < activeOperators.length; i++) {
//         // //     console2.log("Active operator", i);
//         // //     console2.log(activeOperators[i]);
//         // // }

//         // address[] memory danceOperators = new address[](5);
//         // danceOperators[0] = 0xF0a697Fb63a277e8d6931E0831398B0c3ae3739B;
//         // danceOperators[1] = 0x4A9E53fc3e3Fa2897E8AB03b6c1AEe621a5cDFBd;
//         // danceOperators[2] = 0xBFA0cc854B31031a608c10e3aBc41b194dfc2C9A;
//         // danceOperators[3] = 0xc7BC260FC622681064edE65A70143aFA08Fb8E61;
//         // danceOperators[4] = 0xbe73024022096FB6eB1709c2165046FaB300BcF0;

//         // IOperatorRegistry operatorRegistry = IOperatorRegistry(0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548);
//         // IOptInService operatorNetworkOptInService = IOptInService(0x58973d16FFA900D11fC22e5e2B6840d9f7e13401);
//         // IOptInService operatorVaultOptInService = IOptInService(0x95CC0a052ae33941877c9619835A233D21D57351);
//         // for (uint256 i; i < danceOperators.length; i++) {
//         //     console2.log("Operator", danceOperators[i]);
//         //     console2.log("Is opted in to operator registry", operatorRegistry.isEntity(danceOperators[i]));
//         //     console2.log(
//         //         "Is opted in to Tanssi network", operatorNetworkOptInService.isOptedIn(danceOperators[i], tanssi)
//         //     );
//         //     console2.log(
//         //         "Is opted in to DANCE vault", operatorVaultOptInService.isOptedIn(danceOperators[i], danceVaultAddress)
//         //     );
//         //     console2.log("Is registered in middleware", reader.isOperatorRegistered(danceOperators[i]));

//         //     console2.log("Power in DANCE vault", reader.getOperatorPower(danceOperators[i], danceVaultAddress, 0));
//         // }
//     }
// }
