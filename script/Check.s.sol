// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";

contract CheckScript is Script {
    function checkDurations() public view {
        _check(0x446970400e1787814CA050A4b45AE9d21B3f7EA7);
        _check(0x4e0554959A631B3D3938ffC158e0a7b2124aF9c5);
        _check(0xa88e91cEF50b792f9449e2D4C699b6B3CcE1D19F);
        _check(0x7b276aAD6D2ebfD7e270C5a2697ac79182D9550E);
        _check(0x3D93b33f5E5fe74D54676720e70EA35210cdD46E);
        _check(0x82c304aa105fbbE2aA368A83D7F8945d41f6cA54);
        _check(0xc10A7f0AC6E3944F4860eE97a937C51572e3a1Da);
        _check(0x65B560d887c010c4993C8F8B36E595C171d69D63);
        _check(0x81bb35c4152B605574BAbD320f8EABE2871CE8C6);
        _check(0xaF07131C497E06361dc2F75de63dc1d3e113f7cb);
        _check(0xB8Fd82169a574eB97251bF43e443310D33FF056C);
        _check(0x108784D6B93A010f62b652b2356697dAEF3D7341);
        _check(0x450a90fdEa8B87a6448Ca1C87c88Ff65676aC45b);
        _check(0xEa0F2EA61998346aD39dddeF7513ae90915AFb3c);
    }

    function _check(
        address addr
    ) internal view {
        console2.log("Checking", addr);
        uint48 epochDuration = IVault(addr).epochDuration();
        address slasher = IVault(addr).slasher();
        uint48 vetoDuration = IVetoSlasher(slasher).vetoDuration();
        console2.log("Epoch duration", epochDuration / 1 days);
        console2.log("Veto duration", vetoDuration / 1 days);
    }
}
