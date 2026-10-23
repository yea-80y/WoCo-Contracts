// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeploySubEnsRegistry} from "../script/DeploySubEnsRegistry.s.sol";
import {RedeployRegistrar} from "../script/RedeployRegistrar.s.sol";

/**
 * The labels no registrar ever mints. Two deploy scripts each carry the list (a fresh
 * registry, and the routine registrar redeploy), so they are pinned to each other here,
 * and to the names a sign-in page could be mistaken for: `auth` is the passkey host
 * (auth.woco.eth, held on L1), `accounts` and `login` look like it; `scan` is the door
 * scanner's name, `door` and `scanner` look like it.
 */
contract ReservedLabelsTest is Test {
    function test_bothScriptsReserveTheSameLabels() public {
        string[] memory fresh = new DeploySubEnsRegistry().reservedLabels();
        string[] memory redeploy = new RedeployRegistrar().reservedLabels();
        assertEq(fresh.length, redeploy.length, "same count");
        for (uint256 i; i < fresh.length; ++i) {
            assertEq(keccak256(bytes(fresh[i])), keccak256(bytes(redeploy[i])), fresh[i]);
        }
    }

    function test_theSignInAndScannerNamesAreReserved() public {
        string[] memory labels = new RedeployRegistrar().reservedLabels();
        string[7] memory wanted = ["app", "auth", "accounts", "login", "scan", "door", "scanner"];
        for (uint256 w; w < wanted.length; ++w) {
            bool found;
            for (uint256 i; i < labels.length; ++i) {
                if (keccak256(bytes(labels[i])) == keccak256(bytes(wanted[w]))) found = true;
            }
            assertTrue(found, wanted[w]);
        }
    }
}
