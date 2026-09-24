// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// Audit 964 I-1: `ENSDNSUtils.dnsDecode` (used by L2Registry) writes past its
/// output on purpose and is only memory-safe because nothing is compiled via
/// IR (see the comment in `src/durin/lib/ENSDNSUtils.sol`). Nothing enforced
/// that; this does, for the config file and the environment override.
contract BuildConfigTest is Test {
    function test_ViaIrStaysOff() public view {
        string memory toml = vm.readFile("foundry.toml");
        assertFalse(vm.contains(toml, "via_ir = true"), "foundry.toml enables via-IR");
        assertFalse(vm.contains(toml, "via-ir = true"), "foundry.toml enables via-IR");
        assertFalse(vm.envOr("FOUNDRY_VIA_IR", false), "FOUNDRY_VIA_IR is set");
    }
}
