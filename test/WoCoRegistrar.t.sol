// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2RegistryFactory} from "../src/durin/L2RegistryFactory.sol";
import {IL2Registry} from "../src/durin/interfaces/IL2Registry.sol";

contract WoCoRegistrarTest is Test {
    L2RegistryFactory factory;
    L2Registry registry;
    WoCoRegistrar registrar;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address organiser = makeAddr("organiser");
    address stranger = makeAddr("stranger");

    // A short Swarm bzz reference, ENS contenthash-encoded bytes (shape only — content is on Swarm).
    bytes constant SWARM_HASH = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    function setUp() public {
        // Mirror Durin's factory/clone deploy so initializers behave exactly as on-chain.
        L2Registry impl = new L2Registry();
        factory = new L2RegistryFactory(address(impl));

        vm.prank(admin);
        registry = L2Registry(factory.deployRegistry("woco.eth", "WoCo Names", "", admin));

        registrar = new WoCoRegistrar(address(registry), admin);

        vm.startPrank(admin);
        registry.addRegistrar(address(registrar));
        registrar.addSponsor(sponsor);
        registrar.setReserved("admin", true);
        vm.stopPrank();
    }

    function _emptyText() internal pure returns (string[] memory keys, string[] memory vals) {
        keys = new string[](0);
        vals = new string[](0);
    }

    function test_register_mintsToOrganiserAndSetsContenthash() public {
        (string[] memory keys, string[] memory vals) = _emptyText();

        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        assertEq(registry.owner(node), organiser, "organiser owns the name");
        assertEq(registry.contenthash(node), SWARM_HASH, "Swarm pointer set");
        assertFalse(registrar.available("myband"), "no longer available");
    }

    function test_register_setsProfileTextRecords() public {
        string[] memory keys = new string[](2);
        string[] memory vals = new string[](2);
        keys[0] = "description";
        vals[0] = "Independent music venue";
        keys[1] = "avatar";
        vals[1] = "bzz://d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

        vm.prank(sponsor);
        bytes32 node = registrar.register("craufurd-arms", organiser, SWARM_HASH, keys, vals);

        assertEq(registry.text(node, "description"), "Independent music venue");
        assertEq(registry.text(node, "avatar"), vals[1]);
    }

    function test_setContenthash_updatesOnRedeploy() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        bytes memory newHash = hex"e40101fa011b2000000000000000000000000000000000000000000000000000000000deadbeef";
        vm.prank(sponsor);
        registrar.setContenthash("myband", newHash);

        assertEq(registry.contenthash(node), newHash, "pointer updated by platform without organiser signing");
    }

    function test_register_revertsForNonSponsor() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, stranger));
        vm.prank(stranger);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);
    }

    function test_register_revertsForReservedLabel() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "admin"));
        vm.prank(sponsor);
        registrar.register("admin", organiser, SWARM_HASH, keys, vals);
    }

    function test_register_revertsForArrayMismatch() public {
        string[] memory keys = new string[](1);
        string[] memory vals = new string[](0);
        keys[0] = "description";
        vm.expectRevert(WoCoRegistrar.ArrayLengthMismatch.selector);
        vm.prank(sponsor);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);
    }

    function test_validation_rejectsBadLabels() public view {
        assertFalse(registrar.available("ab"), "too short");
        assertFalse(registrar.available("-myband"), "leading hyphen");
        assertFalse(registrar.available("myband-"), "trailing hyphen");
        assertFalse(registrar.available("my--band"), "double hyphen");
        assertFalse(registrar.available("MyBand"), "uppercase");
        assertFalse(registrar.available("my_band"), "underscore");
        assertFalse(registrar.available("admin"), "reserved");
        assertTrue(registrar.available("my-band-3"), "valid label");
    }

    function test_available_falseAfterMint() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        assertTrue(registrar.available("myband"));
        vm.prank(sponsor);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);
        assertFalse(registrar.available("myband"));
    }
}
