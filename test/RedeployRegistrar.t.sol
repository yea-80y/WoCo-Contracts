// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ScriptEnvFixture} from "./ScriptEnvFixture.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {RedeployRegistrar} from "../script/RedeployRegistrar.s.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {IL2Registry} from "../src/durin/interfaces/IL2Registry.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";

/**
 * Tests for the registrar redeploy script.
 *
 * Redeploying the registrar is the ROUTINE operation — the registry is frozen,
 * so every policy change ships this way. The v2 script owns the new registrar by
 * the Safe from construction, never wires it (no deployer key can), and prints
 * the Safe batch that enrols it AND retires the previous registrar — the step v1
 * only reminded the operator about (audit 927 M2).
 */
contract RedeployRegistrarTest is ScriptEnvFixture {
    L2Registry registry;
    WoCoRegistrar previous;
    MockSafe safe;
    address deployer;
    address sponsor = SCRIPT_SPONSOR;

    function setUp() public {
        deployer = vm.addr(SCRIPT_DEPLOYER_PK);
        safe = new MockSafe();

        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", address(safe));
        previous = new WoCoRegistrar(address(registry), address(safe), sponsor, new string[](0));
        vm.prank(address(safe));
        registry.addRegistrar(address(previous));

        // Shared keys come from ScriptEnvFixture - read its header before adding
        // any `vm.setEnv` here. Anything that must VARY per test varies through a
        // `_config()` override instead, never through the environment.
        _setSharedScriptEnv();
        vm.setEnv("L2_REGISTRY_ADDRESS", vm.toString(address(registry)));
        vm.setEnv("REGISTRAR_ADMIN", vm.toString(address(safe)));
    }

    /*//////////////////////////////////////////////////////////////
                    THE SAFE OWNS IT; THE SCRIPT WIRES NOTHING
    //////////////////////////////////////////////////////////////*/

    /// Read through the real environment, so the env wiring is exercised once.
    function test_Redeploy_TheSafeOwnsTheNewRegistrarFromConstruction() public {
        uint64 nonceBefore = vm.getNonce(deployer);
        WoCoRegistrar registrar = WoCoRegistrar(new RedeployRegistrar().run());

        assertEq(vm.getNonce(deployer), nonceBefore + 1, "the redeploy sent more than one transaction");
        assertEq(registrar.owner(), address(safe));
        assertEq(registrar.pendingOwner(), address(0));
        assertEq(address(registrar.registry()), address(registry));
        assertTrue(registrar.authorisedSponsors(sponsor), "sponsor not authorised");
        assertFalse(registrar.available("admin"), "reserved label is mintable");
        assertFalse(registrar.available("woco"), "reserved label is mintable");
        assertTrue(registrar.available("myvenue"), "an ordinary label should be free");
    }

    function test_Redeploy_DoesNotWire() public {
        WoCoRegistrar registrar = WoCoRegistrar(new RedeployRegistrar().run());
        assertFalse(registry.registrars(address(registrar)), "the script wired the registrar");

        bytes32 base = registry.baseNode();
        address organiser = makeAddr("organiser");
        string[] memory none = new string[](0);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        vm.prank(sponsor);
        registrar.register("myvenue", organiser, hex"e301", none, none);
    }

    /*//////////////////////////////////////////////////////////////
                              THE SAFE BATCH
    //////////////////////////////////////////////////////////////*/

    /// The whole point of the batch: afterwards the new registrar mints, and the
    /// previous one can neither mint nor repoint — through its sponsor or the
    /// registry.
    function test_Redeploy_TheBatchSwapsTheRegistrarIn() public {
        // The previous registrar is live and has minted a name.
        string[] memory none = new string[](0);
        vm.prank(sponsor);
        previous.register("oldname", makeAddr("old-holder"), hex"e301", none, none);

        RedeployRegistrar script = new WithInputs(address(safe), address(previous));
        WoCoRegistrar next = WoCoRegistrar(script.run());
        _executeAsSafe(script, address(next), address(previous));

        address organiser = makeAddr("organiser");
        vm.prank(sponsor);
        bytes32 node = next.register("myvenue", organiser, hex"e301", none, none);
        assertEq(registry.owner(node), organiser, "the new registrar cannot mint");

        assertFalse(registry.registrars(address(previous)), "the previous registrar is still enrolled");
        assertFalse(previous.authorisedSponsors(sponsor), "the previous registrar's sponsor survived");

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, sponsor));
        vm.prank(sponsor);
        previous.setContenthash("oldname", hex"e302");
    }

    /// Enrolment first, so that at no point in the batch is nothing enrolled;
    /// then the previous registrar's sponsor; then the previous registrar.
    function test_Redeploy_TheBatchEnrolsBeforeItRetires() public {
        RedeployRegistrar script = new RedeployRegistrar();
        address next = makeAddr("next");
        (address[] memory targets, bytes[] memory data) =
            script.adminBatch(address(registry), next, address(previous), sponsor);

        assertEq(targets.length, 3);
        assertEq(targets[0], address(registry));
        assertEq(data[0], abi.encodeCall(IL2Registry.addRegistrar, (next)));
        assertEq(targets[1], address(previous));
        assertEq(data[1], abi.encodeCall(WoCoRegistrar.removeSponsor, (sponsor)));
        assertEq(targets[2], address(registry));
        assertEq(data[2], abi.encodeCall(IL2Registry.removeRegistrar, (address(previous))));
    }

    function test_Redeploy_WithoutAPreviousRegistrarTheBatchOnlyEnrols() public {
        RedeployRegistrar script = new RedeployRegistrar();
        address next = makeAddr("next");
        (address[] memory targets, bytes[] memory data) = script.adminBatch(address(registry), next, address(0), sponsor);

        assertEq(targets.length, 1);
        assertEq(targets[0], address(registry));
        assertEq(data[0], abi.encodeCall(IL2Registry.addRegistrar, (next)));
    }

    /// A mistyped previous registrar would print a retirement that retires
    /// nothing while the real one keeps minting.
    function test_Redeploy_RefusesAPreviousRegistrarThatIsNotEnrolled() public {
        RedeployRegistrar script = new WithInputs(address(safe), makeAddr("typo"));
        vm.expectRevert("PREVIOUS_REGISTRAR is not enrolled in this registry");
        script.run();
    }

    /// The batch's `removeSponsor` succeeds only from the previous registrar's
    /// owner, and the whole batch comes from the registry admin: when they
    /// differ, the batch would revert as a unit. Refused up front, with the way
    /// out named — the state the Arbitrum Sepolia pair is in today.
    function test_Redeploy_RefusesAPreviousRegistrarTheRegistryAdminDoesNotOwn() public {
        MockSafe otherOwner = new MockSafe();
        WoCoRegistrar foreign = new WoCoRegistrar(address(registry), address(otherOwner), sponsor, new string[](0));
        vm.prank(address(safe));
        registry.addRegistrar(address(foreign));

        RedeployRegistrar script = new WithInputs(address(safe), address(foreign));
        vm.expectRevert("PREVIOUS_REGISTRAR is not owned by the registry admin - retire its sponsor separately");
        script.run();
    }

    /*//////////////////////////////////////////////////////////////
                    THE ADMIN MUST BE SHAPED LIKE A SAFE
    //////////////////////////////////////////////////////////////*/

    function test_Redeploy_RefusesTheZeroAddressAdmin() public {
        RedeployRegistrar script = new WithInputs(address(0), address(0));
        vm.expectRevert("REGISTRAR_ADMIN must not be the zero address");
        script.run();
    }

    function test_Redeploy_RefusesABareKeyAdmin() public {
        RedeployRegistrar script = new WithInputs(makeAddr("bare-key"), address(0));
        vm.expectRevert("REGISTRAR_ADMIN has no code - expected the Safe");
        script.run();
    }

    /// The Safe's own signer is an EIP-7702 delegated EOA, which has code.
    function test_Redeploy_RefusesAnEip7702DelegatedAdmin() public {
        address account = makeAddr("delegated-signer");
        vm.etch(account, abi.encodePacked(hex"ef0100", address(safe)));
        RedeployRegistrar script = new WithInputs(account, address(0));
        vm.expectRevert("REGISTRAR_ADMIN is an EIP-7702 delegated EOA - expected the Safe, not a signer account");
        script.run();
    }

    /// The designator's prefix is refused, not a size.
    function test_Redeploy_TheDesignatorPrefixIsRefusedNotTheSize() public {
        address twentyThree = makeAddr("twenty-three-bytes");
        vm.etch(twentyThree, abi.encodePacked(hex"600000", address(safe)));
        assertEq(WoCoRegistrar(new WithInputs(twentyThree, address(0)).run()).owner(), twentyThree);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _executeAsSafe(RedeployRegistrar script, address next, address prev) internal {
        (address[] memory targets, bytes[] memory data) = script.adminBatch(address(registry), next, prev, sponsor);
        for (uint256 i; i < targets.length; ++i) {
            vm.prank(address(safe));
            (bool ok,) = targets[i].call(data[i]);
            assertTrue(ok, "a batch call failed");
        }
    }
}

/*//////////////////////////////////////////////////////////////
                    CONFIGURATION VARIANTS
//////////////////////////////////////////////////////////////*/

/// @dev Overrides only the inputs; every guard in `run()` is the real one.
contract WithInputs is RedeployRegistrar {
    address internal immutable configuredAdmin;
    address internal immutable configuredPrevious;

    constructor(address admin_, address previous_) {
        configuredAdmin = admin_;
        configuredPrevious = previous_;
    }

    function _config() internal view override returns (Config memory c) {
        c = super._config();
        c.registrarAdmin = configuredAdmin;
        c.previousRegistrar = configuredPrevious;
    }
}

/// @dev A contract, because `REGISTRAR_ADMIN` must not be a bare key.
contract MockSafe {}
