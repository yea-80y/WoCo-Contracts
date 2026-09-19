// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {ScriptEnvFixture} from "./ScriptEnvFixture.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {DeploySubEnsRegistry} from "../script/DeploySubEnsRegistry.s.sol";
import {WoCoSubEnsDeployer} from "../src/WoCoSubEnsDeployer.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";

/**
 * Tests for the sub-ENS v2 deploy script and `WoCoSubEnsDeployer`
 * (WoCo-Contracts #21).
 *
 * They run the script and assert what it actually put on chain: one
 * transaction, the admin seat on the Safe from construction and never
 * anywhere else, a registrar that answers to whoever holds that seat, left for
 * the Safe to wire. And they prove each
 * check the script makes fires on its own, by substituting a deployment that
 * check must reject.
 *
 * The #440 tripwire tests are carried from v1: the bug was never a contract
 * defect, it was a deploy that put a DIFFERENT registry on chain than the one
 * the tests exercised.
 */
contract DeploySubEnsRegistryTest is ScriptEnvFixture {
    DeploySubEnsRegistry script;
    MockSafe safe;
    address deployer;

    function setUp() public {
        script = new DeploySubEnsRegistry();
        safe = new MockSafe();
        deployer = vm.addr(SCRIPT_DEPLOYER_PK);
        // Shared keys come from ScriptEnvFixture — read its header before adding
        // any `vm.setEnv` here. Anything that must VARY per test varies through
        // the script's `_registryAdmin` / `_deploy` seams, never the environment.
        _setSharedScriptEnv();
        vm.setEnv("REGISTRY_ADMIN", vm.toString(address(safe)));
    }

    /*//////////////////////////////////////////////////////////////
                  THE DEPLOY PRODUCES *OUR* REGISTRY
    //////////////////////////////////////////////////////////////*/

    /// The headline #440 assertion: the registry that goes live is a clone of an
    /// implementation this deploy created, not of anything NameStone deployed.
    function test_Deploy_RegistryIsACloneOfOurOwnImplementation() public {
        (address registryAddr,) = script.run();

        assertEq(registryAddr.code.length, 45, "registry is not an EIP-1167 clone");

        address impl = _embeddedImplementation(registryAddr);
        assertTrue(impl.code.length > 0, "implementation has no code");
        assertTrue(
            impl != 0xdeB09eB3111cB75d538216e8B8fC30047d75fb34,
            "registry still points at NameStone's implementation"
        );
    }

    /// Audits 924 F-10 / 927 M9: v1 cloned in one transaction and initialised in
    /// the next, and anyone could have initialised in between. The deploy key
    /// now sends exactly one transaction, and when it lands nobody can
    /// initialise the registry again.
    function test_Deploy_IsOneTransactionAndLeavesNoInitialiseWindow() public {
        uint64 nonceBefore = vm.getNonce(deployer);
        (address registryAddr,) = script.run();
        assertEq(vm.getNonce(deployer), nonceBefore + 1, "the deploy sent more than one transaction");

        address interloper = makeAddr("interloper");
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        L2Registry(registryAddr).initialize("woco.eth", "WoCo Names", "", interloper);
    }

    /// The same property of the deployer contract on its own: by the time its
    /// constructor returns, the clone is initialised and the implementation can
    /// never be.
    function test_Deployer_InitialisesTheCloneInsideItsOwnConstructor() public {
        WoCoSubEnsDeployer d = new WoCoSubEnsDeployer("woco.eth", address(safe), SCRIPT_SPONSOR, script.reservedLabels());
        L2Registry registry = d.registry();
        L2Registry implementation = d.implementation();
        address interloper = makeAddr("interloper");

        assertEq(registry.owner(), address(safe));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        registry.initialize("woco.eth", "WoCo Names", "", interloper);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        implementation.initialize("woco.eth", "WoCo Names", "", interloper);
    }

    /// No rotation: the admin seat's only Transfer is its mint, straight to the
    /// Safe, and the registrar stores no owner at all — it emits no ownership
    /// event and answers to the seat. So neither role was ever held by anyone
    /// else — not the deployer, not for a block.
    function test_Deploy_NoRotation_NeitherRoleWasEverAnywhereElse() public {
        vm.recordLogs();
        (address registryAddr, address registrarAddr) = script.run();
        Vm.Log[] memory logs = vm.getRecordedLogs();

        uint256 baseToken = uint256(L2Registry(registryAddr).baseNode());
        bytes32 transferSig = keccak256("Transfer(address,address,uint256)");
        bytes32 ownershipSig = keccak256("OwnershipTransferred(address,address)");
        bytes32 startedSig = keccak256("OwnershipTransferStarted(address,address)");

        uint256 seatTransfers;
        uint256 registrarOwnerships;
        for (uint256 i; i < logs.length; ++i) {
            Vm.Log memory l = logs[i];
            if (l.emitter == registryAddr && l.topics[0] == transferSig && uint256(l.topics[3]) == baseToken) {
                seatTransfers++;
                assertEq(address(uint160(uint256(l.topics[1]))), address(0), "the seat came from someone");
                assertEq(address(uint160(uint256(l.topics[2]))), address(safe), "the seat went somewhere else");
            }
            if (l.emitter == registrarAddr && (l.topics[0] == ownershipSig || l.topics[0] == startedSig)) {
                registrarOwnerships++;
            }
        }
        assertEq(seatTransfers, 1, "the admin seat moved more than once");
        assertEq(registrarOwnerships, 0, "the registrar emitted an ownership event - it has an owner of its own");
        assertEq(WoCoRegistrar(registrarAddr).owner(), address(safe));
    }

    function test_Deploy_BothRolesOnTheSafeWithNoHandoverOpen() public {
        (address registryAddr, address registrarAddr) = script.run();

        assertEq(L2Registry(registryAddr).owner(), address(safe));
        assertEq(L2Registry(registryAddr).pendingAdmin(), address(0));
        assertEq(WoCoRegistrar(registrarAddr).owner(), address(safe));
        assertEq(L2Registry(registryAddr).balanceOf(deployer), 0, "the deployer holds a name");
    }

    /// Wiring is the Safe's own transaction. Until it lands the registrar
    /// cannot mint.
    function test_Deploy_TheRegistrarCannotMintUntilTheSafeWiresIt() public {
        (address registryAddr, address registrarAddr) = script.run();
        L2Registry registry = L2Registry(registryAddr);
        assertFalse(registry.registrars(registrarAddr), "the script wired the registrar");

        bytes32 base = registry.baseNode();
        address organiser = makeAddr("organiser");
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        vm.prank(SCRIPT_SPONSOR);
        WoCoRegistrar(registrarAddr).register("venue", organiser);
    }

    /// The printed calldata is exactly what the Safe sends, and it works.
    function test_Deploy_TheSafesWiringCallLetsTheRegistrarMint() public {
        (address registryAddr, address registrarAddr) = script.run();
        _wire(registryAddr, registrarAddr);

        address organiser = makeAddr("organiser");
        vm.prank(SCRIPT_SPONSOR);
        bytes32 node = WoCoRegistrar(registrarAddr).register("venue", organiser);
        assertEq(L2Registry(registryAddr).owner(node), organiser);
    }

    /// The capability #440 existed to protect, end to end on the deployed registry.
    function test_Deploy_AdminTransferIsReachableOnTheDeployedRegistry() public {
        (address registryAddr, address registrarAddr) = script.run();
        _wire(registryAddr, registrarAddr);
        L2Registry registry = L2Registry(registryAddr);

        address organiser = makeAddr("organiser");
        address claimant = makeAddr("claimant");
        vm.prank(SCRIPT_SPONSOR);
        bytes32 node = WoCoRegistrar(registrarAddr).register("venue", organiser);

        vm.prank(address(safe));
        registry.adminTransfer(node, claimant);
        assertEq(registry.owner(node), claimant, "adminTransfer is not reachable on the deployed registry");
    }

    /// The seat's way on: the Safe hands it to a DAO in two steps, and the
    /// registrar goes with it in the same transaction (audit 937 F13).
    function test_Deploy_TheSafeCanHandTheSeatToADao() public {
        (address registryAddr, address registrarAddr) = script.run();
        L2Registry registry = L2Registry(registryAddr);
        address dao = address(new MockSafe());

        vm.prank(address(safe));
        registry.nominateAdmin(dao);
        vm.prank(dao);
        registry.acceptAdmin();
        assertEq(registry.owner(), dao);
        assertEq(WoCoRegistrar(registrarAddr).owner(), dao, "the registrar stayed with the Safe");
    }

    /*//////////////////////////////////////////////////////////////
                    THE ADMIN MUST BE SHAPED LIKE A SAFE
    //////////////////////////////////////////////////////////////*/

    function test_Admin_RefusesTheZeroAddress() public {
        WithAdmin s = new WithAdmin(address(0));
        vm.expectRevert("REGISTRY_ADMIN must not be the zero address");
        s.run();
    }

    function test_Admin_RefusesAnAddressWithNoCode() public {
        WithAdmin s = new WithAdmin(makeAddr("bare-key"));
        vm.expectRevert("REGISTRY_ADMIN has no code - expected the Safe");
        s.run();
    }

    /// The case a plain code check misses: the Safe's own signer is an EOA with
    /// an EIP-7702 delegation, and a delegated account has code — exactly the
    /// 23-byte designator `0xef0100 ‖ delegate`.
    function test_Admin_RefusesAnEip7702DelegatedAccount() public {
        address account = makeAddr("delegated-signer");
        vm.etch(account, abi.encodePacked(hex"ef0100", address(safe)));
        WithAdmin s = new WithAdmin(account);
        vm.expectRevert("REGISTRY_ADMIN is an EIP-7702 delegated EOA - expected the Safe, not a signer account");
        s.run();
    }

    /// The premise of the test above, against the real delegation cheatcode
    /// rather than an etch: a delegated account's code reads as the designator.
    function test_Admin_ADelegatedAccountsCodeIsTheDesignator() public {
        uint256 key = 0x7702;
        address account = vm.addr(key);
        address delegate = address(new AcceptsAnything());
        vm.signAndAttachDelegation(delegate, key);
        (bool ok,) = account.call("");
        assertTrue(ok, "the delegated call failed");
        assertEq(account.code, abi.encodePacked(hex"ef0100", delegate));
    }

    /// It is the designator's prefix that is refused, not a size: 23 bytes of
    /// code that is not a delegation is a contract like any other. (Code of
    /// another length starting with 0xEF cannot exist — EIP-3541 — and the test
    /// VM refuses to create it.)
    function test_Admin_TheDesignatorPrefixIsRefusedNotTheSize() public {
        address twentyThree = makeAddr("twenty-three-bytes");
        vm.etch(twentyThree, abi.encodePacked(hex"600000", address(safe)));
        (address registryAddr,) = new WithAdmin(twentyThree).run();
        assertEq(L2Registry(registryAddr).owner(), twentyThree);
    }

    /*//////////////////////////////////////////////////////////////
                  THE DEPLOYED STATE IS CHECKED, CLAUSE BY CLAUSE
    //////////////////////////////////////////////////////////////*/

    function test_State_RefusesASeatThatIsNotOnTheAdmin() public {
        DeploysTheSeatElsewhere bad = new DeploysTheSeatElsewhere();
        vm.expectRevert("registry admin seat is not on REGISTRY_ADMIN");
        bad.run();
    }

    function test_State_RefusesARegistrarOwnedBySomeoneElse() public {
        DeploysARegistrarOwnedElsewhere bad = new DeploysARegistrarOwnedElsewhere();
        vm.expectRevert("registrar is not owned by REGISTRY_ADMIN");
        bad.run();
    }

    function test_State_RefusesARegistrarForAnotherRegistry() public {
        DeploysARegistrarForAnotherRegistry bad = new DeploysARegistrarForAnotherRegistry();
        vm.expectRevert("registrar mints into a different registry");
        bad.run();
    }

    function test_State_RefusesARegistrarWithoutTheSponsor() public {
        DeploysWithoutTheSponsor bad = new DeploysWithoutTheSponsor();
        vm.expectRevert("SPONSOR_ADDRESS is not an authorised sponsor");
        bad.run();
    }

    function test_State_RefusesARegistrarWithoutTheReservedLabels() public {
        DeploysWithoutReservedLabels bad = new DeploysWithoutReservedLabels();
        vm.expectRevert("a reserved label is not reserved");
        bad.run();
    }

    /// A registry under a mistyped parent mints normally and resolves nothing
    /// once L1 points at it, so the parent is checked by its node, pinned as a
    /// literal rather than recomputed from the same string.
    function test_State_RefusesARegistryForAnotherParent() public {
        DeploysUnderAnotherParent bad = new DeploysUnderAnotherParent();
        vm.expectRevert("registry is not woco.eth - its base node is not namehash(woco.eth)");
        bad.run();
    }

    function test_State_TheParentNodeIsNamehashOfWocoEth() public {
        (address registryAddr,) = script.run();
        assertEq(L2Registry(registryAddr).baseNode(), vm.ensNamehash("woco.eth"));
        assertEq(L2Registry(registryAddr).baseNode(), 0x616c19dee44e200629c0e4918ca0fe2f6e85100ea0b354c4f888e11c07a9006f);
    }

    /*//////////////////////////////////////////////////////////////
                        EACH TRIPWIRE CLAUSE FIRES
    //////////////////////////////////////////////////////////////*/

    /// Clause 1. The literal #440 regression: a registry cloned from an
    /// implementation other than the one reported.
    function test_Tripwire_RejectsACloneOfSomethingElse() public {
        ClonesSomethingElse bad = new ClonesSomethingElse();
        vm.expectRevert("registry is not a clone of the implementation this script deployed");
        bad.run();
    }

    /// Clause 2. NameStone's implementation address, named. The code behind it is
    /// genuinely ours here, so every other clause passes.
    function test_Tripwire_RejectsNameStonesImplementationAddress() public {
        ClonesNameStonesAddress bad = new ClonesNameStonesAddress();
        vm.expectRevert("registry implementation is NameStone's - the factory path is back");
        bad.run();
    }

    /// Clause 3. An implementation at an address of its own, correctly cloned,
    /// that simply is not our source — upstream Durin's shape.
    function test_Tripwire_RejectsAnUpstreamShapedImplementation() public {
        ClonesUpstreamShape bad = new ClonesUpstreamShape();
        vm.expectRevert("registry implementation does not run WoCo's adminTransfer - it is not our bytecode");
        bad.run();
    }

    /// Clause 3, the case a bytecode scan gets wrong: runtime code that CONTAINS
    /// the `adminTransfer` selector, as a constant, with no such function.
    function test_Tripwire_RejectsAnImplementationThatMerelyMentionsTheSelector() public {
        address impostor = address(new MentionsTheSelector());
        assertTrue(
            _codeContainsSelector(impostor, L2Registry.adminTransfer.selector),
            "precondition: the selector bytes are present, so a byte scan would accept this"
        );

        ClonesTheSelectorMentioner bad = new ClonesTheSelectorMentioner();
        vm.expectRevert("registry implementation does not run WoCo's adminTransfer - it is not our bytecode");
        bad.run();
    }

    /// Clause 3 is a REVERT match, not a return match.
    function test_Tripwire_RejectsAnImplementationThatAnswersWithoutReverting() public {
        ClonesTheEchoer bad = new ClonesTheEchoer();
        vm.expectRevert("registry implementation does not run WoCo's adminTransfer - it is not our bytecode");
        bad.run();
    }

    /// Clause 3 matches the ERROR, not merely a revert.
    function test_Tripwire_RejectsAnImplementationThatRevertsWithTheWrongError() public {
        ClonesTheWrongErrors bad = new ClonesTheWrongErrors();
        vm.expectRevert("registry implementation does not run WoCo's adminTransfer - it is not our bytecode");
        bad.run();
    }

    /// Clause 3 covers `release` (#464).
    function test_Tripwire_RejectsAnImplementationWithoutRelease() public {
        ClonesAdminTransferOnly bad = new ClonesAdminTransferOnly();
        vm.expectRevert("registry implementation does not run WoCo's release - it is not our bytecode");
        bad.run();
    }

    /// Clause 3 covers the signature rail.
    function test_Tripwire_RejectsAnImplementationWithoutReleaseWithSignature() public {
        ClonesReleaseOnly bad = new ClonesReleaseOnly();
        vm.expectRevert("registry implementation does not run WoCo's releaseWithSignature - it is not our bytecode");
        bad.run();
    }

    /// Clause 4, the regression that matters for this redeploy: v1's shape —
    /// every v1 probe answers exactly as ours did — without the admin handover.
    /// A deploy from a stale branch lands here.
    function test_Tripwire_RejectsAV1ShapedImplementation() public {
        ClonesV1Shape bad = new ClonesV1Shape();
        vm.expectRevert("registry implementation does not run v2's acceptAdmin - it is not the v2 bytecode");
        bad.run();
    }

    /// Clause 4, the other half: every v2 probe answers, yet `nonces` — the
    /// signed setters' counter — is still there.
    function test_Tripwire_RejectsAnImplementationThatStillAnswersNonces() public {
        ClonesStillAnswersNonces bad = new ClonesStillAnswersNonces();
        vm.expectRevert("registry implementation still answers nonces - it carries v1's signed record setters");
        bad.run();
    }

    /// Clause 5, the regression that matters for THIS redeploy: v2 exactly as
    /// merged — every v1 and v2 probe answers as ours does — without the
    /// signature ceiling. A deploy from the v2 branch lands here.
    function test_Tripwire_RejectsAV2ShapedImplementation() public {
        ClonesV2Shape bad = new ClonesV2Shape();
        vm.expectRevert("registry implementation does not bound release signatures - it is not the v2.1 bytecode");
        bad.run();
    }

    /// Clause 5, the other half: the ceiling is there, `parentTransfer` is not.
    function test_Tripwire_RejectsAnImplementationWithoutParentTransfer() public {
        ClonesCeilingOnly bad = new ClonesCeilingOnly();
        vm.expectRevert("registry implementation does not run v2.1's parentTransfer - it is not the v2.1 bytecode");
        bad.run();
    }

    /// Clause 6, the regression that matters for THIS redeploy: v2.1 as it
    /// stands at 7dc5638 — every earlier probe answers as ours does — still
    /// delegating. A deploy from the v2.1 branch lands here.
    function test_Tripwire_RejectsAV21ShapedImplementation() public {
        ClonesV21Shape bad = new ClonesV21Shape();
        vm.expectRevert("registry implementation still delegates - it is not the v2.2 bytecode");
        bad.run();
    }

    /// Clause 6, the other half: approvals refused, the public batch kept.
    function test_Tripwire_RejectsAnImplementationThatStillAnswersMulticall() public {
        ClonesStillAnswersMulticall bad = new ClonesStillAnswersMulticall();
        vm.expectRevert("registry implementation still answers multicall - it is not the v2.2 bytecode");
        bad.run();
    }

    /// Clause 3's signature probe must reach the body: an implementation that
    /// refuses every expiration as too far — so never gets past its modifier —
    /// is not answering as ours does.
    function test_Tripwire_RejectsAnImplementationThatRefusesEveryExpiration() public {
        ClonesRefusesEveryExpiration bad = new ClonesRefusesEveryExpiration();
        vm.expectRevert("registry implementation does not run WoCo's releaseWithSignature - it is not our bytecode");
        bad.run();
    }

    /// The genuine implementation passes clause 5 on a chain whose clock is
    /// at the far end of what a `uint64` timestamp can say, where "now plus
    /// the ceiling" is still well inside `uint256`.
    function test_Tripwire_PassesAtALateTimestamp() public {
        vm.warp(type(uint64).max);
        (address registryAddr,) = script.run();
        assertEq(L2Registry(registryAddr).owner(), address(safe));
    }

    /// Shape, length: a proxy carrying trailing immutable args.
    function test_Tripwire_RejectsACloneWithTrailingBytes() public {
        DeploysOversizedProxy bad = new DeploysOversizedProxy();
        vm.expectRevert("registry is not an EIP-1167 clone");
        bad.run();
    }

    /// Shape, prefix.
    function test_Tripwire_RejectsAProxyWithTheWrongPrefix() public {
        bytes memory runtime = bytes.concat(
            hex"00112233445566778899", // not 363d3d373d3d3d363d73
            bytes20(makeAddr("impl")),
            hex"5af43d82803e903d91602b57fd5bf3" // ...but a correct suffix
        );
        DeploysEtchedProxy bad = new DeploysEtchedProxy(runtime);
        vm.expectRevert("registry is not an EIP-1167 clone");
        bad.run();
    }

    /// Shape, suffix.
    function test_Tripwire_RejectsAProxyWithTheWrongSuffix() public {
        bytes memory runtime = bytes.concat(
            hex"363d3d373d3d3d363d73", // a correct prefix...
            bytes20(makeAddr("impl")),
            hex"00112233445566778899aabbccddee" // ...and a tail that does something else
        );
        DeploysEtchedProxy bad = new DeploysEtchedProxy(runtime);
        vm.expectRevert("registry is not an EIP-1167 clone");
        bad.run();
    }

    /// Not a proxy at all — the registry deployed directly rather than cloned.
    function test_Tripwire_RejectsANonProxyRegistry() public {
        DeploysDirectly bad = new DeploysDirectly();
        vm.expectRevert("registry is not an EIP-1167 clone");
        bad.run();
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _wire(address registryAddr, address registrarAddr) internal {
        bytes memory wiring = script.wiringCall(registrarAddr);
        vm.prank(address(safe));
        (bool ok,) = registryAddr.call(wiring);
        assertTrue(ok, "the printed wiring call failed");
        assertTrue(L2Registry(registryAddr).registrars(registrarAddr));
    }

    function _embeddedImplementation(address clone) internal view returns (address impl) {
        bytes memory code = clone.code;
        assembly {
            impl := shr(96, mload(add(code, 0x2a)))
        }
    }

    /// @dev The scan the tripwire once used, kept here only to demonstrate what
    ///      it accepts.
    function _codeContainsSelector(address target, bytes4 selector) internal view returns (bool) {
        bytes memory code = target.code;
        if (code.length < 4) return false;
        for (uint256 i; i <= code.length - 4; ++i) {
            if (
                code[i] == selector[0] && code[i + 1] == selector[1] && code[i + 2] == selector[2]
                    && code[i + 3] == selector[3]
            ) return true;
        }
        return false;
    }
}

/*//////////////////////////////////////////////////////////////
                    CONFIGURATION VARIANTS
//////////////////////////////////////////////////////////////*/

/// @dev Overrides only who the admin is; every guard in `run()` is the real one.
contract WithAdmin is DeploySubEnsRegistry {
    address internal immutable configuredAdmin;

    constructor(address admin_) {
        configuredAdmin = admin_;
    }

    function _registryAdmin() internal view override returns (address) {
        return configuredAdmin;
    }
}

/*//////////////////////////////////////////////////////////////
    DEPLOYMENTS THE STATE CHECK MUST REJECT

    Each builds a genuine v2 registry — so the tripwire passes — and gets
    exactly one fact wrong.
//////////////////////////////////////////////////////////////*/

abstract contract BuildsAGenuineRegistry is DeploySubEnsRegistry {
    function _genuineRegistry(string memory parentName, address seat)
        internal
        returns (address registryAddr, address implAddr)
    {
        implAddr = address(new L2Registry());
        registryAddr = Clones.clone(implAddr);
        L2Registry(registryAddr).initialize(parentName, "WoCo Names", "", seat);
    }
}

contract DeploysTheSeatElsewhere is BuildsAGenuineRegistry {
    function _deploy(string memory parentName, address admin, address sponsor, string[] memory labels)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        (registryAddr, implAddr) = _genuineRegistry(parentName, address(new MockSafe()));
        registrarAddr = address(new WoCoRegistrar(registryAddr, sponsor, labels));
    }
}

contract DeploysARegistrarOwnedElsewhere is BuildsAGenuineRegistry {
    function _deploy(string memory parentName, address admin, address sponsor, string[] memory labels)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        (registryAddr, implAddr) = _genuineRegistry(parentName, admin);
        // A registrar answers to its own registry's admin, so one owned by
        // someone else is one bound to a registry whose seat is elsewhere.
        (address elsewhere,) = _genuineRegistry(parentName, address(new MockSafe()));
        registrarAddr = address(new WoCoRegistrar(elsewhere, sponsor, labels));
    }
}

contract DeploysARegistrarForAnotherRegistry is BuildsAGenuineRegistry {
    function _deploy(string memory parentName, address admin, address sponsor, string[] memory labels)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        (registryAddr, implAddr) = _genuineRegistry(parentName, admin);
        (address other,) = _genuineRegistry(parentName, admin);
        registrarAddr = address(new WoCoRegistrar(other, sponsor, labels));
    }
}

contract DeploysWithoutTheSponsor is BuildsAGenuineRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory labels)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        (registryAddr, implAddr) = _genuineRegistry(parentName, admin);
        registrarAddr = address(new WoCoRegistrar(registryAddr, address(0xdead), labels));
    }
}

contract DeploysWithoutReservedLabels is BuildsAGenuineRegistry {
    function _deploy(string memory parentName, address admin, address sponsor, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        (registryAddr, implAddr) = _genuineRegistry(parentName, admin);
        registrarAddr = address(new WoCoRegistrar(registryAddr, sponsor, new string[](0)));
    }
}

contract DeploysUnderAnotherParent is BuildsAGenuineRegistry {
    function _deploy(string memory, address admin, address sponsor, string[] memory labels)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        (registryAddr, implAddr) = _genuineRegistry("wocoo.eth", admin);
        registrarAddr = address(new WoCoRegistrar(registryAddr, sponsor, labels));
    }
}

/*//////////////////////////////////////////////////////////////
        SUBSTITUTE DEPLOYMENTS THE TRIPWIRE MUST REJECT

    The tripwire runs before any registrar is looked at, so these return
    no registrar.
//////////////////////////////////////////////////////////////*/

contract ClonesSomethingElse is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new L2Registry()); // reported...
        registryAddr = Clones.clone(address(new L2Registry())); // ...but not the one cloned
        L2Registry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesNameStonesAddress is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = NAMESTONE_REGISTRY_IMPLEMENTATION;
        // Our real bytecode, at their address: every other clause is satisfied.
        vm.etch(implAddr, address(new L2Registry()).code);
        registryAddr = Clones.clone(implAddr);
        L2Registry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesUpstreamShape is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new UpstreamShapedRegistry());
        registryAddr = Clones.clone(implAddr);
        UpstreamShapedRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesTheSelectorMentioner is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new MentionsTheSelector());
        registryAddr = Clones.clone(implAddr);
        MentionsTheSelector(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesTheEchoer is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new EchoesTheExpectedError());
        registryAddr = Clones.clone(implAddr);
        EchoesTheExpectedError(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesTheWrongErrors is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new WrongErrorRegistry());
        registryAddr = Clones.clone(implAddr);
        WrongErrorRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesAdminTransferOnly is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new AdminTransferOnlyRegistry());
        registryAddr = Clones.clone(implAddr);
        AdminTransferOnlyRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesReleaseOnly is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new ReleaseOnlyRegistry());
        registryAddr = Clones.clone(implAddr);
        ReleaseOnlyRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesV1Shape is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new V1ShapedRegistry());
        registryAddr = Clones.clone(implAddr);
        V1ShapedRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesV2Shape is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new V2ShapedRegistry());
        registryAddr = Clones.clone(implAddr);
        V2ShapedRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesCeilingOnly is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new CeilingOnlyRegistry());
        registryAddr = Clones.clone(implAddr);
        CeilingOnlyRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesRefusesEveryExpiration is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new RefusesEveryExpiration());
        registryAddr = Clones.clone(implAddr);
        RefusesEveryExpiration(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesV21Shape is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new V21ShapedRegistry());
        registryAddr = Clones.clone(implAddr);
        V21ShapedRegistry(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesStillAnswersMulticall is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new StillAnswersMulticall());
        registryAddr = Clones.clone(implAddr);
        StillAnswersMulticall(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract ClonesStillAnswersNonces is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new StillAnswersNonces());
        registryAddr = Clones.clone(implAddr);
        StillAnswersNonces(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

contract DeploysOversizedProxy is DeploySubEnsRegistry {
    function _deploy(string memory, address, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new L2Registry());
        registryAddr = Clones.clone(implAddr);
        // A minimal proxy carrying appended immutable args.
        vm.etch(registryAddr, bytes.concat(registryAddr.code, hex"deadbeef"));
        registrarAddr = address(0);
    }
}

/// @dev Puts arbitrary runtime bytecode where the registry should be, so the
///      prefix and suffix halves of the shape check can be exercised separately.
contract DeploysEtchedProxy is DeploySubEnsRegistry {
    bytes internal runtime;

    constructor(bytes memory runtime_) {
        runtime = runtime_;
    }

    function _deploy(string memory, address, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new L2Registry());
        registryAddr = address(uint160(uint256(keccak256(runtime))));
        vm.etch(registryAddr, runtime);
        registrarAddr = address(0);
    }
}

contract DeploysDirectly is DeploySubEnsRegistry {
    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new L2Registry());
        UpstreamShapedRegistry direct = new UpstreamShapedRegistry();
        direct.initialize(parentName, "WoCo Names", "", admin);
        registryAddr = address(direct);
        registrarAddr = address(0);
    }
}

/// @dev Stands in for upstream Durin: initialises like a registry, has no
///      `adminTransfer`. Deliberately tiny — what matters is the absence.
contract UpstreamShapedRegistry {
    address public admin;

    function initialize(string calldata, string memory, string memory, address admin_) external {
        admin = admin_;
    }
}

/// @dev Upstream's shape plus the four bytes of `adminTransfer`'s selector as a
///      public constant, so they appear verbatim in the runtime bytecode. No
///      such function exists. A right-aligned `uint32`, not a `bytes4`: solc's
///      constant optimiser re-encodes a left-aligned four-byte value without
///      its literal bytes, which is its own argument against scanning for them.
contract MentionsTheSelector is UpstreamShapedRegistry {
    uint32 public constant LOOKS_LIKE_ADMIN_TRANSFER = uint32(L2Registry.adminTransfer.selector);
}

/// @dev Initialises like a registry; every other call SUCCEEDS and returns the
///      `Unauthorized(bytes32)` selector as data. Never reverts.
contract EchoesTheExpectedError is UpstreamShapedRegistry {
    fallback() external {
        bytes4 sel = L2Resolver.Unauthorized.selector;
        assembly {
            mstore(0, sel)
            return(0, 32)
        }
    }
}

/// @dev Has both WoCo entry points, and reverts from each with an error that
///      is not ours.
contract WrongErrorRegistry is UpstreamShapedRegistry {
    error NotOurs(bytes32 node);

    function adminTransfer(bytes32 node, address) external pure {
        revert NotOurs(node);
    }

    function release(bytes32 node) external pure {
        revert NotOurs(node);
    }
}

/// @dev A registry from a branch with #422 but without #464.
contract AdminTransferOnlyRegistry is UpstreamShapedRegistry {
    error Unauthorized(bytes32 node);

    function adminTransfer(bytes32, address) external view {
        if (admin != msg.sender) revert Unauthorized(bytes32(0));
    }
}

/// @dev A registry with #422 and the first half of #464, but no
///      `releaseWithSignature` — the registry deployed on 2026-09-02.
contract ReleaseOnlyRegistry is AdminTransferOnlyRegistry {
    error ReleaseUnregistered(bytes32 node);

    function release(bytes32 node) external pure {
        revert ReleaseUnregistered(node);
    }
}

/// @dev v1's shape: every v1 probe answers exactly as ours did, and there is no
///      `acceptAdmin` — the registry live on Arbitrum One until the v2 cutover.
contract V1ShapedRegistry is ReleaseOnlyRegistry {
    function releaseWithSignature(bytes32 node, uint256, address, bytes calldata) external pure {
        revert ReleaseUnregistered(node);
    }

    function nonces(bytes32) external pure returns (uint256) {
        return 0;
    }
}

/// @dev Every v2 probe answers as ours does — `acceptAdmin` included — and
///      `nonces` still answers too.
contract StillAnswersNonces is V1ShapedRegistry {
    error NotPendingAdmin(address caller);

    function acceptAdmin() external view {
        revert NotPendingAdmin(msg.sender);
    }
}

/// @dev v2 as merged: every v1 probe, `acceptAdmin`, no `nonces` — and a
///      `releaseWithSignature` whose body answers whatever the expiration.
contract V2ShapedRegistry is ReleaseOnlyRegistry {
    error NotPendingAdmin(address caller);

    function releaseWithSignature(bytes32 node, uint256, address, bytes calldata) external pure {
        revert ReleaseUnregistered(node);
    }

    function acceptAdmin() external view {
        revert NotPendingAdmin(msg.sender);
    }
}

/// @dev v2 plus the signature ceiling, without `parentTransfer`.
contract CeilingOnlyRegistry is ReleaseOnlyRegistry {
    error NotPendingAdmin(address caller);
    error ExpirationTooFar();

    function releaseWithSignature(bytes32 node, uint256 expiration, address, bytes calldata) external view {
        if (expiration > block.timestamp + 48 hours) revert ExpirationTooFar();
        revert ReleaseUnregistered(node);
    }

    function acceptAdmin() external view {
        revert NotPendingAdmin(msg.sender);
    }
}

/// @dev Answers every other probe as v2.1 does, but refuses every expiration
///      before its body runs.
contract RefusesEveryExpiration is ReleaseOnlyRegistry {
    error NotPendingAdmin(address caller);
    error ExpirationTooFar();
    error ParentTransferUnregistered(bytes32 node);

    function releaseWithSignature(bytes32, uint256, address, bytes calldata) external pure {
        revert ExpirationTooFar();
    }

    function acceptAdmin() external view {
        revert NotPendingAdmin(msg.sender);
    }

    function parentTransfer(bytes32 node, address) external pure {
        revert ParentTransferUnregistered(node);
    }
}

/// @dev v2.1 as it stands at 7dc5638: every v2.1 probe answers as ours does;
///      `approve` refuses the probe name the OpenZeppelin way (it does not
///      exist), and the inherited `multicall` answers an empty batch.
contract V21ShapedRegistry is ReleaseOnlyRegistry {
    error NotPendingAdmin(address caller);
    error ExpirationTooFar();
    error ParentTransferUnregistered(bytes32 node);
    error ERC721NonexistentToken(uint256 tokenId);

    function releaseWithSignature(bytes32 node, uint256 expiration, address, bytes calldata) external view {
        if (expiration > block.timestamp + 48 hours) revert ExpirationTooFar();
        revert ReleaseUnregistered(node);
    }

    function acceptAdmin() external view {
        revert NotPendingAdmin(msg.sender);
    }

    function parentTransfer(bytes32 node, address) external pure {
        revert ParentTransferUnregistered(node);
    }

    function approve(address, uint256 tokenId) external pure virtual {
        revert ERC721NonexistentToken(tokenId);
    }

    function multicall(bytes[] calldata data) external pure returns (bytes[] memory results) {
        results = new bytes[](data.length);
    }
}

/// @dev v2.1 with approvals refused as v2.2 refuses them — and the public
///      batch still there.
contract StillAnswersMulticall is V21ShapedRegistry {
    error DelegationNotSupported();

    function approve(address, uint256) external pure override {
        revert DelegationNotSupported();
    }
}

/// @dev A contract, because `REGISTRY_ADMIN` must not be a bare key.
contract MockSafe {}

/// @dev A delegate that accepts any call.
contract AcceptsAnything {
    fallback() external payable {}
}

/// @dev The `nonces` probe checks ABSENCE, not failure: an implementation whose
///      `nonces` exists but reverts WITH data still carries v1's counter, and must
///      be refused like one that answers. Its own contract so it takes nothing
///      from the main suite's environment: the admin comes from an override.
contract DeploySubEnsRegistryNoncesProbeTest is ScriptEnvFixture {
    function setUp() public {
        _setSharedScriptEnv();
    }

    function test_Tripwire_RejectsAnImplementationWhoseNoncesRevertsWithData() public {
        ClonesNoncesThatRevert bad = new ClonesNoncesThatRevert(address(new MockSafe()));
        vm.expectRevert("registry implementation still answers nonces - it carries v1's signed record setters");
        bad.run();
    }
}

contract ClonesNoncesThatRevert is DeploySubEnsRegistry {
    address internal immutable configuredAdmin;

    constructor(address admin_) {
        configuredAdmin = admin_;
    }

    function _registryAdmin() internal view override returns (address) {
        return configuredAdmin;
    }

    function _deploy(string memory parentName, address admin, address, string[] memory)
        internal
        override
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        implAddr = address(new NoncesThatRevert());
        registryAddr = Clones.clone(implAddr);
        NoncesThatRevert(registryAddr).initialize(parentName, "WoCo Names", "", admin);
        registrarAddr = address(0);
    }
}

/// @dev Answers every other probe exactly as v2 does; `nonces` exists and
///      reverts with data.
contract NoncesThatRevert is ReleaseOnlyRegistry {
    error NotPendingAdmin(address caller);
    error NoncesAreGone();

    function releaseWithSignature(bytes32 node, uint256, address, bytes calldata) external pure {
        revert ReleaseUnregistered(node);
    }

    function acceptAdmin() external view {
        revert NotPendingAdmin(msg.sender);
    }

    function nonces(bytes32) external pure returns (uint256) {
        revert NoncesAreGone();
    }
}
