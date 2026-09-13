// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WoCoGuardianHook} from "../src/recovery/WoCoGuardianHook.sol";

interface IKernel {
    function installModule(uint256 moduleType, address module, bytes calldata initData) external payable;
    function uninstallModule(uint256 moduleType, address module, bytes calldata deInitData) external payable;
    function execute(bytes32 execMode, bytes calldata executionCalldata) external payable;
    function selectorConfig(bytes4 selector) external view returns (address hook, address target, bytes1 callType);
    function rootValidator() external view returns (bytes21);
    function accountId() external view returns (string memory);
    /// @dev Not a Kernel function: reaches Kernel's fallback and the installed route.
    function doRecovery(address validator, bytes calldata data) external payable;
}

interface IKernelFactory {
    function createAccount(bytes calldata data, bytes32 salt) external payable returns (address);
}

interface IECDSAValidator {
    function ecdsaValidatorStorage(address account) external view returns (address owner);
}

/// @dev The hook INSIDE the Kernel it serves (WoCo-Event-App #571).
///
///      WoCoGuardianHook.t.sol calls the hook directly, so it cannot show what Kernel does around
///      it — and one of those things decides whether a removed guardian stays removed. Here the
///      account is a Kernel v3.1 proxy made by the real KernelFactory, running the runtime bytecode
///      deployed on Arbitrum One (implementation, factory, ECDSAValidator and ZeroDev's recovery
///      action, captured at block 504856734 into test/fixtures/kernel-v3.1/), with this repo's hook
///      at its CREATE2 address, driven by the calldata the WoCo app sends. Kernel source for the
///      paths used: zerodevapp/kernel tag v3.1 (03f7f5c) — Kernel.sol installModule / uninstallModule
///      / execute / fallback, core/SelectorManager.sol, core/HookManager.sol, utils/ExecLib.sol.
///
///      ZeroDev's recovery action has no verified source. Recompiling
///          interface IValidator {
///              function onInstall(bytes calldata data) external payable;
///              function onUninstall(bytes calldata data) external payable;
///          }
///          contract RecoveryAction {
///              function doRecovery(address _validator, bytes calldata _data) external {
///                  IValidator(_validator).onUninstall(hex"");
///                  IValidator(_validator).onInstall(_data);
///              }
///          }
///      with solc 0.8.24, optimizer 200 runs, evm paris reproduces all 460 executable bytes of
///      0xe884…DC6E; only the metadata tail differs.
contract WoCoGuardianHookKernelTest is Test {
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant KERNEL_IMPL = 0xBAC849bB641841b44E965fB01A4Bf5F074f84b4D;
    address constant KERNEL_FACTORY = 0xaac5D4240AF87249B3f71BC8E4A2cae074A3E419;
    address constant ECDSA_VALIDATOR = 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57;
    address constant RECOVERY_ACTION = 0xe884C2868CC82c16177eC73a93f7D9E6F3A5DC6E;
    address constant HOOK = 0xF43524473EBC651969BeCc748462ED27ed39d4Db;

    bytes4 constant DO_RECOVERY = 0xac39fd0f;
    /// @dev Kernel's `InvalidSelector()` — what fallback raises for a selector with no route.
    bytes4 constant INVALID_SELECTOR = 0x7352d91c;
    /// @dev ERC-7579 mode: CALLTYPE_BATCH (0x01), EXECTYPE_DEFAULT (0x00), rest zero.
    bytes32 constant BATCH_MODE = bytes32(uint256(1) << 248);

    address constant OWNER = address(0xA11CE);
    address constant G1 = 0x1111111111111111111111111111111111111111;
    address constant G2 = 0x2222222222222222222222222222222222222222;
    address constant G3 = 0x3333333333333333333333333333333333333333;
    /// @dev KernelFactory.getAddress for OWNER, salt 0 — the account every test drives.
    address constant KERNEL = 0x237FEAB983ba5f02BfDC3fFEe7b7625E82A9fe95;

    // The app's bytes, pinned on the app side by apps/web/test/recovery-route.test.ts.
    /// @dev buildRegisterGuardianCallData(G1): what "add a backup" sends on an unprotected account.
    bytes constant APP_INSTALL_G1 = hex"9517e29f0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000e884c2868cc82c16177ec73a93f7d9e6f3a5dc6e00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000138ac39fd0ff43524473ebc651969becc748462ed27ed39d4db000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001ff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000061ff000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000";
    /// @dev @zerodev/sdk encodeCallDataEpV07(buildRemoveRecoveryCalls(KERNEL)): the userOp callData
    ///      "Remove all backups" sends since #571.
    bytes constant APP_REMOVAL = hex"e9ae5c530100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000180000000000000000000000000237feab983ba5f02bfdc3ffee7b7625e82a9fe950000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a4a71763a80000000000000000000000000000000000000000000000000000000000000003000000000000000000000000e884c2868cc82c16177ec73a93f7d9e6f3a5dc6e00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004ac39fd0f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f43524473ebc651969becc748462ed27ed39d4db00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000407ce01ee00000000000000000000000000000000000000000000000000000000";
    /// @dev buildUninstallRecoveryCallData(): the whole removal before #571.
    bytes constant APP_UNINSTALL_BEFORE_571 = hex"a71763a80000000000000000000000000000000000000000000000000000000000000003000000000000000000000000e884c2868cc82c16177ec73a93f7d9e6f3a5dc6e00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004ac39fd0f00000000000000000000000000000000000000000000000000000000";

    struct Execution {
        address target;
        uint256 value;
        bytes callData;
    }

    WoCoGuardianHook hook = WoCoGuardianHook(HOOK);
    address stranger = makeAddr("stranger");
    address newOwner = makeAddr("newOwner");

    function setUp() public {
        vm.chainId(42161);
        _etchFixture(KERNEL_IMPL, "KernelImpl");
        _etchFixture(KERNEL_FACTORY, "KernelFactory");
        _etchFixture(ECDSA_VALIDATOR, "ECDSAValidator");
        _etchFixture(RECOVERY_ACTION, "RecoveryAction");
        vm.etch(HOOK, address(new WoCoGuardianHook()).code);

        // What the app's createKernelAccount({ plugins: { sudo: ecdsaValidator } }) initialises.
        bytes memory init = abi.encodeWithSignature(
            "initialize(bytes21,address,bytes,bytes,bytes[])",
            bytes21(abi.encodePacked(bytes1(0x01), ECDSA_VALIDATOR)),
            address(0),
            abi.encodePacked(OWNER),
            hex"",
            new bytes[](0)
        );
        address created = IKernelFactory(KERNEL_FACTORY).createAccount(init, bytes32(0));
        assertEq(created, KERNEL, "account address moved: APP_REMOVAL embeds it and must be regenerated");
    }

    // ------------------------------------------------------------------ helpers

    function _etchFixture(address at, string memory name) internal {
        vm.etch(at, vm.parseBytes(vm.readFile(string.concat("test/fixtures/kernel-v3.1/", name, ".runtime.hex"))));
    }

    function _arr(address a) internal pure returns (address[] memory r) {
        r = new address[](1);
        r[0] = a;
    }

    function _install(address[] memory guardians, bool withFlag) internal pure returns (bytes memory) {
        bytes memory hookData = abi.encodePacked(withFlag ? bytes1(0xff) : bytes1(0x00), abi.encode(guardians));
        bytes memory initData = abi.encodePacked(DO_RECOVERY, HOOK, abi.encode(bytes(hex"ff"), hookData));
        return abi.encodeCall(IKernel.installModule, (3, RECOVERY_ACTION, initData));
    }

    function _routeUninstall() internal pure returns (bytes memory) {
        return abi.encodeCall(IKernel.uninstallModule, (3, RECOVERY_ACTION, abi.encodePacked(DO_RECOVERY)));
    }

    function _removal(address account) internal pure returns (bytes memory) {
        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution(account, 0, _routeUninstall());
        batch[1] = Execution(HOOK, 0, abi.encodeCall(WoCoGuardianHook.clearGuardians, ()));
        return abi.encodeCall(IKernel.execute, (BATCH_MODE, abi.encode(batch)));
    }

    /// @dev A sudo userOp's execution: EntryPoint calls the account with the userOp callData.
    function _asEntryPoint(bytes memory callData) internal {
        vm.prank(ENTRYPOINT);
        (bool ok, bytes memory ret) = KERNEL.call(callData);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _routeHook() internal view returns (address h) {
        (h,,) = IKernel(KERNEL).selectorConfig(DO_RECOVERY);
    }

    function _ownerOf() internal view returns (address) {
        return IECDSAValidator(ECDSA_VALIDATOR).ecdsaValidatorStorage(KERNEL);
    }

    function _recoverAs(address guardian) internal {
        vm.prank(guardian);
        IKernel(KERNEL).doRecovery(ECDSA_VALIDATOR, abi.encodePacked(newOwner));
        assertEq(_ownerOf(), newOwner);
    }

    function _expectRefused(address caller) internal {
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, KERNEL, caller));
        vm.prank(caller);
        IKernel(KERNEL).doRecovery(ECDSA_VALIDATOR, abi.encodePacked(newOwner));
    }

    // ---------------------------------------------------------------- the setup

    /// @dev The fixtures ARE the code on Arbitrum One (keccak256 of `cast code <address> --block
    ///      504856734`), and the hook at its address IS this repo's source, byte for byte.
    function test_fixtures_areTheDeployedCode() public view {
        assertEq(KERNEL_IMPL.codehash, 0xcc67e791036a8f3df40d3d0f840e7df67f3c69eae9da0a8bffec9e0f91a8db7b);
        assertEq(KERNEL_FACTORY.codehash, 0xeecde6f459d0ecadbd5b76e89de74d8187b52d5c71651fdfc007c45d4f2f3ca0);
        assertEq(ECDSA_VALIDATOR.codehash, 0x2f8b585e669feb673b21af5666d38b5a9ef3c361cf29a48299240fa97c890708);
        assertEq(RECOVERY_ACTION.codehash, 0xfcfe9c1a11298ee296c28eea8f377a8e6e8969cea336d4dcfe3b53e007b7cf89);
        assertEq(HOOK.codehash, 0xc5ca29197860da24a44b65f97ecf47fe3342e0486646315f1afe73b19eeb10bf, "hook source drifted from the deployed singleton");

        assertEq(IKernel(KERNEL).accountId(), "kernel.advanced.v0.3.1");
        assertEq(bytes32(IKernel(KERNEL).rootValidator()), bytes32(bytes21(abi.encodePacked(bytes1(0x01), ECDSA_VALIDATOR))));
        assertEq(_ownerOf(), OWNER);
    }

    /// @dev This suite's builders produce exactly the app's bytes, so every test below drives the
    ///      account the way the app does.
    function test_appCalldata_isWhatThisSuiteBuilds() public pure {
        assertEq(_install(_arr(G1), true), APP_INSTALL_G1);
        assertEq(_removal(KERNEL), APP_REMOVAL);
        assertEq(_routeUninstall(), APP_UNINSTALL_BEFORE_571);
    }

    // ---------------------------------------------------------------- the route

    function test_appInstall_guardianRotatesOwner_othersRefused() public {
        _asEntryPoint(APP_INSTALL_G1);

        (address h, address target, bytes1 callType) = IKernel(KERNEL).selectorConfig(DO_RECOVERY);
        assertEq(h, HOOK);
        assertEq(target, RECOVERY_ACTION);
        assertEq(bytes32(callType), bytes32(bytes1(0xff))); // CALLTYPE_DELEGATECALL
        assertEq(hook.guardiansOf(KERNEL), _arr(G1));

        _expectRefused(stranger);
        assertEq(_ownerOf(), OWNER);
        _recoverAs(G1);
    }

    /// @dev Kernel.sol:454-456 → SelectorManager.sol:63-73: the route goes and the hook is never
    ///      called, so the set stays — unreachable, but still initialised.
    function test_routeUninstall_leavesTheSetBehind() public {
        _asEntryPoint(APP_INSTALL_G1);
        _asEntryPoint(APP_UNINSTALL_BEFORE_571);

        assertEq(_routeHook(), address(0));
        vm.expectRevert(INVALID_SELECTOR);
        vm.prank(G1);
        IKernel(KERNEL).doRecovery(ECDSA_VALIDATOR, abi.encodePacked(newOwner));

        assertEq(hook.guardiansOf(KERNEL), _arr(G1));
        assertTrue(hook.isInitialized(KERNEL));
    }

    /// @dev Before #571 this flag was the only thing between a removed guardian and the account:
    ///      HookManager.sol:37-39 calls onInstall on an initialised hook only for 0xff, which replaces.
    function test_reinstallWithFlag_afterRouteUninstall_replacesTheSet() public {
        _asEntryPoint(APP_INSTALL_G1);
        _asEntryPoint(APP_UNINSTALL_BEFORE_571);
        _asEntryPoint(_install(_arr(G2), true));

        assertEq(hook.guardiansOf(KERNEL), _arr(G2));
        _expectRefused(G1);
        _recoverAs(G2);
    }

    /// @dev ...and without it HookManager.sol:34 sees an initialised hook and skips onInstall: the
    ///      removed guardian recovers the account, and the one just added cannot.
    function test_reinstallWithoutFlag_afterRouteUninstall_revivesTheRemovedGuardian() public {
        _asEntryPoint(APP_INSTALL_G1);
        _asEntryPoint(APP_UNINSTALL_BEFORE_571);
        _asEntryPoint(_install(_arr(G2), false));

        assertEq(hook.guardiansOf(KERNEL), _arr(G1));
        _expectRefused(G2);
        _recoverAs(G1);
    }

    // ------------------------------------------------------------ the removal

    /// @dev #571: the app's removal empties the set in the same batch, so nothing a later install
    ///      sends — flag or not — can bring a removed guardian back.
    function test_appRemoval_leavesNoSet_soNoInstallCanReviveIt() public {
        _asEntryPoint(APP_INSTALL_G1);
        _asEntryPoint(APP_REMOVAL);

        assertEq(_routeHook(), address(0));
        assertEq(hook.guardianCount(KERNEL), 0);
        assertFalse(hook.isInitialized(KERNEL));

        _asEntryPoint(_install(_arr(G2), false));
        assertEq(hook.guardiansOf(KERNEL), _arr(G2));
        _expectRefused(G1);
        _recoverAs(G2);
    }

    /// @dev The app sends the removal even when the route reads absent (a lagging replica can say
    ///      so), so on an account with no route and no set — or sent twice — it must succeed.
    function test_appRemoval_onAnUnprotectedAccount_andTwice_succeeds() public {
        _asEntryPoint(APP_REMOVAL);
        assertEq(_routeHook(), address(0));
        assertEq(hook.guardianCount(KERNEL), 0);

        _asEntryPoint(APP_INSTALL_G1);
        _asEntryPoint(APP_REMOVAL);
        _asEntryPoint(APP_REMOVAL);
        assertEq(_routeHook(), address(0));
        assertEq(hook.guardianCount(KERNEL), 0);
    }

    /// @dev ExecLib.sol:69-77: a default batch reverts as a whole, so a route read back as gone at
    ///      the landing block means the clear ran in that same transaction.
    function test_appRemoval_isAllOrNothing() public {
        _asEntryPoint(APP_INSTALL_G1);

        vm.mockCallRevert(HOOK, abi.encodeCall(WoCoGuardianHook.clearGuardians, ()), "clear refused");
        vm.prank(ENTRYPOINT);
        (bool ok,) = KERNEL.call(APP_REMOVAL);
        assertFalse(ok);
        vm.clearMockedCalls();

        assertEq(_routeHook(), HOOK);
        assertEq(hook.guardiansOf(KERNEL), _arr(G1));
    }

    // ------------------------------------------------------ what a guardian can do

    /// @dev #166.5: the action calls onUninstall("") then onInstall(data) on WHATEVER address the
    ///      guardian names, as the account. Named at the hook, that rewrites the account's set. No
    ///      escalation while a guardian can already rotate the owner, but no design may treat a
    ///      guardian as "rotate only".
    function test_guardianCanRewriteTheSet_throughTheAction() public {
        _asEntryPoint(APP_INSTALL_G1);

        vm.prank(G1);
        IKernel(KERNEL).doRecovery(HOOK, abi.encode(_arr(G3)));

        assertEq(hook.guardiansOf(KERNEL), _arr(G3));
        assertEq(_ownerOf(), OWNER);
        _expectRefused(G1);
    }

    /// @dev Audit Lead 2: on the doRecovery route (module type 3) the hook gates that selector only;
    ///      the account's own execute path never consults it.
    function test_hookGatesOnlyTheRecoveryRoute() public {
        _asEntryPoint(APP_INSTALL_G1);

        vm.expectCall(HOOK, abi.encodeWithSelector(WoCoGuardianHook.preCheck.selector), 0);
        _asEntryPoint(abi.encodeCall(IKernel.execute, (bytes32(0), abi.encodePacked(stranger, uint256(0), bytes("")))));
    }

    /// @dev Audit Low 2 (payable hook functions): Kernel's pre-hook call forwards no value
    ///      (HookManager.sol:18-20), and the action is non-payable under delegatecall, so ETH sent
    ///      with a recovery call is refused outright and never reaches the hook.
    function test_etherSentWithRecovery_isRefused_andNeverReachesTheHook() public {
        _asEntryPoint(APP_INSTALL_G1);
        vm.deal(G1, 1 ether);

        vm.expectRevert(bytes(""));
        vm.prank(G1);
        IKernel(KERNEL).doRecovery{value: 1 ether}(ECDSA_VALIDATOR, abi.encodePacked(newOwner));

        assertEq(HOOK.balance, 0);
        assertEq(G1.balance, 1 ether);
        assertEq(_ownerOf(), OWNER);
    }
}
