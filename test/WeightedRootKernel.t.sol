// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

struct Execution {
    address target;
    uint256 value;
    bytes callData;
}

interface IKernel31 {
    function execute(bytes32 execMode, bytes calldata executionCalldata) external payable;
    function rootValidator() external view returns (bytes21);
    function changeRootValidator(bytes21 rootValidator, address hook, bytes calldata validatorData, bytes calldata hookData)
        external
        payable;
    function uninstallValidation(bytes21 vId, bytes calldata deinitData, bytes calldata hookDeinitData) external payable;
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        returns (uint256);
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory);
}

interface IKernelFactory {
    function createAccount(bytes calldata data, bytes32 salt) external payable returns (address);
}

interface IWeighted {
    function renew(address[] calldata guardians, uint24[] calldata weights, uint24 threshold, uint48 delay) external payable;
    function guardian(address guardian, address kernel) external view returns (uint24 weight, address nextGuardian);
    function weightedStorage(address kernel)
        external
        view
        returns (uint24 totalWeight, uint24 threshold, uint48 delay, address firstGuardian);
}

interface IECDSAValidator {
    function ecdsaValidatorStorage(address account) external view returns (address owner);
}

/// @dev Every passkey a co-owner (WoCo-Event-App #746, Fable consult 9): an account that starts on
///      ZeroDev's ECDSAValidator as its root moves to ZeroDev's WeightedECDSAValidator - one signer per
///      passkey, weight 1, threshold 1 - and any one passkey then signs alone. This pins, against the
///      runtime bytecode deployed on Arbitrum One, the facts the app's design rests on:
///
///        F1  changeRootValidator from ECDSA to weighted, sent the way the app sends it (execute ->
///            self), leaves the account where it is and makes weighted the root.
///        F2  a userOp signed by ANY ONE listed signer validates; an unlisted key does not.
///        F3  renew adds and removes signers, and a removed signer stops validating.
///        F4  ERC-1271 typed data signed by one listed signer is valid (names are signed this way).
///        F5  what renew does with an empty list, or a threshold above the total weight.
///        F6  the OLD ECDSA validation is still installed after the switch: unless the switch also
///            uninstalls it, the first passkey's key keeps an ERC-1271 path that renew cannot remove
///            (not a userOp path: Kernel refuses a non-root validation the selector it was never granted).
///
///      Fixtures: test/fixtures/kernel-v3.1/ (Kernel, factory and ECDSAValidator captured at block
///      504856734 and re-checked equal at 511330785; WeightedECDSAValidator 0xeD89…EEEE captured at
///      511330785). Kernel source for the paths used: zerodevapp/kernel tag v3.1 (03f7f5c).
contract WeightedRootKernelTest is Test {
    address constant ENTRYPOINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant KERNEL_IMPL = 0xBAC849bB641841b44E965fB01A4Bf5F074f84b4D;
    address constant KERNEL_FACTORY = 0xaac5D4240AF87249B3f71BC8E4A2cae074A3E419;
    address constant ECDSA_VALIDATOR = 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57;
    address constant WEIGHTED = 0xeD89244160CfE273800B58b1B534031699dFeEEE;

    bytes4 constant ERC1271_MAGIC = 0x1626ba7e;
    bytes32 constant SINGLE_MODE = bytes32(0);
    bytes32 constant BATCH_MODE = bytes32(uint256(1) << 248);
    bytes1 constant VALIDATION_TYPE_VALIDATOR = 0x01;
    /// IValidator.validateUserOp(PackedUserOperation, bytes32).
    bytes4 constant ECDSA_VALIDATE_USEROP = 0x97003203;
    /// Kernel's InvalidValidator().
    bytes4 constant INVALID_VALIDATOR = 0x682a6e7c;

    uint256 constant PK_A = 0xA11CE; // the passkey the account was made with
    uint256 constant PK_B = 0xB0B; // a passkey added later
    uint256 constant PK_C = 0xC0FFEE; // a key that is not on the account
    address A;
    address B;
    address C;
    IKernel31 kernel;
    uint64 seq;

    function setUp() public {
        vm.chainId(42161);
        _etchFixture(KERNEL_IMPL, "KernelImpl");
        _etchFixture(KERNEL_FACTORY, "KernelFactory");
        _etchFixture(ECDSA_VALIDATOR, "ECDSAValidator");
        _etchFixture(WEIGHTED, "WeightedECDSAValidator");
        A = vm.addr(PK_A);
        B = vm.addr(PK_B);
        C = vm.addr(PK_C);
        // What the app's createKernelAccount({ plugins: { sudo: ecdsaValidator } }) initialises.
        bytes memory init = abi.encodeWithSignature(
            "initialize(bytes21,address,bytes,bytes,bytes[])",
            _vid(ECDSA_VALIDATOR),
            address(0),
            abi.encodePacked(A),
            hex"",
            new bytes[](0)
        );
        kernel = IKernel31(IKernelFactory(KERNEL_FACTORY).createAccount(init, bytes32(0)));
    }

    // ------------------------------------------------------------------ controls (today's account)

    function test_control_ecdsaRoot_ownerSignsAndOthersDoNot() public {
        assertTrue(_userOpValid(PK_A), "owner userOp");
        assertFalse(_userOpValid(PK_B), "stranger userOp");
        assertEq(kernel.isValidSignature(keccak256("x"), _rootSig(PK_A, keccak256("x"))), ERC1271_MAGIC, "owner 1271");
        assertTrue(kernel.isValidSignature(keccak256("x"), _rootSig(PK_B, keccak256("x"))) != ERC1271_MAGIC, "stranger 1271");
    }

    // ------------------------------------------------------------------ F1

    function test_F1_changeRoot_keepsAccount_weightedBecomesRoot() public {
        address before = address(kernel);
        _changeRoot(_pair(A, B), false);
        assertEq(address(kernel), before);
        assertEq(kernel.rootValidator(), _vid(WEIGHTED), "root is weighted");
        (uint24 total, uint24 threshold, uint48 delay,) = IWeighted(WEIGHTED).weightedStorage(address(kernel));
        assertEq(total, 2);
        assertEq(threshold, 1);
        assertEq(delay, 0);
    }

    // ------------------------------------------------------------------ F2

    function test_F2_anyOneListedSignerValidates_strangerDoesNot() public {
        _changeRoot(_pair(A, B), false);
        assertTrue(_userOpValid(PK_A), "first passkey alone");
        assertTrue(_userOpValid(PK_B), "added passkey alone");
        assertFalse(_userOpValid(PK_C), "stranger");
    }

    // ------------------------------------------------------------------ F3

    function test_F3_renewAddsAndRemoves() public {
        _changeRoot(_pair(A, B), false);
        _renew(_three(A, B, C));
        assertTrue(_userOpValid(PK_C), "third added");
        _renew(_one(B));
        (uint24 wA,) = IWeighted(WEIGHTED).guardian(A, address(kernel));
        (uint24 wB,) = IWeighted(WEIGHTED).guardian(B, address(kernel));
        (uint24 wC,) = IWeighted(WEIGHTED).guardian(C, address(kernel));
        assertEq(wA, 0, "A removed");
        assertEq(wB, 1, "B kept");
        assertEq(wC, 0, "C removed");
        assertFalse(_userOpValid(PK_A), "removed first passkey refused");
        assertFalse(_userOpValid(PK_C), "removed third refused");
        assertTrue(_userOpValid(PK_B), "kept passkey still signs");
    }

    // ------------------------------------------------------------------ F4

    function test_F4_erc1271_oneSignature() public {
        _changeRoot(_pair(A, B), false);
        bytes32 h = keccak256("a name pointer");
        assertEq(kernel.isValidSignature(h, _rootSig(PK_A, h)), ERC1271_MAGIC, "first passkey");
        assertEq(kernel.isValidSignature(h, _rootSig(PK_B, h)), ERC1271_MAGIC, "added passkey");
        assertTrue(kernel.isValidSignature(h, _rootSig(PK_C, h)) != ERC1271_MAGIC, "stranger");
        _renew(_one(B));
        assertTrue(kernel.isValidSignature(h, _rootSig(PK_A, h)) != ERC1271_MAGIC, "removed passkey, root path");
    }

    // ------------------------------------------------------------------ F5

    /// The validator does NOT refuse these: each leaves an account no passkey can sign for, for good.
    /// The app must never send them and the sponsorship policy must refuse them (list 1..10, every
    /// weight 1, threshold 1, delay 0).
    function test_F5_renewToEmptyList_isAccepted_andLocksTheAccount() public {
        _changeRoot(_pair(A, B), false);
        _execSelf(WEIGHTED, abi.encodeCall(IWeighted.renew, (new address[](0), new uint24[](0), 1, 0)));
        (uint24 total,,,) = IWeighted(WEIGHTED).weightedStorage(address(kernel));
        assertEq(total, 0, "no signer left");
        assertFalse(_userOpValid(PK_A), "first passkey locked out");
        assertFalse(_userOpValid(PK_B), "added passkey locked out");
    }

    function test_F5_thresholdAboveTotalWeight_isAccepted_andLocksTheAccount() public {
        _changeRoot(_pair(A, B), false);
        uint24[] memory w = new uint24[](1);
        w[0] = 1;
        _execSelf(WEIGHTED, abi.encodeCall(IWeighted.renew, (_one(B), w, 2, 0)));
        assertFalse(_userOpValid(PK_B), "the only signer can no longer reach the threshold");
    }

    // ------------------------------------------------------------------ F6

    /// The switch alone leaves the ECDSA validation installed: the first passkey's key still answers
    /// ERC-1271 through it after renew removed that passkey. This is why the app's switch must
    /// uninstall it in the same batch.
    function test_F6_switchAlone_leavesOldKeyAn1271Path() public {
        _changeRoot(_pair(A, B), false);
        _renew(_one(B));
        bytes32 h = keccak256("a name pointer");
        assertEq(IECDSAValidator(ECDSA_VALIDATOR).ecdsaValidatorStorage(address(kernel)), A, "ECDSA storage kept");
        assertEq(kernel.isValidSignature(h, _ecdsaSecondarySig(PK_A, h)), ERC1271_MAGIC, "old key, ECDSA path");
    }

    /// Not worse than the ERC-1271 path (a sign-off asked whether it was): after the switch alone, a
    /// userOp through the ECDSA nonce key IS routed to the still-installed ECDSA validation, and that
    /// validator accepts the removed first passkey's signature - but Kernel v3.1 then refuses with
    /// InvalidValidator, because a non-root validation was never granted the selector being called.
    /// So the hazard the uninstall closes is the names (ERC-1271) path. `expectCall` is the positive
    /// control for `_ecdsaNonce()`: the refusals in the next test are not a mis-encoded nonce.
    function test_F6_switchAlone_oldKeyUserOp_reachesEcdsa_butKernelRefusesTheSelector() public {
        _changeRoot(_pair(A, B), false);
        _renew(_one(B));
        (PackedUserOperation memory op, bytes32 userOpHash) = _signedOp(_ecdsaNonce() | ++seq, PK_A);
        vm.expectCall(ECDSA_VALIDATOR, abi.encodeWithSelector(ECDSA_VALIDATE_USEROP));
        vm.prank(ENTRYPOINT);
        vm.expectRevert(INVALID_VALIDATOR);
        kernel.validateUserOp(op, userOpHash, 0);
    }

    function test_F6_switchWithUninstall_closesOldKeyPaths() public {
        _changeRoot(_pair(A, B), true);
        assertEq(IECDSAValidator(ECDSA_VALIDATOR).ecdsaValidatorStorage(address(kernel)), address(0), "ECDSA storage cleared");
        _renew(_one(B));
        bytes32 h = keccak256("a name pointer");
        assertFalse(_try1271(h, _ecdsaSecondarySig(PK_A, h)), "old key, ECDSA path");
        assertFalse(_userOpValid(_ecdsaNonce(), PK_A), "old key, ECDSA userOp");
        assertTrue(_userOpValid(PK_B), "kept passkey still signs");
    }

    /// An account that once had backups still carries the recovery route, and its doRecovery makes the
    /// account call ECDSAValidator.onInstall(newOwner) - rewriting that validator's storage. Once the
    /// switch has uninstalled the ECDSA validation, a key written there must open nothing.
    function test_F7_afterUninstall_rewritingEcdsaStorageOpensNothing() public {
        _changeRoot(_pair(A, B), true);
        vm.prank(address(kernel));
        (bool ok,) = ECDSA_VALIDATOR.call(abi.encodeWithSignature("onInstall(bytes)", abi.encodePacked(C)));
        assertTrue(ok, "storage rewrite");
        assertEq(IECDSAValidator(ECDSA_VALIDATOR).ecdsaValidatorStorage(address(kernel)), C);
        bytes32 h = keccak256("a name pointer");
        assertFalse(_try1271(h, _ecdsaSecondarySig(PK_C, h)), "rewritten key, ECDSA 1271 path");
        assertFalse(_userOpValid(_ecdsaNonce(), PK_C), "rewritten key, ECDSA userOp");
        assertFalse(_userOpValid(PK_C), "rewritten key, root userOp");
        assertTrue(_userOpValid(PK_A), "listed passkey still signs");
    }

    // ------------------------------------------------------------------ helpers

    function _etchFixture(address at, string memory name) internal {
        vm.etch(at, vm.parseBytes(vm.readFile(string.concat("test/fixtures/kernel-v3.1/", name, ".runtime.hex"))));
    }

    function _vid(address validator) internal pure returns (bytes21) {
        return bytes21(abi.encodePacked(VALIDATION_TYPE_VALIDATOR, validator));
    }

    /// Signers sorted descending, as the ZeroDev weighted plugin (getEnableData) sorts them.
    function _enable(address[] memory signers) internal pure returns (bytes memory) {
        address[] memory s = _sortDesc(signers);
        uint24[] memory w = new uint24[](s.length);
        for (uint256 i; i < s.length; i++) w[i] = 1;
        return abi.encode(s, w, uint24(1), uint48(0));
    }

    /// What the app sends for the first add: execute -> self -> changeRootValidator (the SDK's
    /// changeSudoValidator for v3.1), optionally batched with uninstalling the ECDSA validation.
    function _changeRoot(address[] memory signers, bool uninstallEcdsa) internal {
        bytes memory change =
            abi.encodeCall(IKernel31.changeRootValidator, (_vid(WEIGHTED), address(0), _enable(signers), hex""));
        if (!uninstallEcdsa) {
            _execSelf(address(kernel), change);
            return;
        }
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(address(kernel), 0, change);
        calls[1] = Execution(
            address(kernel), 0, abi.encodeCall(IKernel31.uninstallValidation, (_vid(ECDSA_VALIDATOR), hex"", hex""))
        );
        vm.prank(ENTRYPOINT);
        kernel.execute(BATCH_MODE, abi.encode(calls));
    }

    function _renew(address[] memory signers) internal {
        address[] memory s = _sortDesc(signers);
        uint24[] memory w = new uint24[](s.length);
        for (uint256 i; i < s.length; i++) w[i] = 1;
        _execSelf(WEIGHTED, abi.encodeCall(IWeighted.renew, (s, w, 1, 0)));
    }

    function _execSelf(address target, bytes memory data) internal {
        vm.prank(ENTRYPOINT);
        kernel.execute(SINGLE_MODE, abi.encodePacked(target, uint256(0), data));
    }

    /// One signature, as the weighted plugin's signUserOperation produces it for a single local signer:
    /// EIP-191 over the userOpHash.
    function _userOpValid(uint256 pk) internal returns (bool) {
        return _userOpValid(0, pk);
    }

    /// `key` is the nonce's top 192 bits (0 = root validator); each call takes the next sequence
    /// number, as the EntryPoint gives one per included userOp.
    function _userOpValid(uint256 key, uint256 pk) internal returns (bool) {
        (PackedUserOperation memory op, bytes32 userOpHash) = _signedOp(key | ++seq, pk);
        vm.prank(ENTRYPOINT);
        try kernel.validateUserOp(op, userOpHash, 0) returns (uint256 vd) {
            return uint160(vd) == 0;
        } catch {
            return false;
        }
    }

    /// A userOp calling `execute`, signed by one key as the weighted plugin signs for one local
    /// signer (EIP-191 over the userOpHash) - which is also how the ECDSA validator checks it.
    function _signedOp(uint256 nonce, uint256 pk) internal view returns (PackedUserOperation memory op, bytes32 userOpHash) {
        op.sender = address(kernel);
        op.nonce = nonce;
        op.callData = abi.encodeCall(IKernel31.execute, (SINGLE_MODE, abi.encodePacked(address(0xdead), uint256(0), hex"")));
        userOpHash = keccak256(abi.encode("op", nonce, pk));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(pk, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)));
        op.signature = abi.encodePacked(r, s, v);
    }

    function _ecdsaNonce() internal pure returns (uint256) {
        // mode DEFAULT | type VALIDATOR | ECDSA validator | key 0, in the top 192 bits; sequence 0.
        bytes24 key = bytes24(abi.encodePacked(bytes1(0x00), VALIDATION_TYPE_VALIDATOR, ECDSA_VALIDATOR, uint16(0)));
        return uint256(uint192(key)) << 64;
    }

    /// Kernel v3.1's ERC-1271: the hash is wrapped in the account's own EIP-712 domain
    /// (Kernel(bytes32 hash)), then the validator checks the signature over the wrapped digest.
    function _wrapped(bytes32 h) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = kernel.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), h))));
    }

    function _rawSig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Root validator: one leading 0x00 byte, as the SDK's root identifier.
    function _rootSig(uint256 pk, bytes32 h) internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(0x00), _rawSig(pk, _wrapped(h)));
    }

    /// A named secondary validator: 0x01 || validator || signature.
    function _ecdsaSecondarySig(uint256 pk, bytes32 h) internal view returns (bytes memory) {
        return abi.encodePacked(VALIDATION_TYPE_VALIDATOR, ECDSA_VALIDATOR, _rawSig(pk, _wrapped(h)));
    }

    function _try1271(bytes32 h, bytes memory sig) internal view returns (bool) {
        try kernel.isValidSignature(h, sig) returns (bytes4 r) {
            return r == ERC1271_MAGIC;
        } catch {
            return false;
        }
    }

    function _sortDesc(address[] memory a) internal pure returns (address[] memory s) {
        s = new address[](a.length);
        for (uint256 i; i < a.length; i++) s[i] = a[i];
        for (uint256 i; i < s.length; i++) {
            for (uint256 j = i + 1; j < s.length; j++) {
                if (s[j] > s[i]) (s[i], s[j]) = (s[j], s[i]);
            }
        }
    }

    function _one(address a) internal pure returns (address[] memory r) {
        r = new address[](1);
        r[0] = a;
    }

    function _pair(address a, address b) internal pure returns (address[] memory r) {
        r = new address[](2);
        r[0] = a;
        r[1] = b;
    }

    function _three(address a, address b, address c) internal pure returns (address[] memory r) {
        r = new address[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }
}
