// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";

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

interface IEntryPoint07 {
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);
    function getNonce(address sender, uint192 key) external view returns (uint256);
}

interface IKernel31Upgrade {
    function rootValidator() external view returns (bytes21);
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory);
}

interface IWeightedUpgrade {
    function guardian(address guardian, address kernel) external view returns (uint24 weight, address nextGuardian);
    function weightedStorage(address kernel)
        external
        view
        returns (uint24 totalWeight, uint24 threshold, uint48 delay, address firstGuardian);
}

interface IECDSAValidatorUpgrade {
    function ecdsaValidatorStorage(address account) external view returns (address owner);
}

/// @dev An email account upgraded to a passkey in place (WoCo-Event-App #746, "upgrade this account to a
///      passkey"). An email account's Kernel is usually still counterfactual, so the ONE op that upgrades it
///      also deploys it: initCode for the ECDSA account the email key owns, then the co-owner switch with a
///      list of ONE key - the new passkey - and the email key's ECDSA validation uninstalled.
///      WeightedRootKernel.t.sol pins the switch on an account that already exists, with the old key kept on
///      the list; this runs the app's exact bytes through the real EntryPoint v0.7 on an Arbitrum One fork:
///
///        U1  deploy + switch in one op lands: the account exists at its counterfactual address, its root is
///            the weighted validator holding the passkey alone, and the ECDSA storage is cleared.
///        U2  the passkey signs a later op alone; the email key does not, on the root nonce or the ECDSA one.
///        U3  ERC-1271: the passkey's signature is valid, the email key's is not on either path.
///
///      The op bytes are the ZeroDev SDK's (`createKernelAccount(...).getFactoryArgs()` and
///      `encodeCalls(coOwnerSwitchCalls(..., [X]))` from apps/web/src/lib/auth/co-owner-calls.ts), generated
///      for the two fixed keys below at Arbitrum One block 512668495. Needs ARB_ONE_RPC_URL (skipped without);
///      fork near the tip - the public endpoint is not an archive node.
contract WeightedRootUpgradeForkTest is Test {
    IEntryPoint07 constant ENTRYPOINT = IEntryPoint07(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
    address constant ECDSA_VALIDATOR = 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57;
    address constant WEIGHTED = 0xeD89244160CfE273800B58b1B534031699dFeEEE;
    /// The SDK's factory for v3.1: the meta factory, calling deployWithFactory(KernelFactory, ...).
    address constant META_FACTORY = 0xd703aaE79538628d27099B8c4f621bE4CCd142d5;

    uint256 constant PK_EMAIL = 0xE3A11; // the email login's key: the account's ECDSA owner
    uint256 constant PK_PASSKEY = 0x9A55; // the new passkey's key
    address constant EMAIL = 0xA5055321C0190A7F28C073d20abe50423f2E8B6e;
    address constant PASSKEY = 0xEE11c1A45315385d6DeAd4A0ad8C843891D6dDc9;
    address constant ACCOUNT = 0x472054E06723aff11a27e04bE65C1c66e8Ff08dC;

    bytes constant FACTORY_DATA =
        hex"c5265d5d000000000000000000000000aac5d4240af87249b3f71bc8e4a2cae074a3e4190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001243c3b752b01845ADb2C711129d4f3966735eD98a9F09fC4cE570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000014A5055321C0190A7F28C073d20abe50423f2E8B6e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes constant SWITCH_CALLDATA =
        hex"e9ae5c5301000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000472054e06723aff11a27e04be65c1c66e8ff08dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c452141cd901ed89244160cfe273800b58b1b534031699dfeeee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000ee11c1a45315385d6dead4a0ad8c843891d6ddc900000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000472054e06723aff11a27e04be65c1c66e8ff08dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a4e6f3d50a01845adb2c711129d4f3966735ed98a9f09fc4ce570000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    bytes32 constant SINGLE_MODE = bytes32(0);
    bytes1 constant VALIDATION_TYPE_VALIDATOR = 0x01;
    bytes4 constant ERC1271_MAGIC = 0x1626ba7e;
    bytes32 constant USEROP_EVENT =
        keccak256("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
    address payable constant BUNDLER = payable(address(0xB0D1E5));

    function setUp() public {
        string memory rpc = vm.envOr("ARB_ONE_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        uint256 forkBlock = vm.envOr("ARB_ONE_FORK_BLOCK", uint256(0));
        if (forkBlock == 0) vm.createSelectFork(rpc);
        else vm.createSelectFork(rpc, forkBlock);
        assertEq(vm.addr(PK_EMAIL), EMAIL, "email key");
        assertEq(vm.addr(PK_PASSKEY), PASSKEY, "passkey key");
        assertEq(ACCOUNT.code.length, 0, "the account starts counterfactual");
        vm.deal(ACCOUNT, 1 ether); // prefund: no paymaster on the fork
    }

    // ------------------------------------------------------------------ control

    /// The same account deployed WITHOUT the switch: the email key signs ops and ERC-1271, so the
    /// refusals below are the switch's doing, not a mis-built op or signature.
    function test_control_withoutTheSwitch_emailKeySigns() public {
        PackedUserOperation memory op;
        op.sender = ACCOUNT;
        op.nonce = ENTRYPOINT.getNonce(ACCOUNT, 0);
        op.initCode = abi.encodePacked(META_FACTORY, FACTORY_DATA);
        op.callData = abi.encodeWithSignature(
            "execute(bytes32,bytes)", SINGLE_MODE, abi.encodePacked(address(0xdead), uint256(0), hex"")
        );
        op.accountGasLimits = bytes32((uint256(1_500_000) << 128) | 1_000_000);
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32((uint256(0.01 gwei) << 128) | 0.1 gwei);
        op.signature = _sign(PK_EMAIL, ENTRYPOINT.getUserOpHash(op));
        _handle(op);
        assertGt(ACCOUNT.code.length, 0, "deployed");
        assertEq(IECDSAValidatorUpgrade(ECDSA_VALIDATOR).ecdsaValidatorStorage(ACCOUNT), EMAIL, "email key owns it");
        assertTrue(_tryOp(0, PK_EMAIL), "email key, root nonce");
        assertFalse(_tryOp(0, PK_PASSKEY), "passkey not yet");
        bytes32 h = keccak256("a name pointer");
        assertTrue(_try1271(h, _validatorSig(ECDSA_VALIDATOR, PK_EMAIL, h)), "email key, ECDSA path");
        assertTrue(_try1271(h, abi.encodePacked(bytes1(0x00), _rawSig(PK_EMAIL, _wrapped(h)))), "email key, root path");
    }

    // ------------------------------------------------------------------ U1

    function test_U1_deployAndSwitchToThePasskeyAlone_inOneOp() public {
        (bool success, uint256 gasUsed) = _upgrade();
        assertTrue(success, "the op's execution succeeded");
        emit log_named_uint("deploy + switch, actualGasUsed", gasUsed);
        assertGt(ACCOUNT.code.length, 0, "deployed at the counterfactual address");
        assertEq(IKernel31Upgrade(ACCOUNT).rootValidator(), _vid(WEIGHTED), "root is weighted");
        (uint24 total, uint24 threshold, uint48 delay, address first) = IWeightedUpgrade(WEIGHTED).weightedStorage(ACCOUNT);
        assertEq(total, 1, "one signer");
        assertEq(threshold, 1);
        assertEq(delay, 0);
        assertEq(first, PASSKEY, "the passkey is the list");
        (uint24 wEmail,) = IWeightedUpgrade(WEIGHTED).guardian(EMAIL, ACCOUNT);
        assertEq(wEmail, 0, "the email key is not on the list");
        assertEq(IECDSAValidatorUpgrade(ECDSA_VALIDATOR).ecdsaValidatorStorage(ACCOUNT), address(0), "ECDSA storage cleared");
    }

    // ------------------------------------------------------------------ U2

    function test_U2_passkeySignsAlone_emailKeyRefused() public {
        (bool success,) = _upgrade();
        assertTrue(success);
        assertFalse(_tryOp(0, PK_EMAIL), "email key, root nonce");
        assertFalse(_tryOp(_ecdsaNonceKey(), PK_EMAIL), "email key, ECDSA nonce");
        assertTrue(_tryOp(0, PK_PASSKEY), "passkey alone");
    }

    // ------------------------------------------------------------------ U3

    function test_U3_erc1271_passkeyValid_emailKeyNot() public {
        (bool success,) = _upgrade();
        assertTrue(success);
        bytes32 h = keccak256("a name pointer");
        assertEq(
            IKernel31Upgrade(ACCOUNT).isValidSignature(h, _validatorSig(WEIGHTED, PK_PASSKEY, h)), ERC1271_MAGIC, "passkey"
        );
        assertFalse(_try1271(h, _validatorSig(WEIGHTED, PK_EMAIL, h)), "email key, weighted path");
        assertFalse(_try1271(h, abi.encodePacked(bytes1(0x00), _rawSig(PK_EMAIL, _wrapped(h)))), "email key, root path");
        assertFalse(_try1271(h, _validatorSig(ECDSA_VALIDATOR, PK_EMAIL, h)), "email key, ECDSA path");
    }

    // ------------------------------------------------------------------ helpers

    /// The upgrade op as the app sends it: initCode + the switch, signed by the email key
    /// (the ECDSA validator checks EIP-191 over the userOpHash, which is what the SDK signs).
    function _upgrade() internal returns (bool success, uint256 gasUsed) {
        PackedUserOperation memory op;
        op.sender = ACCOUNT;
        op.nonce = ENTRYPOINT.getNonce(ACCOUNT, 0);
        op.initCode = abi.encodePacked(META_FACTORY, FACTORY_DATA);
        op.callData = SWITCH_CALLDATA;
        op.accountGasLimits = bytes32((uint256(1_500_000) << 128) | 1_000_000);
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32((uint256(0.01 gwei) << 128) | 0.1 gwei);
        op.signature = _sign(PK_EMAIL, ENTRYPOINT.getUserOpHash(op));
        vm.recordLogs();
        _handle(op);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == address(ENTRYPOINT) && logs[i].topics[0] == USEROP_EVENT) {
                (, bool ok,, uint256 used) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
                return (ok, used);
            }
        }
        revert("no UserOperationEvent");
    }

    /// A harmless later op (execute -> 0xdead, no data) on nonce key `key`, signed by `pk`.
    /// True when the EntryPoint accepted it.
    function _tryOp(uint192 key, uint256 pk) internal returns (bool) {
        PackedUserOperation memory op;
        op.sender = ACCOUNT;
        op.nonce = ENTRYPOINT.getNonce(ACCOUNT, key);
        op.callData = abi.encodeWithSignature(
            "execute(bytes32,bytes)", SINGLE_MODE, abi.encodePacked(address(0xdead), uint256(0), hex"")
        );
        op.accountGasLimits = bytes32((uint256(500_000) << 128) | 200_000);
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32((uint256(0.01 gwei) << 128) | 0.1 gwei);
        op.signature = _sign(pk, ENTRYPOINT.getUserOpHash(op));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(BUNDLER, BUNDLER);
        try ENTRYPOINT.handleOps(ops, BUNDLER) {
            return true;
        } catch {
            return false;
        }
    }

    function _handle(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(BUNDLER, BUNDLER);
        ENTRYPOINT.handleOps(ops, BUNDLER);
    }

    function _sign(uint256 pk, bytes32 userOpHash) internal pure returns (bytes memory) {
        return _rawSig(pk, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)));
    }

    function _ecdsaNonceKey() internal pure returns (uint192) {
        // mode DEFAULT | type VALIDATOR | ECDSA validator | key 0.
        return uint192(bytes24(abi.encodePacked(bytes1(0x00), VALIDATION_TYPE_VALIDATOR, ECDSA_VALIDATOR, uint16(0))));
    }

    function _vid(address validator) internal pure returns (bytes21) {
        return bytes21(abi.encodePacked(VALIDATION_TYPE_VALIDATOR, validator));
    }

    /// Kernel v3.1's ERC-1271 digest: the hash wrapped in the account's own EIP-712 domain.
    function _wrapped(bytes32 h) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying,,) =
            IKernel31Upgrade(ACCOUNT).eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, keccak256(abi.encode(keccak256("Kernel(bytes32 hash)"), h)))
        );
    }

    function _rawSig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// A named validator, as the SDK signs ERC-1271: 0x01 || validator || signature.
    function _validatorSig(address validator, uint256 pk, bytes32 h) internal view returns (bytes memory) {
        return abi.encodePacked(VALIDATION_TYPE_VALIDATOR, validator, _rawSig(pk, _wrapped(h)));
    }

    function _try1271(bytes32 h, bytes memory sig) internal view returns (bool) {
        try IKernel31Upgrade(ACCOUNT).isValidSignature(h, sig) returns (bytes4 r) {
            return r == ERC1271_MAGIC;
        } catch {
            return false;
        }
    }
}
