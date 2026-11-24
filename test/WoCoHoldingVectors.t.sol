// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

/// @notice The ticket-receipt formats, rebuilt in Solidity and pinned to the SAME golden
///         values the app's encoder is pinned to (WoCo-Event-App
///         `packages/shared/test/holding/vectors.ts`). Nothing on chain verifies a receipt
///         yet: this test exists so the off-chain encoder and a future on-chain verifier
///         (the v3 ledger's receipt fingerprint, a holding registry) can never disagree.
///         Change a golden value only together with that file - every receipt already
///         issued depends on it.
contract WoCoHoldingVectorsTest is Test {
    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant DOMAIN_TYPEHASH_NO_CHAIN = keccak256("EIP712Domain(string name,string version)");

    bytes32 constant TICKET_HOLDING_TYPEHASH =
        keccak256("TicketHolding(bytes32 eventId,uint256 slot,address holder,address answerKey,bytes32 nkCommit)");
    bytes32 constant HOLDING_PRESENTATION_TYPEHASH = keccak256(
        "HoldingPresentation(bytes32 receipt,address audience,bytes32 context,uint64 issuedAt,uint64 expiresAt)"
    );
    bytes32 constant VOID_LIST_TYPEHASH =
        keccak256("VoidList(bytes32 eventId,bytes32 entriesHash,uint64 seq,uint64 issuedAt,uint64 validUntil)");
    bytes32 constant ERASE_PICKUP_TYPEHASH = keccak256("ErasePickup(bytes32 pickupId,uint64 issuedAt)");

    // Inputs (vectors.ts).
    uint256 constant CHAIN_ID = 42161;
    address constant LEDGER = 0x5cD8394EF7A4E50403fF72d6aDDd4582332A6050; // WoCoTicketLedger v2, Arbitrum One
    bytes32 constant EVENT_ID = 0xabababababababababababababababababababababababababababababababab;
    uint256 constant SLOT = 6;
    uint256 constant BURNER_KEY = 0x1111111111111111111111111111111111111111111111111111111111111111;
    address constant AUDIENCE = 0x2222222222222222222222222222222222222222;
    bytes32 constant CONTEXT = 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd;
    uint64 constant T0 = 1_800_000_000;

    address constant HOLDER_0 = 0x8bc7C1C1e49b82b62b4A4fdfEbF11141d988a49f;
    address constant HOLDER_1 = 0x358E9f2AE14bD9116F895589F8CE6D39AEDDDE9e;
    address constant HOLDER_2 = 0xE5f4795398B2f668F884f3250d98148883A6B99e;
    address constant ANSWER_0 = 0xBeE5391E94B4a06C5884999c12B2827271156FC8;
    address constant ANSWER_1 = 0x7E312DD51dBdB6E0af64DE9f9a711b9159bFC853;
    address constant ANSWER_2 = 0x5a64CB1cF92ddc17CAb54f9A63348d083616718d;
    bytes32 constant NK = 0x002743f4d210fe2b727de32606120b28fb3d7d000d7e4337454789382923eda2;
    bytes32 constant PICKUP_ID = 0x51e3ae07b949f7ebd89b1729397646d05bb1ad29d1daaa5ac43889c3b375b9bf;

    // Goldens (vectors.ts).
    bytes32 constant NK_COMMIT = 0x35c00f5290574ca0e06482cc1203398631ed488c01fad28832a4c2e3aa4e7f7b;
    bytes32 constant RECEIPT_DIGEST = 0xe811a5e21454fdf8ed2d17a0cbaf211a33568a540384eea60045d17030316a2d;
    bytes constant RECEIPT_SIG =
        hex"703ec3cea4493403500be2820d7ad40014b58c55e33b373c259106a89e441d2026b23a2d78b2609cc1fb59b3a448fff03716ba97374292c64d58ea9a6be1a7201b";
    bytes32 constant PRESENTATION_DIGEST = 0xf7bb1d7ce9c4a142325affb93a93fa5b3853115a5a798e6514eb3c29f63aca0b;
    bytes32 constant LEAF_0 = 0x12f8ea62ec73964994c7caf95e08a568a313f33b5c1e2873d30111278ad2c0cb;
    bytes32 constant LEAF_1 = 0x2659457c836aae627105c4824e5780adfdf64e64c903c8eaf7b40de2e172d0a6;
    bytes32 constant LEAF_2 = 0xd0f958395df68e664c701891e5cd5edf9c1fa70643e816bb1604d446c296178e;
    bytes32 constant ROOT = 0xfe3e6ca753855a9e5e902f219822952888f4e25deaaff98d0bbd01cf033e5a94;
    bytes32 constant VOID_TAG = 0x21b1fd5a6f1bf6ddd2953a21d774a9671b8173e8690277fc017e194a228706e9;
    bytes32 constant ENTRIES_HASH = 0x6925e1ecbbad7c1fb39b4289563976ff887e674e0d23df5a86624163975bd79f;
    bytes32 constant VOID_LIST_DIGEST = 0xda70ea4f532cd5297d2a8aa7729f37ff10092260dae1042e3b725d4eb1ee3712;
    bytes32 constant ERASE_DIGEST = 0x9eb284a31e1e97929cccb55d53dd65ee3876221bcaebba3d7d8913f5a4e74cf0;

    function _domain(string memory name, string memory version) private pure returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), CHAIN_ID, LEDGER)
        );
    }

    function _typed(bytes32 domainSeparator, bytes32 structHash) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _receiptDigest() private pure returns (bytes32) {
        return _typed(
            _domain("WoCo Ticket Holding", "1"),
            keccak256(abi.encode(TICKET_HOLDING_TYPEHASH, EVENT_ID, SLOT, HOLDER_0, ANSWER_0, NK_COMMIT))
        );
    }

    function test_nkCommit() public pure {
        assertEq(keccak256(abi.encode(keccak256("woco/holding/v1/nk-commit"), NK)), NK_COMMIT);
    }

    function test_receiptDigest_andItsSigner() public pure {
        bytes32 digest = _receiptDigest();
        assertEq(digest, RECEIPT_DIGEST);
        (bytes32 r, bytes32 s, uint8 v) = _split(RECEIPT_SIG);
        assertEq(ecrecover(digest, v, r, s), vm.addr(BURNER_KEY));
    }

    function test_presentationDigest() public pure {
        bytes32 structHash = keccak256(
            abi.encode(HOLDING_PRESENTATION_TYPEHASH, RECEIPT_DIGEST, AUDIENCE, CONTEXT, T0, T0 + 86_400)
        );
        assertEq(_typed(_domain("WoCo Ticket Holding", "1"), structHash), PRESENTATION_DIGEST);
    }

    function test_leavesAndRoot() public pure {
        bytes32 tag = keccak256("woco/holding/v1/leaf");
        assertEq(keccak256(abi.encode(tag, HOLDER_0, ANSWER_0, NK_COMMIT)), LEAF_0);
        assertEq(keccak256(abi.encode(tag, HOLDER_1, ANSWER_1, NK_COMMIT)), LEAF_1);
        assertEq(keccak256(abi.encode(tag, HOLDER_2, ANSWER_2, NK_COMMIT)), LEAF_2);
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = LEAF_0;
        leaves[1] = LEAF_1;
        leaves[2] = LEAF_2;
        assertEq(keccak256(abi.encodePacked(leaves)), ROOT);
    }

    function test_voidTagAndList() public pure {
        assertEq(keccak256(abi.encode(keccak256("woco/holding/v1/void-tag"), RECEIPT_DIGEST)), VOID_TAG);
        bytes32 structHash = keccak256(abi.encode(VOID_LIST_TYPEHASH, EVENT_ID, ENTRIES_HASH, uint64(3), T0, T0 + 21_600));
        assertEq(_typed(_domain("WoCo Void List", "1"), structHash), VOID_LIST_DIGEST);
    }

    function test_eraseDigest() public pure {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH_NO_CHAIN, keccak256("WoCo Holding Pickup"), keccak256("1"))
        );
        assertEq(_typed(domainSeparator, keccak256(abi.encode(ERASE_PICKUP_TYPEHASH, PICKUP_ID, T0))), ERASE_DIGEST);
    }

    function test_receiptIsNotTheLedgerTransferDigest() public pure {
        // The ledger's own domain and TransferSlot type: a receipt can never be submitted as a transfer.
        bytes32 transferStruct = keccak256(
            abi.encode(
                keccak256(
                    "TransferSlot(bytes32 eventId,uint256 slot,address from,address to,uint256 nonce,uint256 deadline)"
                ),
                EVENT_ID,
                SLOT,
                vm.addr(BURNER_KEY),
                HOLDER_0,
                uint256(0),
                uint256(T0)
            )
        );
        assertTrue(_typed(_domain("WoCoTicketLedger", "2"), transferStruct) != RECEIPT_DIGEST);
    }

    function _split(bytes memory sig) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
