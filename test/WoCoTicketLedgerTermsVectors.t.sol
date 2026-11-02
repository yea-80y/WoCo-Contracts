// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/// @notice The app's encoder for organiser-signed actions
///         (WoCo-Event-App `packages/shared/src/ticket/ledger2-terms.ts`) against the
///         ledger's own digest views. The digests below are that file's GOLDEN
///         vectors (`packages/shared/test/ledger2-terms.test.ts`), computed there with
///         the same inputs: if the two ever disagree, every signature the app makes is
///         refused on chain. Every field holds a distinct non-zero value where the
///         type allows, so a swapped pair changes the digest. Change a digest here only
///         together with that test.
contract WoCoTicketLedgerTermsVectorsTest is Test {
    address constant TARGET = 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f;
    bytes32 constant EVENT_ID = 0xabababababababababababababababababababababababababababababababab;
    address constant HOLDER = 0x1111111111111111111111111111111111111111;
    uint256 constant ISSUED_AT = 1_800_000_000;
    uint256 constant DEADLINE = 1_800_003_600;

    // `forge inspect WoCoTicketLedger storageLayout`; each write below is read back
    // through the public getter, so a wrong slot fails loudly rather than vacuously.
    uint256 constant SLOTS_SLOT = 6;
    uint256 constant TERMS_NONCES_SLOT = 13;
    uint256 constant TRANSFER_NONCES_SLOT = 16;
    uint256 constant SEAT_NONCES_SLOT = 17;

    WoCoTicketLedger ledger;

    function setUp() public {
        vm.chainId(42161);
        deployCodeTo(
            "WoCoTicketLedger.sol:WoCoTicketLedger",
            abi.encode(makeAddr("owner"), makeAddr("sponsor"), uint32(100)),
            TARGET
        );
        ledger = WoCoTicketLedger(TARGET);
    }

    function _setTermsNonce(uint256 n) private {
        vm.store(TARGET, keccak256(abi.encode(EVENT_ID, TERMS_NONCES_SLOT)), bytes32(n));
        assertEq(ledger.termsNonces(EVENT_ID), n);
    }

    function _nested(uint256 base, uint256 key) private pure returns (bytes32) {
        return keccak256(abi.encode(key, keccak256(abi.encode(EVENT_ID, base))));
    }

    function test_termsDigestsMatchTheAppEncoder() public {
        _setTermsNonce(3);
        assertEq(
            ledger.setSupplyDigest(EVENT_ID, 120, ISSUED_AT, DEADLINE),
            0x0f9638f8888c531ccdd05ad76d90103effc6e67eb7538872348069ee426db0ef
        );
        _setTermsNonce(4);
        assertEq(
            ledger.extendSalesEndDigest(EVENT_ID, 1_900_000_000, ISSUED_AT, DEADLINE),
            0xaedf4803168296c6410de89a90ea786e996add56bee500ad8d23177d900258d2
        );
        _setTermsNonce(5);
        assertEq(
            ledger.cancelEventDigest(EVENT_ID, ISSUED_AT, DEADLINE),
            0xecac648162449e19ef21ec09cbe54924f118a8a9a414e3d8808623a4eb0583ae
        );
        _setTermsNonce(6);
        assertEq(
            ledger.revokeSignaturesDigest(EVENT_ID, ISSUED_AT, DEADLINE),
            0xfe5d8fc087e40ecdd7abefd3757d70c7a04c15fac3adfcbafd7af58255ffa67f
        );
    }

    function test_seatMoveDigestsMatchTheAppEncoder() public {
        _setTermsNonce(9);
        // Slot 7: owner HOLDER (the low 160 bits of the packed Slot word), transfer nonce 2.
        vm.store(TARGET, _nested(SLOTS_SLOT, 7), bytes32(uint256(uint160(HOLDER))));
        assertEq(ledger.slotOwner(EVENT_ID, 7), HOLDER);
        vm.store(TARGET, _nested(TRANSFER_NONCES_SLOT, 7), bytes32(uint256(2)));
        assertEq(ledger.transferNonces(EVENT_ID, 7), 2);
        // Seat 41 freed once.
        vm.store(TARGET, _nested(SEAT_NONCES_SLOT, 41), bytes32(uint256(1)));
        assertEq(ledger.seatNonces(EVENT_ID, 41), 1);

        assertEq(
            ledger.reseatDigest(EVENT_ID, 7, 41, ISSUED_AT, DEADLINE),
            0x68731ff2799e85023f80c06e3f693ce0c908d96f3cd75c63b554906c2fea5162
        );
        uint256 noSeat = ledger.NO_SEAT();
        assertEq(ledger.seatNonces(EVENT_ID, noSeat), 0);
        assertEq(
            ledger.reseatBearerDigest(EVENT_ID, 7, noSeat, ISSUED_AT, DEADLINE),
            0x2a107cff2feba6daddb8d828eeebc9a9ab48b0faba783c7cced483961022a613
        );
    }
}
