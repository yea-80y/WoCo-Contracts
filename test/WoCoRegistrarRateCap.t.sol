// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";

/**
 * Tests for the per-recipient mint rate cap in `WoCoRegistrar` — the
 * REPLACEABLE half of WoCo-Event-App #464.
 *
 * The property that matters most is the one that is easy to get backwards:
 * the cap is keyed on the address that RECEIVES the name, not on whoever
 * sends the transaction. Every mint is submitted by a sponsor key on the
 * organiser's behalf, so a sender-keyed cap would throttle the platform, not
 * the account.
 */
contract WoCoRegistrarRateCapTest is Test {
    L2Registry registry;
    WoCoRegistrar registrar;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    uint32 constant DEFAULT_MAX = 30;
    uint64 constant DEFAULT_WINDOW = 30 days;
    uint256 constant T0 = 1_800_000_000;

    bytes constant SWARM_HASH =
        hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    event MintRateCapSet(uint32 maxMintsPerWindow, uint64 mintWindowSeconds);
    event MintWindowReset(address indexed recipient);

    function setUp() public {
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);

        registrar = new WoCoRegistrar(address(registry), sponsor, new string[](0));

        vm.prank(admin);
        registry.addRegistrar(address(registrar));

        vm.warp(T0);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _label(uint256 i) internal pure returns (string memory) {
        return string.concat("name-", vm.toString(i));
    }

    function _mint(string memory label, address to) internal returns (bytes32) {
        return _mintAs(sponsor, label, to);
    }

    function _mintAs(address by, string memory label, address to) internal returns (bytes32) {
        string[] memory keys = new string[](0);
        string[] memory vals = new string[](0);
        vm.prank(by);
        return registrar.register(label, to, SWARM_HASH, keys, vals);
    }

    function _mintN(address to, uint256 n, uint256 seed) internal {
        for (uint256 i; i < n; ++i) {
            _mint(_label(seed + i), to);
        }
    }

    /*//////////////////////////////////////////////////////////////
                              THE CAP BINDS
    //////////////////////////////////////////////////////////////*/

    function test_Defaults() public view {
        assertEq(registrar.maxMintsPerWindow(), DEFAULT_MAX);
        assertEq(registrar.mintWindowSeconds(), DEFAULT_WINDOW);
    }

    function test_Cap_AllowsExactlyTheCapWithinAWindow() public {
        _mintN(alice, DEFAULT_MAX, 0);

        (uint64 end, uint32 count) = registrar.mintWindow(alice);
        assertEq(count, DEFAULT_MAX);
        assertEq(end, uint64(T0) + DEFAULT_WINDOW, "window ends one length after the first mint");

        vm.expectRevert(
            abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, alice, uint64(T0) + DEFAULT_WINDOW)
        );
        _mint("one-too-many", alice);

        // And the refused label was not consumed — it is still free.
        assertTrue(registrar.available("one-too-many"));
    }

    /// Every sponsor draws on the same window per recipient: a second sponsor
    /// key is not a second allowance.
    function test_Cap_EverySponsorSharesTheRecipientsWindow() public {
        address second = makeAddr("second-sponsor");
        vm.prank(admin);
        registrar.addSponsor(second);

        for (uint256 i; i < 15; ++i) {
            _mintAs(sponsor, _label(i), alice);
            _mintAs(second, _label(100 + i), alice);
        }
        (, uint32 count) = registrar.mintWindow(alice);
        assertEq(count, 30, "sponsors are counted separately");

        vm.expectRevert(
            abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, alice, uint64(T0) + DEFAULT_WINDOW)
        );
        _mintAs(second, "thirty-first", alice);
    }

    /*//////////////////////////////////////////////////////////////
                    KEYED ON THE RECIPIENT, NOT THE SENDER
    //////////////////////////////////////////////////////////////*/

    /// The sponsor mints for many organisers from one key. Filling one
    /// organiser's window must leave every other organiser's untouched —
    /// otherwise the cap is on the platform.
    function test_Cap_IsPerRecipientNotPerSender() public {
        _mintN(alice, DEFAULT_MAX, 0);

        // Same sender (the sponsor), different recipient: unaffected.
        _mint("bobs-first", bob);
        (, uint32 bobCount) = registrar.mintWindow(bob);
        assertEq(bobCount, 1);

        // The sponsor itself never accumulates a window.
        (uint64 sponsorEnd, uint32 sponsorCount) = registrar.mintWindow(sponsor);
        assertEq(sponsorEnd, 0);
        assertEq(sponsorCount, 0);
    }

    /*//////////////////////////////////////////////////////////////
                             THE WINDOW ROLLS
    //////////////////////////////////////////////////////////////*/

    function test_Cap_ResetsWhenTheWindowElapses() public {
        _mintN(alice, DEFAULT_MAX, 0);

        vm.warp(T0 + DEFAULT_WINDOW - 1);
        vm.expectRevert(
            abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, alice, uint64(T0) + DEFAULT_WINDOW)
        );
        _mint("still-inside", alice);

        vm.warp(T0 + DEFAULT_WINDOW);
        _mint("fresh-window", alice);

        (uint64 end, uint32 count) = registrar.mintWindow(alice);
        assertEq(end, uint64(T0 + 2 * DEFAULT_WINDOW), "new window not opened at this mint");
        assertEq(count, 1, "count not reset");
    }

    /// A window is opened by the recipient's FIRST mint in it, not at a
    /// global epoch — so an organiser who mints once and comes back in six
    /// weeks starts a fresh window rather than inheriting a stale one.
    function test_Cap_WindowIsOpenedByTheFirstMintInIt() public {
        _mint("first", alice);
        vm.warp(T0 + 45 days);
        _mint("second", alice);

        (uint64 end, uint32 count) = registrar.mintWindow(alice);
        assertEq(end, uint64(T0 + 45 days) + DEFAULT_WINDOW);
        assertEq(count, 1);
    }

    /*//////////////////////////////////////////////////////////////
                              mintAllowance
    //////////////////////////////////////////////////////////////*/

    function test_Allowance_ReportsRemainingAndReset() public {
        (uint32 remaining, uint64 resetsAt) = registrar.mintAllowance(alice);
        assertEq(remaining, DEFAULT_MAX, "fresh recipient has the full cap");
        assertEq(resetsAt, uint64(T0) + DEFAULT_WINDOW);

        _mintN(alice, 12, 0);
        (remaining, resetsAt) = registrar.mintAllowance(alice);
        assertEq(remaining, DEFAULT_MAX - 12);
        assertEq(resetsAt, uint64(T0) + DEFAULT_WINDOW);

        _mintN(alice, DEFAULT_MAX - 12, 100);
        (remaining,) = registrar.mintAllowance(alice);
        assertEq(remaining, 0, "full window should report zero");

        vm.warp(T0 + DEFAULT_WINDOW);
        (remaining, resetsAt) = registrar.mintAllowance(alice);
        assertEq(remaining, DEFAULT_MAX, "elapsed window should report the full cap");
        assertEq(resetsAt, uint64(T0 + DEFAULT_WINDOW) + DEFAULT_WINDOW);
    }

    /// `available()` is about the label; it must not start answering for the
    /// recipient. A capped organiser looking at a free label sees it as free
    /// and learns about their allowance from `mintAllowance`.
    function test_Allowance_DoesNotLeakIntoAvailable() public {
        _mintN(alice, DEFAULT_MAX, 0);
        assertTrue(registrar.available("still-a-free-label"));
    }

    /*//////////////////////////////////////////////////////////////
                                 TUNING
    //////////////////////////////////////////////////////////////*/

    function test_Tune_OwnerCanRetune() public {
        vm.expectEmit(false, false, false, true, address(registrar));
        emit MintRateCapSet(3, 1 days);
        vm.prank(admin);
        registrar.setMintRateCap(3, 1 days);

        _mintN(alice, 3, 0);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, alice, uint64(T0 + 1 days)));
        _mint("fourth", alice);

        vm.warp(T0 + 1 days);
        _mint("fourth", alice);
    }

    /// Lowering the cap below a recipient's current count must not underflow
    /// or grant anything: they are simply over the line until their window
    /// rolls.
    function test_Tune_LoweringBelowCurrentCountJustBlocks() public {
        _mintN(alice, 10, 0);
        vm.prank(admin);
        registrar.setMintRateCap(5, DEFAULT_WINDOW);

        (uint32 remaining,) = registrar.mintAllowance(alice);
        assertEq(remaining, 0);
        vm.expectRevert(
            abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, alice, uint64(T0) + DEFAULT_WINDOW)
        );
        _mint("over-the-new-line", alice);
    }

    function test_Tune_OnlyOwner() public {
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, alice));
        vm.prank(alice);
        registrar.setMintRateCap(1, 1);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, sponsor));
        vm.prank(sponsor);
        registrar.setMintRateCap(1, 1);
    }

    /// Audit 937 F6: an open window keeps the end it was opened with. A shorter
    /// length applies from the next window; a lower cap applies at once.
    function test_Tune_AnOpenWindowKeepsItsEnd() public {
        _mintN(alice, 3, 0);
        vm.warp(T0 + 10 days);
        vm.prank(admin);
        registrar.setMintRateCap(DEFAULT_MAX, 1 days);

        (uint32 remaining, uint64 resetsAt) = registrar.mintAllowance(alice);
        assertEq(resetsAt, uint64(T0) + DEFAULT_WINDOW, "retuning moved the open window's end");
        assertEq(remaining, DEFAULT_MAX - 3);

        // A recipient with no window open sees the new length.
        (, uint64 bobResets) = registrar.mintAllowance(bob);
        assertEq(bobResets, uint64(T0 + 10 days + 1 days));

        // Lengthening does not extend it either.
        vm.prank(admin);
        registrar.setMintRateCap(DEFAULT_MAX, 90 days);
        (, resetsAt) = registrar.mintAllowance(alice);
        assertEq(resetsAt, uint64(T0) + DEFAULT_WINDOW, "lengthening moved the open window's end");
    }

    /*//////////////////////////////////////////////////////////////
                              RESETTING
    //////////////////////////////////////////////////////////////*/

    /// Audit 937 F12: a sponsor chooses the recipient, so it can spend an
    /// allowance on names the recipient did not want. The owner gives it back.
    function test_Reset_TheOwnerGivesOneRecipientItsAllowanceBack() public {
        _mintN(alice, DEFAULT_MAX, 0);
        _mintN(bob, 5, 100);

        vm.expectEmit(true, false, false, true, address(registrar));
        emit MintWindowReset(alice);
        vm.prank(admin);
        registrar.resetMintWindow(alice);

        (uint64 end, uint32 count) = registrar.mintWindow(alice);
        assertEq(end, 0);
        assertEq(count, 0);
        (uint32 remaining, uint64 resetsAt) = registrar.mintAllowance(alice);
        assertEq(remaining, DEFAULT_MAX);
        assertEq(resetsAt, uint64(T0) + DEFAULT_WINDOW);
        _mint("after-reset", alice);

        (, uint32 bobCount) = registrar.mintWindow(bob);
        assertEq(bobCount, 5, "the reset reached another recipient");
    }

    function test_Reset_OnlyOwner() public {
        _mintN(alice, 2, 0);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, sponsor));
        vm.prank(sponsor);
        registrar.resetMintWindow(alice);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, alice));
        vm.prank(alice);
        registrar.resetMintWindow(alice);
        (, uint32 count) = registrar.mintWindow(alice);
        assertEq(count, 2);
    }

    /// Zero is a pause or a no-op dressed as a number. Refused so a fat-fingered
    /// tuning cannot silently disable the cap or all minting.
    function test_Tune_RefusesZero() public {
        vm.startPrank(admin);
        vm.expectRevert(WoCoRegistrar.InvalidMintRateCap.selector);
        registrar.setMintRateCap(0, DEFAULT_WINDOW);
        vm.expectRevert(WoCoRegistrar.InvalidMintRateCap.selector);
        registrar.setMintRateCap(DEFAULT_MAX, 0);
        vm.stopPrank();

        assertEq(registrar.maxMintsPerWindow(), DEFAULT_MAX, "cap changed despite the revert");
        assertEq(registrar.mintWindowSeconds(), DEFAULT_WINDOW);
    }

    /// Audit 925 finding 3. The window arithmetic is checked `uint64`, so v1's
    /// unbounded window let one owner call make every REPEAT mint revert on
    /// overflow — a pause with no name. One second past the bound is refused.
    function test_Tune_RefusesAWindowPastTheBound() public {
        uint64 bound = registrar.MAX_MINT_WINDOW_SECONDS();
        assertEq(bound, 366 days, "the bound is a year");

        vm.expectRevert(WoCoRegistrar.InvalidMintRateCap.selector);
        vm.prank(admin);
        registrar.setMintRateCap(DEFAULT_MAX, bound + 1);

        assertEq(registrar.mintWindowSeconds(), DEFAULT_WINDOW, "window changed despite the revert");
    }

    /// The bound itself is accepted, and minting keeps working under it.
    function test_Tune_AcceptsTheBoundAndRepeatMintsStillWork() public {
        vm.prank(admin);
        registrar.setMintRateCap(DEFAULT_MAX, 366 days);

        _mint("first", alice);
        _mint("second", alice);
        (, uint32 count) = registrar.mintWindow(alice);
        assertEq(count, 2);
    }

    /// Whatever window the owner can set, a repeat mint in it fails only for
    /// the cap, never for arithmetic — at today's clock and at the uint32 edge.
    function testFuzz_Tune_NoAcceptedWindowBreaksRepeatMints(uint64 window, bool late) public {
        window = uint64(bound(window, 1, registrar.MAX_MINT_WINDOW_SECONDS()));
        vm.prank(admin);
        registrar.setMintRateCap(2, window);
        if (late) vm.warp(type(uint32).max);

        _mint("first", alice);
        _mint("second", alice);
        (uint32 remaining,) = registrar.mintAllowance(alice);
        assertEq(remaining, 0);
    }

    /*//////////////////////////////////////////////////////////////
                     INTERACTION WITH release (#464)
    //////////////////////////////////////////////////////////////*/

    /// Releasing does not refund the allowance: a name given back still
    /// counted when it was minted.
    function test_Cap_ReleaseDoesNotRefundTheAllowance() public {
        for (uint256 i; i < DEFAULT_MAX; ++i) {
            bytes32 node = _mint(_label(i), alice);
            vm.prank(alice);
            registry.release(node);
        }

        vm.expectRevert(
            abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, alice, uint64(T0) + DEFAULT_WINDOW)
        );
        _mint("one-more", alice);
    }

    /// Audit 937 F21: taking back a label you released yourself is not a new
    /// name, so it costs nothing — even at the cap, where anyone else could
    /// otherwise take it first. Churning one label is bounded by the relay and
    /// the sponsor's gas instead (owner decision with the Fable consult,
    /// 2026-09-17).
    function test_Cap_RetakingYourOwnReleasedLabelIsFree() public {
        for (uint256 i; i < DEFAULT_MAX + 5; ++i) {
            bytes32 node = _mint("churn", alice);
            vm.prank(alice);
            registry.release(node);
        }
        (, uint32 count) = registrar.mintWindow(alice);
        assertEq(count, 1, "only the first mint of the label counted");

        _mintN(alice, DEFAULT_MAX - 1, 0);
        vm.expectRevert(
            abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, alice, uint64(T0) + DEFAULT_WINDOW)
        );
        _mint("one-more", alice);
        _mint("churn", alice);
    }

    /// Someone else's release is not yours: taking their label counts.
    function test_Cap_TakingSomeoneElsesReleasedLabelCounts() public {
        bytes32 node = _mint("theirs", bob);
        vm.prank(bob);
        registry.release(node);

        _mint("theirs", alice);
        (, uint32 count) = registrar.mintWindow(alice);
        assertEq(count, 1);

        // And after a hand-over, the label's last release names whoever held it
        // then, not whoever minted it first.
        vm.prank(alice);
        registry.transferFrom(alice, bob, uint256(node));
        vm.prank(bob);
        registry.release(node);
        _mint("theirs", alice);
        (, count) = registrar.mintWindow(alice);
        assertEq(count, 2, "alice retook a label bob released as if it were hers");
    }
}
