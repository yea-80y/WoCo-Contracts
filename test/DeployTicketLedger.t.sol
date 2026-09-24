// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ScriptEnvFixture} from "./ScriptEnvFixture.sol";
import {DeployWoCoTicketLedger} from "../script/DeployTicketLedger.s.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Tests for the WoCoTicketLedger deploy script. Each `require` gets a test that
 * makes it the one that trips, and the happy path reads every role back.
 *
 * Per `ScriptEnvFixture`, only the shared keys touch the process environment;
 * every other input goes through `TestableDeployTicketLedger`'s stored `Config`.
 */
contract DeployTicketLedgerTest is ScriptEnvFixture {
    address owner   = address(uint160(0x5AFE));
    address sponsor = SCRIPT_SPONSOR;

    function setUp() public {
        _setSharedScriptEnv();
    }

    function _script(address owner_, address sponsor_, uint256 perHour) internal returns (TestableDeployTicketLedger) {
        return new TestableDeployTicketLedger(SCRIPT_DEPLOYER_PK, owner_, sponsor_, perHour);
    }

    function test_Run_StampsEveryRoleAndReadsThemBack() public {
        WoCoTicketLedger ledger = _script(owner, sponsor, 1_000).run();
        assertEq(ledger.owner(), owner);
        assertEq(ledger.disputeAuthority(), owner);
        assertTrue(ledger.authorisedSponsors(sponsor));
        (uint32 perHour, , ) = ledger.sponsorMintAllowance(sponsor);
        assertEq(perHour, 1_000);
        assertFalse(ledger.authorisedSponsors(vm.addr(SCRIPT_DEPLOYER_PK)), "the deployer holds no role");
    }

    function test_Refuses_UnlimitedForTheFirstSponsor() public {
        TestableDeployTicketLedger s = _script(owner, sponsor, type(uint32).max);
        vm.expectRevert(
            bytes("INITIAL_SPONSOR must have a finite cap: UNLIMITED_MINTS is for a sponsor the chain can check, added later")
        );
        s.run();
    }

    function test_Refuses_ZeroOwner() public {
        TestableDeployTicketLedger s = _script(address(0), sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must not be the zero address"));
        s.run();
    }

    function test_Refuses_ZeroSponsor() public {
        TestableDeployTicketLedger s = _script(owner, address(0), 1_000);
        vm.expectRevert(bytes("INITIAL_SPONSOR must not be the zero address"));
        s.run();
    }

    function test_Refuses_CapAboveUint32() public {
        TestableDeployTicketLedger s = _script(owner, sponsor, uint256(type(uint32).max) + 1);
        vm.expectRevert(bytes("INITIAL_SPONSOR_MINTS_PER_HOUR exceeds uint32"));
        s.run();
    }

    function test_Refuses_ZeroCap() public {
        TestableDeployTicketLedger s = _script(owner, sponsor, 0);
        vm.expectRevert(
            bytes("INITIAL_SPONSOR_MINTS_PER_HOUR must not be 0: that is the stopped state, set it later with setSponsorMintCap")
        );
        s.run();
    }

    /// The live owner Safe's singleton (SafeL2 1.4.1) and address.
    address constant SAFE_L2_141 = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address constant WOCO_SAFE   = 0xD26abFb5fBd37eFBD876e87cB169286eF0f14BA2;

    /// Runtime code of the live owner Safe (SafeProxy 1.4.1), read with
    /// `cast code` on Arbitrum One 2026-09-24; keccak256 = the script's 1.4.1 constant.
    bytes constant PROXY_141 = hex"608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea264697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f31441364736f6c63430007060033";

    /// A chain the script does not know: every production check applies, but
    /// not the Arbitrum One address pin, so each check can be tripped alone.
    uint256 constant OTHER_PROD_CHAIN = 999_999;

    /// A real Safe proxy at `a`: the official proxy code, an official singleton
    /// in slot 0, and MockSafe's getters at that singleton for the delegatecall.
    function _etchSafe(address a) internal {
        vm.etch(a, PROXY_141);
        vm.store(a, bytes32(0), bytes32(uint256(uint160(SAFE_L2_141))));
        vm.etch(SAFE_L2_141, address(new MockSafe()).code);
    }

    function test_Fixture_IsTheOfficialProxyCode() public pure {
        assertEq(keccak256(PROXY_141), 0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c);
    }

    function test_Production_RefusesAnOwnerWithoutCode() public {
        vm.chainId(OTHER_PROD_CHAIN);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must be a Safe deployed on this chain"));
        s.run();
    }

    /// The audit's FakeSafe: answers the getters and even stores an official
    /// singleton in slot 0, but is not the official proxy code (audit 961 M-1, Fable F1/F2).
    function test_Production_RefusesAFakeSafeEvenWithAnOfficialSlot0() public {
        vm.chainId(OTHER_PROD_CHAIN);
        vm.etch(owner, address(new MockSafe()).code);
        vm.store(owner, bytes32(0), bytes32(uint256(uint160(SAFE_L2_141))));
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER is not an official Safe proxy"));
        s.run();
    }

    /// The official proxy code pointing at a singleton that is not an official release.
    function test_Production_RefusesAnOfficialProxyOfAnUnofficialSingleton() public {
        vm.chainId(OTHER_PROD_CHAIN);
        address rogue = address(0xB0605);
        vm.etch(owner, PROXY_141);
        vm.store(owner, bytes32(0), bytes32(uint256(uint160(rogue))));
        vm.etch(rogue, address(new MockSafe()).code);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER is not a proxy of an official Safe singleton"));
        s.run();
    }

    /// An official proxy and singleton that does not answer getThreshold() (audit 960 L-6).
    function test_Production_RefusesASafeThatDoesNotAnswerGetThreshold() public {
        vm.chainId(OTHER_PROD_CHAIN);
        vm.etch(owner, PROXY_141);
        vm.store(owner, bytes32(0), bytes32(uint256(uint160(SAFE_L2_141))));
        vm.etch(SAFE_L2_141, hex"00");
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER does not answer getThreshold() like a Safe"));
        s.run();
    }

    function test_Production_RefusesAMissingOwnerSigner() public {
        vm.chainId(OTHER_PROD_CHAIN);
        _etchSafe(owner);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        s.setOwnerSigner(address(0));
        vm.expectRevert(bytes("INITIAL_OWNER_SIGNER must be set to a signer of the owner Safe"));
        s.run();
    }

    /// A Safe, but not ours: the named signer is not one of its owners (Fable 960 N5).
    function test_Production_RefusesASafeThatDoesNotListTheSigner() public {
        vm.chainId(OTHER_PROD_CHAIN);
        _etchSafe(owner);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        s.setOwnerSigner(address(0xBAD));
        vm.expectRevert(bytes("INITIAL_OWNER_SIGNER is not an owner of INITIAL_OWNER"));
        s.run();
    }

    function test_Production_RefusesTheSponsorAsOwner() public {
        vm.chainId(OTHER_PROD_CHAIN);
        _etchSafe(sponsor);
        TestableDeployTicketLedger s = _script(sponsor, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must not be the sponsor"));
        s.run();
    }

    /// An EIP-7702 deployer has code; it must still not be the owner (audit 960 I-4).
    function test_Production_RefusesTheDeployerAsOwner() public {
        vm.chainId(OTHER_PROD_CHAIN);
        address deployer = vm.addr(SCRIPT_DEPLOYER_PK);
        _etchSafe(deployer);
        TestableDeployTicketLedger s = _script(deployer, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must not be the deployer"));
        s.run();
    }

    /// The gas-only deployer must never double as the hot sponsor (audit 961 L-3).
    function test_Production_RefusesTheDeployerAsSponsor() public {
        vm.chainId(OTHER_PROD_CHAIN);
        _etchSafe(owner);
        TestableDeployTicketLedger s = _script(owner, vm.addr(SCRIPT_DEPLOYER_PK), 1_000);
        vm.expectRevert(bytes("INITIAL_SPONSOR must not be the deployer"));
        s.run();
    }

    function test_Production_AcceptsARealSafeOwner() public {
        vm.chainId(OTHER_PROD_CHAIN);
        _etchSafe(owner);
        WoCoTicketLedger ledger = _script(owner, sponsor, 1_000).run();
        assertEq(ledger.owner(), owner);
        assertEq(ledger.disputeAuthority(), owner);
    }

    /// A genuine Safe listing our signer is still not OUR Safe: on Arbitrum One
    /// the owner is pinned to the address (Fable F3).
    function test_ArbitrumOne_RefusesAnyOtherGenuineSafe() public {
        vm.chainId(42161);
        _etchSafe(owner);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER is not the WoCo owner Safe"));
        s.run();
    }

    function test_ArbitrumOne_AcceptsTheWoCoOwnerSafe() public {
        vm.chainId(42161);
        _etchSafe(WOCO_SAFE);
        WoCoTicketLedger ledger = _script(WOCO_SAFE, sponsor, 1_000).run();
        assertEq(ledger.owner(), WOCO_SAFE);
        assertEq(ledger.disputeAuthority(), WOCO_SAFE);
    }

    /// Testnet rehearsals (here the local chain) may use an EOA owner.
    function test_Testnets_AllowAnEoaOwner() public {
        WoCoTicketLedger ledger = _script(owner, sponsor, 1_000).run();
        assertEq(owner.code.length, 0);
        assertEq(ledger.owner(), owner);
    }
}

/// Answers like a Safe whose one signer is `SIGNER`; no storage, so its code can be etched.
contract MockSafe {
    address internal constant SIGNER = address(uint160(0x5165));

    function getThreshold() external pure returns (uint256) {
        return 1;
    }

    function isOwner(address a) external pure returns (bool) {
        return a == SIGNER;
    }
}

contract TestableDeployTicketLedger is DeployWoCoTicketLedger {
    Config internal cfg;

    constructor(uint256 deployerPk_, address owner_, address sponsor_, uint256 perHour_) {
        cfg.deployerPk = deployerPk_;
        cfg.owner = owner_;
        cfg.ownerSigner = address(uint160(0x5165));
        cfg.sponsor = sponsor_;
        cfg.perHour = perHour_;
        cfg.writeDeploymentRecord = false;
    }

    function setOwnerSigner(address s) external {
        cfg.ownerSigner = s;
    }

    function _config() internal view override returns (Config memory) {
        return cfg;
    }
}
