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

    function _etchSafe(address a) internal {
        vm.etch(a, address(new MockSafe()).code);
    }

    function test_ArbitrumOne_RefusesAnOwnerWithoutCode() public {
        vm.chainId(42161);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must be a Safe deployed on this chain"));
        s.run();
    }

    /// Code is not enough: a contract that is not a Safe is refused (audit 960 L-6).
    function test_ArbitrumOne_RefusesAContractThatIsNotASafe() public {
        vm.chainId(42161);
        vm.etch(owner, hex"00");
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER does not answer getThreshold() like a Safe"));
        s.run();
    }

    function test_ArbitrumOne_RefusesAMissingOwnerSigner() public {
        vm.chainId(42161);
        _etchSafe(owner);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        s.setOwnerSigner(address(0));
        vm.expectRevert(bytes("INITIAL_OWNER_SIGNER must be set to a signer of the owner Safe"));
        s.run();
    }

    /// A Safe, but not ours: the named signer is not one of its owners (Fable N5).
    function test_ArbitrumOne_RefusesASafeThatDoesNotListTheSigner() public {
        vm.chainId(42161);
        _etchSafe(owner);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        s.setOwnerSigner(address(0xBAD));
        vm.expectRevert(bytes("INITIAL_OWNER_SIGNER is not an owner of INITIAL_OWNER"));
        s.run();
    }

    function test_ArbitrumOne_RefusesTheSponsorAsOwner() public {
        vm.chainId(42161);
        _etchSafe(sponsor);
        TestableDeployTicketLedger s = _script(sponsor, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must not be the sponsor"));
        s.run();
    }

    /// An EIP-7702 deployer has code; it must still not be the owner (audit 960 I-4).
    function test_ArbitrumOne_RefusesTheDeployerAsOwner() public {
        vm.chainId(42161);
        address deployer = vm.addr(SCRIPT_DEPLOYER_PK);
        _etchSafe(deployer);
        TestableDeployTicketLedger s = _script(deployer, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must not be the deployer"));
        s.run();
    }

    function test_ArbitrumOne_AcceptsASafeOwner() public {
        vm.chainId(42161);
        _etchSafe(owner);
        WoCoTicketLedger ledger = _script(owner, sponsor, 1_000).run();
        assertEq(ledger.owner(), owner);
    }

    /// A chain the script does not know gets the production checks (audit 960 I-5).
    function test_UnknownChain_GetsTheProductionChecks() public {
        vm.chainId(999_999);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must be a Safe deployed on this chain"));
        s.run();
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
