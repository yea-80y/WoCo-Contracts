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

    function test_Run_AcceptsUnlimited() public {
        WoCoTicketLedger ledger = _script(owner, sponsor, type(uint32).max).run();
        (uint32 perHour, , ) = ledger.sponsorMintAllowance(sponsor);
        assertEq(perHour, ledger.UNLIMITED_MINTS());
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

    function test_ArbitrumOne_RefusesAnOwnerWithoutCode() public {
        vm.chainId(42161);
        TestableDeployTicketLedger s = _script(owner, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must be a Safe deployed on Arbitrum One"));
        s.run();
    }

    function test_ArbitrumOne_RefusesTheSponsorAsOwner() public {
        vm.chainId(42161);
        vm.etch(sponsor, hex"00");
        TestableDeployTicketLedger s = _script(sponsor, sponsor, 1_000);
        vm.expectRevert(bytes("INITIAL_OWNER must not be the sponsor"));
        s.run();
    }

    function test_ArbitrumOne_AcceptsAContractOwner() public {
        vm.chainId(42161);
        vm.etch(owner, hex"00");
        WoCoTicketLedger ledger = _script(owner, sponsor, 1_000).run();
        assertEq(ledger.owner(), owner);
    }

    /// The code check is Arbitrum One only: testnet rehearsals may use an EOA.
    function test_OtherChains_AllowAnEoaOwner() public {
        WoCoTicketLedger ledger = _script(owner, sponsor, 1_000).run();
        assertEq(owner.code.length, 0);
        assertEq(ledger.owner(), owner);
    }
}

contract TestableDeployTicketLedger is DeployWoCoTicketLedger {
    Config internal cfg;

    constructor(uint256 deployerPk_, address owner_, address sponsor_, uint256 perHour_) {
        cfg.deployerPk = deployerPk_;
        cfg.owner = owner_;
        cfg.sponsor = sponsor_;
        cfg.perHour = perHour_;
        cfg.writeDeploymentRecord = false;
    }

    function _config() internal view override returns (Config memory) {
        return cfg;
    }
}
