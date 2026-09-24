// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {WoCoTicketLedger, LEDGER_UNLIMITED_MINTS} from "../src/WoCoTicketLedger.sol";

/**
 * Deploy WoCoTicketLedger — the allocation ledger, with no payment handling.
 *
 * Unlike DeployEventV2.s.sol this takes NO payment token, treasury, or fee:
 * the contract holds no funds, so there is nothing to configure. Money
 * settings belong to WoCoPayments when it ships.
 *
 * Usage:
 *   Arbitrum Sepolia (staging):
 *     forge script script/DeployTicketLedger.s.sol \
 *       --rpc-url arb_sepolia --broadcast --verify
 *
 *   Arbitrum One (production — explicit confirmation required):
 *     forge script script/DeployTicketLedger.s.sol \
 *       --rpc-url arbitrum --broadcast --verify
 *
 * Dry-run (no broadcast):
 *     forge script script/DeployTicketLedger.s.sol --rpc-url arb_sepolia
 *
 * Required env (none defaulted — each is a decision that cannot be undone
 * cheaply, and a console warning is not a safeguard because forge script
 * output scrolls past):
 *   DEPLOYER_PRIVATE_KEY — pays gas and nothing else; it holds no role.
 *   INITIAL_OWNER        — the Safe. It becomes owner AND dispute authority
 *                          in the deploy transaction itself, so no handover is
 *                          left to do and the deployer never holds either role.
 *                          Off testnets it must be a Safe native to that chain
 *                          (it must answer getThreshold()) and neither the
 *                          sponsor nor the deployer: an L1 Safe acting via the
 *                          bridge arrives aliased and could never pass
 *                          onlyOwner (audit 959 I-2).
 *   INITIAL_OWNER_SIGNER — off testnets only: one signer of that Safe (for WoCo,
 *                          the owner's own account). The script refuses a Safe
 *                          that does not list it, so "a Safe" is "our Safe".
 *   INITIAL_SPONSOR      — the sponsor wallet that will mint (the server's
 *                          WOCO_SPONSOR_PRIVATE_KEY address). A wrong sponsor is
 *                          a contract the server cannot mint through,
 *                          discovered at first sale.
 *   INITIAL_SPONSOR_MINTS_PER_HOUR — that sponsor's hourly mint cap (audit 959
 *                          M-1). Finite and non-zero: the first sponsor is the
 *                          hot card key. The Safe retunes it later with
 *                          setSponsorMintCap.
 *
 * POST-DEPLOY, IN THIS ORDER (1 before 2 — reversing them opens a window in
 * which every mint reverts NotAuthorised and ticket fulfilment stops):
 *   1. Confirm the sponsor and its cap:
 *        cast call <ledger> "authorisedSponsors(address)(bool)" <sponsor>
 *        cast call <ledger> "sponsorMintAllowance(address)(uint32,uint32,uint64)" <sponsor>
 *   2. Point the server at the new address
 *      (WOCO_EVENT_ADDRESS_LEDGER_{chainId} + WOCO_EVENT_VERSION_{chainId}).
 *   3. Confirm owner() and disputeAuthority() both read the Safe.
 */
contract DeployWoCoTicketLedger is Script {
    struct Config {
        uint256 deployerPk;
        address owner;
        address ownerSigner;
        address sponsor;
        uint256 perHour;
        bool writeDeploymentRecord;
    }

    /// @dev `virtual` ONLY so tests can vary the inputs: `vm.setEnv` writes the
    ///      whole forge process's environment and tests run in parallel, so
    ///      per-test environments race (see test/ScriptEnvFixture.sol). The
    ///      guards stay in `run()` and are never overridden.
    function _config() internal view virtual returns (Config memory c) {
        c.deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        c.owner = vm.envAddress("INITIAL_OWNER");
        c.ownerSigner = vm.envOr("INITIAL_OWNER_SIGNER", address(0));
        c.sponsor = vm.envAddress("INITIAL_SPONSOR");
        c.perHour = vm.envUint("INITIAL_SPONSOR_MINTS_PER_HOUR");
        c.writeDeploymentRecord = vm.envOr("WRITE_DEPLOYMENT_RECORD", true);
    }

    function run() external returns (WoCoTicketLedger ledger) {
        Config memory c = _config();
        address deployer = vm.addr(c.deployerPk);
        require(c.owner != address(0), "INITIAL_OWNER must not be the zero address");
        require(c.sponsor != address(0), "INITIAL_SPONSOR must not be the zero address");
        require(c.perHour <= type(uint32).max, "INITIAL_SPONSOR_MINTS_PER_HOUR exceeds uint32");
        require(c.perHour > 0, "INITIAL_SPONSOR_MINTS_PER_HOUR must not be 0: that is the stopped state, set it later with setSponsorMintCap");
        // The first sponsor is always the hot card key, the one the cap exists
        // to bound (audit 960 L-2). A payments contract that may run unlimited
        // needs this ledger's address, so it is always added later.
        require(c.perHour != LEDGER_UNLIMITED_MINTS, "INITIAL_SPONSOR must have a finite cap: UNLIMITED_MINTS is for a sponsor the chain can check, added later");
        if (!_isTestnet(block.chainid)) {
            require(c.owner.code.length > 0, "INITIAL_OWNER must be a Safe deployed on this chain");
            // Code, or answering Safe getters, proves only "a contract" (audits
            // 960 L-6, 961 M-1): a hand-rolled contract can answer both. A proxy
            // whose singleton (slot 0) is an official Safe release runs the real
            // Safe logic, so its getters and signature checks are genuine.
            require(_isCanonicalSafeProxy(c.owner), "INITIAL_OWNER is not a proxy of an official Safe singleton");
            require(_safeThreshold(c.owner) > 0, "INITIAL_OWNER does not answer getThreshold() like a Safe");
            // A genuine Safe is not yet OUR Safe: it must list a signer we hold.
            require(c.ownerSigner != address(0), "INITIAL_OWNER_SIGNER must be set to a signer of the owner Safe");
            require(_safeIsOwner(c.owner, c.ownerSigner), "INITIAL_OWNER_SIGNER is not an owner of INITIAL_OWNER");
            require(c.owner != c.sponsor, "INITIAL_OWNER must not be the sponsor");
            // An EIP-7702 deployer has code, so the checks above do not rule it out (audit 960 I-4).
            require(c.owner != deployer, "INITIAL_OWNER must not be the deployer");
            // The gas-only deployer key must never double as the hot sponsor (audit 961 L-3).
            require(c.sponsor != deployer, "INITIAL_SPONSOR must not be the deployer");
        }

        console.log("Deploying WoCoTicketLedger...");
        console.log("  Chain ID:            ", block.chainid);
        console.log("  Deployer (gas only): ", deployer);
        console.log("  Owner + dispute auth:", c.owner);
        if (!_isTestnet(block.chainid)) {
            uint256 threshold = _safeThreshold(c.owner);
            console.log("  Owner Safe threshold:", threshold);
            // Not refused: signer policy is the owner's call, and the Safe can be
            // raised to m-of-n at any time without touching this contract.
            if (threshold < 2) console.log("  WARNING: the owner Safe is 1-of-n - every owner power rests on one key");
        }
        console.log("  Initial sponsor:     ", c.sponsor);
        console.log("  Sponsor mints/hour:  ", c.perHour);

        // safe: bounded to uint32 by the require above
        // forge-lint: disable-next-line(unsafe-typecast)
        uint32 perHour = uint32(c.perHour);

        vm.startBroadcast(c.deployerPk);
        ledger = new WoCoTicketLedger(c.owner, c.sponsor, perHour);
        vm.stopBroadcast();

        require(ledger.owner() == c.owner, "owner read-back failed");
        require(ledger.disputeAuthority() == c.owner, "dispute authority read-back failed");
        require(ledger.authorisedSponsors(c.sponsor), "sponsor read-back failed");
        (uint32 capBack,,) = ledger.sponsorMintAllowance(c.sponsor);
        require(capBack == perHour, "cap read-back failed");

        console.log("WoCoTicketLedger deployed to:", address(ledger));

        if (c.writeDeploymentRecord) {
            _writeDeployment(address(ledger), deployer, c.owner, c.sponsor, c.perHour);
        }
    }

    /// @dev Chains where the production checks are skipped: local and public
    ///      testnets, where a rehearsal may use an EOA owner. Every other chain,
    ///      including one this script has never seen, gets them (audit 960 I-5).
    function _isTestnet(uint256 id) internal pure returns (bool) {
        return id == 31337 || id == 421614 || id == 84532 || id == 11155111 || id == 11155420;
    }

    /// @dev A Safe's threshold, or 0 for anything that does not answer
    ///      `getThreshold()` with exactly one word.
    function _safeThreshold(address a) internal view returns (uint256) {
        (bool ok, bytes memory ret) = a.staticcall(abi.encodeWithSignature("getThreshold()"));
        if (!ok || ret.length != 32) return 0;
        return abi.decode(ret, (uint256));
    }

    /// @dev Official Safe singletons (same address on every chain, deterministic
    ///      deployment), each checked on Arbitrum One on 2026-09-24 to hold code
    ///      and report its VERSION. A Safe proxy keeps its singleton in slot 0.
    function _isCanonicalSafeProxy(address a) internal view returns (bool) {
        address singleton = address(uint160(uint256(vm.load(a, bytes32(0)))));
        return singleton == 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762  // SafeL2 1.4.1
            || singleton == 0x41675C099F32341bf84BFc5382aF534df5C7461a  // Safe 1.4.1
            || singleton == 0x3E5c63644E683549055b9Be8653de26E0B4CD36E  // SafeL2 1.3.0
            || singleton == 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552  // Safe 1.3.0
            || singleton == 0xfb1bffC9d739B8D520DaF37dF666da4C687191EA  // SafeL2 1.3.0 (eip155)
            || singleton == 0x69f4D1788e39c87893C980c06EdF4b7f686e2938; // Safe 1.3.0 (eip155)
    }

    /// @dev True only when `isOwner(signer)` answers one word equal to 1.
    function _safeIsOwner(address safe, address signer) internal view returns (bool) {
        (bool ok, bytes memory ret) = safe.staticcall(abi.encodeWithSignature("isOwner(address)", signer));
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }

    function _writeDeployment(
        address contractAddr,
        address deployer,
        address owner,
        address sponsor,
        uint256 perHour
    ) internal {
        vm.createDir("deployments", true);

        string memory obj = "deployment";
        vm.serializeString (obj, "contract",              "WoCoTicketLedger");
        vm.serializeUint   (obj, "chainId",               block.chainid);
        vm.serializeAddress(obj, "deployer",              deployer);
        vm.serializeAddress(obj, "owner",                 owner);
        vm.serializeAddress(obj, "disputeAuthority",      owner);
        vm.serializeAddress(obj, "initialSponsor",        sponsor);
        vm.serializeUint   (obj, "initialSponsorPerHour", perHour);
        vm.serializeString (obj, "note_payments",         "Holds no funds. Money lives in WoCoPayments (not yet built)");
        string memory json = vm.serializeAddress(obj, "address", contractAddr);

        string memory path = string.concat(
            "deployments/",
            vm.toString(block.chainid),
            "-ledger.json"
        );
        vm.writeJson(json, path);
        console.log("Deployment saved to:", path);
    }
}
