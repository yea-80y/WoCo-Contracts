// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ENS} from "@ensdomains/ens-contracts/registry/ENS.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";
import {L1Resolver, INameWrapper} from "../src/durin/L1Resolver.sol";

/// @title DeployL1Resolver
/// @notice Deploys `L1Resolver` (or reuses one already deployed for a different
///         name — see PLAN-ONLY MODE below) and PRINTS, rather than sends, the
///         transactions that wire it up. Never broadcasts a name-owner transaction.
///
/// @dev Run against mainnet, or a mainnet fork for a dry run:
///        forge script script/DeployL1Resolver.s.sol --rpc-url mainnet
///      (add --broadcast only for the DEPLOYER's own transaction, if any — see below)
///
///      Required env:
///        DEPLOYER_PRIVATE_KEY    — deployer EOA. Broadcasts the `new L1Resolver`
///                                  transaction only; holds no role afterwards.
///        GATEWAY_SIGNER_ADDRESS  — CCIP-Read gateway's signing key. When replacing a resolver
///                                  that has a `signer()`, it must be THAT key (G18): one
///                                  gateway key signs for both during the swap. A new key
///                                  only for a first deploy, or with a rotation plan.
///        SPONSOR_ADDRESS         — platform gas-sponsor wallet (checked against, not used).
///        RESOLVER_OWNER          — ends up owning `setURL`/`setSigner`. REQUIRED, no default.
///        L2_CHAIN_ID             — uint64 chain id of the L2 sub-ENS registry.
///        L2_REGISTRY_ADDRESS     — the L2Registry this resolver should point queries at.
///        FALLBACK_RESOLVER       — ordinary L1 resolver the apex itself answers from.
///        NAME_WRAPPER            — the ENS NameWrapper, a constructor argument (immutable).
///                                  Defaults to the mainnet wrapper on chain 1, and MUST
///                                  equal it there (G13); required everywhere else.
///        EXPECT_NAME_OWNER       — the address the operator BELIEVES controls PARENT_NAME.
///                                  REQUIRED, no default — see the #420 custody guard below.
///      Optional env:
///        PARENT_NAME              — defaults to "woco.eth".
///        GATEWAY_URL              — defaults to the WoCo events-api gateway route.
///        L2_DEPLOYMENT_RECORD     — defaults to deployments/<L2_CHAIN_ID>-subens.json.
///        ALLOW_EOA_ADMIN          — testnet escape hatch for RESOLVER_OWNER; see below.
///        ALLOW_FALLBACK_MISMATCH  — testnet escape hatch for the fallback-vs-current-resolver check.
///        ALLOW_SIGNER_CHANGE      — escape hatch for G18, only with a signer-rotation plan.
///        WRITE_DEPLOYMENT_RECORD  — defaults to true; tests set it false.
///        EXISTING_RESOLVER        — set to reuse an already-deployed resolver (PLAN-ONLY MODE).
///
/// WHY THIS SCRIPT PRINTS INSTEAD OF SENDING (#419, #420)
///
/// `configure` (the name's settings, written into the name owner's own slot) and
/// the `setResolver` swap that actually points the name at this contract are
/// both sent by the ENS NAME OWNER, not
/// by this contract's `owner()` and not by the deployer. On mainnet the name owner
/// is the custody Safe (#420) — the deployer key that runs this script never holds
/// that role, on purpose, so the script has no private key to send these with even
/// if it wanted to. Printing the exact calldata, computed from the SAME inputs the
/// deploy just used, is what keeps the Safe's transactions from being hand-typed —
/// which is the failure mode this script exists to remove, not merely the deploy.
///
/// WHY THE L2 DEPLOYMENT RECORD IS CROSS-CHECKED (see the G9 guards below)
///
/// `L2_CHAIN_ID` / `L2_REGISTRY_ADDRESS` are typed in by an operator. The
/// deployment record for the SAME sub-ENS registry already states, on disk, which
/// chain, which registry, and which parent name it was built for. Reading it back
/// and requiring agreement turns a typo into a revert instead of a resolver that
/// quietly points a whole registry's worth of subnames at the wrong place — the
/// baseNode check in particular catches "an L2 registry built for a different
/// parent," which is invisible from either input alone.
///
/// WHY THE FALLBACK MUST MATCH WHERE THE APEX ANSWERS NOW (see G12, G12b)
///
/// The apex's own records (`woco.eth`'s contenthash, the app itself) live wherever
/// the name answers from TODAY — pointing `fallbackResolver` anywhere else
/// silently serves someone else's records, or none. When the current resolver is
/// itself an L1Resolver (v1 before this swap), it stores no records: it forwards
/// the apex to ITS fallback, so that fallback is the source, not the resolver. A
/// typed address left over from a previous chain, a run repeated after the swap,
/// or a fallback that cannot answer `contenthash` all fail here rather than
/// taking the app offline.
///
/// WHY PLAN-ONLY MODE EXISTS (`EXISTING_RESOLVER`)
///
/// One `L1Resolver` can serve many names — `url` and `signer` are shared, while
/// settings are keyed per (node, owner). If a resolver was
/// already deployed for a throwaway name during rehearsal, the mainnet cutover for
/// `woco.eth` reuses that SAME contract rather than deploying a second one with a
/// second gateway signer to keep in sync. Plan-only mode skips the broadcast
/// entirely and instead verifies the reused resolver actually matches what the
/// operator described (G15/G16) before computing the same plan.
///
/// ⚠️ `RESOLVER_OWNER` IS SET IN ONE STEP, BY THE CONSTRUCTOR. `L1Resolver` is
/// `Ownable2Step`, but the two-step accept only guards LATER transfers; the
/// constructor argument takes effect immediately, and renounce is disabled. An
/// address you do not control therefore holds `setURL`/`setSigner`/
/// `setDefaultModule` for good. The name owner can still `setResolver` away with
/// one transaction touching no name on L2 — a wrong owner degrades the gateway
/// settings, it does not strand the name. Verify `RESOLVER_OWNER` on a block
/// explorer before broadcasting regardless.
contract DeployL1Resolver is Script {
    /// @notice The canonical ENS registry address `L1Resolver`'s constructor
    ///         hardcodes. Declared again here, rather than read off the resolver,
    ///         so G8 can run before anything is deployed or reused.
    address constant ENS_ADDRESS = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;

    /// @notice The mainnet NameWrapper. Its admin is the zero address and no
    ///         upgrade contract is set, so no wrapped name can ever leave it -
    ///         which is why the resolver may hold it immutably (audit 964 I-3).
    address constant MAINNET_NAME_WRAPPER = 0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401;

    /// @notice Everything this script reads from its environment, in one place.
    struct Config {
        uint256 deployerPk;
        address gatewaySigner;
        address sponsor;
        address resolverOwner;
        uint64 l2ChainId;
        address l2RegistryAddress;
        address fallbackResolver;
        address nameWrapper;
        address expectNameOwner;
        string parentName;
        string gatewayUrl;
        string l2DeploymentRecord;
        bool allowEoaAdmin;
        bool allowFallbackMismatch;
        bool allowSignerChange;
        bool writeDeploymentRecord;
        address existingResolver;
    }

    /// @notice The name-owner transactions this script computed but did not send,
    ///         plus the facts it verified along the way.
    struct Plan {
        address resolver;
        bytes32 node;
        address nameWrapper;
        bool wrapped;
        address nameOwner;
        address currentResolver;
        bytes configureCall;
        address swapTarget;
        bytes swapCall;
        bytes rollbackCall;
    }

    /// @dev `virtual` ONLY so that tests can vary the inputs — they cannot do it
    ///      through the environment: `vm.setEnv` writes the whole forge process's
    ///      environment and Foundry runs test functions in parallel, so per-test
    ///      environments race. The guards themselves stay in `run()` and are
    ///      never overridden. Production always runs this body.
    function _config() internal view virtual returns (Config memory c) {
        c.deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        c.gatewaySigner = vm.envAddress("GATEWAY_SIGNER_ADDRESS");
        c.sponsor = vm.envAddress("SPONSOR_ADDRESS");
        c.resolverOwner = vm.envAddress("RESOLVER_OWNER");
        c.l2ChainId = uint64(vm.envUint("L2_CHAIN_ID"));
        c.l2RegistryAddress = vm.envAddress("L2_REGISTRY_ADDRESS");
        c.fallbackResolver = vm.envAddress("FALLBACK_RESOLVER");
        c.nameWrapper = vm.envOr("NAME_WRAPPER", block.chainid == 1 ? MAINNET_NAME_WRAPPER : address(0));
        // Required, not defaulted to the deployer or to anything else — see G14.
        c.expectNameOwner = vm.envAddress("EXPECT_NAME_OWNER");
        c.parentName = vm.envOr("PARENT_NAME", string("woco.eth"));
        c.gatewayUrl =
            vm.envOr("GATEWAY_URL", string("https://events-api.woco-net.com/api/ens-gateway/v1/{sender}/{data}"));
        c.l2DeploymentRecord = vm.envOr(
            "L2_DEPLOYMENT_RECORD", string.concat("deployments/", vm.toString(uint256(c.l2ChainId)), "-subens.json")
        );
        c.allowEoaAdmin = vm.envOr("ALLOW_EOA_ADMIN", false);
        c.allowFallbackMismatch = vm.envOr("ALLOW_FALLBACK_MISMATCH", false);
        c.allowSignerChange = vm.envOr("ALLOW_SIGNER_CHANGE", false);
        c.writeDeploymentRecord = vm.envOr("WRITE_DEPLOYMENT_RECORD", true);
        c.existingResolver = vm.envOr("EXISTING_RESOLVER", address(0));
    }

    /// @dev Split into several internal steps, each with its own stack frame,
    ///      purely to stay under the EVM's 16-local stack-slot limit — this
    ///      script has too many independently-named values (env inputs, chain
    ///      reads, and the computed plan) to fit in one function body.
    function run() external returns (Plan memory plan) {
        Config memory c = _config();

        (ENS ens, bytes memory dnsName, bytes32 node, address currentResolver) = _checkPreDeployGuards(c);

        (L1Resolver resolver, bool planOnly) = _deployOrReuse(c);

        plan = _finalizePlan(c, ens, resolver, node, dnsName, currentResolver, planOnly);

        if (c.writeDeploymentRecord) {
            _writeDeploymentRecord(c, plan, planOnly);
        }
    }

    /*//////////////////////////////////////////////////////////////
              PRE-BROADCAST GUARDS — env shape and chain reads (G1-G13, G18)
    //////////////////////////////////////////////////////////////*/

    function _checkPreDeployGuards(Config memory c)
        internal
        view
        returns (ENS ens, bytes memory dnsName, bytes32 node, address currentResolver)
    {
        address deployer = vm.addr(c.deployerPk);

        // G1
        require(c.resolverOwner != address(0), "RESOLVER_OWNER must not be the zero address");

        // G2. A multisig is a contract; a bare key is not. Coarse and
        // deliberately so — it cannot check signers or a threshold, only that
        // this is not ending on one key. The owner holds `setURL`/`setSigner`,
        // i.e. who may forge every subname this resolver ever answers for.
        require(
            c.allowEoaAdmin || c.resolverOwner.code.length > 0,
            "RESOLVER_OWNER has no code - expected a multisig; the owner holds setURL/setSigner, i.e. who may forge every subname; set ALLOW_EOA_ADMIN=true for testnet"
        );

        // G3
        require(c.gatewaySigner != address(0), "GATEWAY_SIGNER_ADDRESS must not be the zero address");

        // G4. Owner rule: the gateway key is a NEW hot key. The server also
        // refuses to boot on this equality; this is defence in depth at the
        // point the address is actually set.
        require(
            c.gatewaySigner != c.sponsor,
            "GATEWAY_SIGNER_ADDRESS must not equal SPONSOR_ADDRESS - the gateway key must be a new hot key, never the sponsor's"
        );

        // G5. The deployer key lives in contracts/.env; it is not the gateway's key.
        require(
            c.gatewaySigner != deployer,
            "GATEWAY_SIGNER_ADDRESS must not equal the deployer - the deployer key lives in contracts/.env, it is not the gateway's key"
        );

        // G6. EIP-3668 template. Without {data} clients POST and the gateway
        // route is GET-only, so every lookup fails.
        require(_contains(c.gatewayUrl, "{sender}"), "GATEWAY_URL must contain the literal substring {sender}");
        require(
            _contains(c.gatewayUrl, "{data}"),
            "GATEWAY_URL must contain the literal substring {data} - without it clients POST and the gateway route is GET-only, so every lookup fails"
        );

        // G7
        require(c.l2ChainId != 0, "L2_CHAIN_ID must not be zero");
        require(c.l2RegistryAddress != address(0), "L2_REGISTRY_ADDRESS must not be the zero address");

        // G8. Catches running this against an L2 by mistake.
        require(
            ENS_ADDRESS.code.length > 0,
            "the canonical ENS registry has no code on this chain - are you pointed at an L2 by mistake?"
        );

        // G13. The wrapper is immutable in the resolver, so a wrong one could
        // never be fixed. On mainnet only the canonical wrapper is accepted.
        require(c.nameWrapper.code.length > 0, "NAME_WRAPPER has no code");
        require(
            block.chainid != 1 || c.nameWrapper == MAINNET_NAME_WRAPPER,
            "NAME_WRAPPER is not the mainnet NameWrapper 0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401"
        );

        ens = ENS(ENS_ADDRESS);
        (dnsName, node) = NameEncoder.dnsEncodeName(c.parentName);

        // Read BEFORE anything else touches state - this is the prepared
        // one-tx rollback target, and it must reflect the resolver in place
        // right now, not whatever it becomes later in this script.
        currentResolver = ens.resolver(node);

        // G9. Cross-check the L2 deployment record against these inputs. One
        // require per field, in this order, so each is independently
        // reachable in tests. The baseNode clause is the one that catches "an
        // L2 registry built for a different parent" - every subname would
        // then silently resolve to nothing.
        string memory record = vm.readFile(c.l2DeploymentRecord);
        require(
            vm.parseJsonUint(record, ".chainId") == uint256(c.l2ChainId),
            "L2_DEPLOYMENT_RECORD chainId does not match L2_CHAIN_ID"
        );
        require(
            vm.parseJsonAddress(record, ".l2Registry") == c.l2RegistryAddress,
            "L2_DEPLOYMENT_RECORD l2Registry does not match L2_REGISTRY_ADDRESS"
        );
        require(
            vm.parseJsonBytes32(record, ".baseNode") == node,
            "L2_DEPLOYMENT_RECORD baseNode does not match namehash(PARENT_NAME) - the L2 registry was built for a different parent, every subname would silently resolve to nothing"
        );
        require(
            keccak256(bytes(vm.parseJsonString(record, ".parentName"))) == keccak256(bytes(c.parentName)),
            "L2_DEPLOYMENT_RECORD parentName does not match PARENT_NAME"
        );

        // G10
        require(ens.owner(node) != address(0), "PARENT_NAME is not registered - ens.owner(node) is the zero address");

        // G11. The contract checks at set time too, but that would be the
        // Safe's transaction - fail here, before deploy.
        require(c.fallbackResolver != address(0), "FALLBACK_RESOLVER must not be the zero address");
        require(c.fallbackResolver.code.length > 0, "FALLBACK_RESOLVER has no code");

        // G12. The apex must keep answering from where it answers NOW - through
        // an L1Resolver, that is its fallback (see the header).
        require(
            c.allowFallbackMismatch || c.fallbackResolver == _apexSource(currentResolver, node),
            "FALLBACK_RESOLVER does not match where the apex CURRENTLY answers from - set ALLOW_FALLBACK_MISMATCH=true to override"
        );

        // G12b. Even with the override, the fallback must be a record store: an
        // L1Resolver has no `contenthash`, so the app would go dark at the swap.
        (bool answers,) = c.fallbackResolver.staticcall(abi.encodeWithSignature("contenthash(bytes32)", node));
        require(
            answers,
            "FALLBACK_RESOLVER does not answer contenthash(node) - it is not a record store, and the apex would go dark"
        );

        // G18. One gateway key signs for BOTH resolvers during the swap (the old
        // format for the current one, the chain-bound format for this one), and a
        // rollback needs the current one to still accept it. A different key is a
        // rotation, which needs its own plan.
        address currentSigner = _signerOf(currentResolver);
        require(
            c.allowSignerChange || currentSigner == address(0) || currentSigner == c.gatewaySigner,
            "GATEWAY_SIGNER_ADDRESS differs from the current resolver's signer() - one gateway key signs for both during the swap; set ALLOW_SIGNER_CHANGE=true only with a rotation plan"
        );
    }

    /// @dev Where the apex answers from today: the current resolver itself, or,
    ///      when it is an L1Resolver (it has `fallbackResolver(bytes32)`), the
    ///      fallback it forwards the apex to.
    function _apexSource(address current, bytes32 node) internal view returns (address) {
        if (current.code.length == 0) return current;
        (bool ok, bytes memory ret) = current.staticcall(abi.encodeWithSignature("fallbackResolver(bytes32)", node));
        if (ok && ret.length == 32) return abi.decode(ret, (address));
        return current;
    }

    /// @dev The current resolver's gateway signer, or zero when it has none
    ///      (an ordinary resolver such as the ENS PublicResolver).
    function _signerOf(address current) internal view returns (address) {
        if (current.code.length == 0) return address(0);
        (bool ok, bytes memory ret) = current.staticcall(abi.encodeWithSignature("signer()"));
        if (ok && ret.length == 32) return abi.decode(ret, (address));
        return address(0);
    }

    /*//////////////////////////////////////////////////////////////
              DEPLOY (or reuse an existing resolver) — G15/G16
    //////////////////////////////////////////////////////////////*/

    function _deployOrReuse(Config memory c) internal returns (L1Resolver resolver, bool planOnly) {
        planOnly = c.existingResolver != address(0);

        if (!planOnly) {
            vm.startBroadcast(c.deployerPk);
            resolver = new L1Resolver(c.gatewayUrl, c.gatewaySigner, c.resolverOwner, INameWrapper(c.nameWrapper));
            vm.stopBroadcast();
        } else {
            // G15
            require(c.existingResolver.code.length > 0, "EXISTING_RESOLVER has no code");
            resolver = L1Resolver(c.existingResolver);

            // G16. Three independent checks, distinct messages: each says the
            // existing resolver is not the one the operator described.
            require(
                resolver.signer() == c.gatewaySigner,
                "EXISTING_RESOLVER.signer() does not match GATEWAY_SIGNER_ADDRESS - this is not the resolver the operator described"
            );
            require(
                resolver.owner() == c.resolverOwner,
                "EXISTING_RESOLVER.owner() does not match RESOLVER_OWNER - this is not the resolver the operator described"
            );
            require(
                keccak256(bytes(resolver.url())) == keccak256(bytes(c.gatewayUrl)),
                "EXISTING_RESOLVER.url() does not match GATEWAY_URL - this is not the resolver the operator described"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
            POST-DEPLOY GUARDS (G13/G14) + PLAN CONSTRUCTION

            A failure in here still aborts the WHOLE broadcast in
            simulation: forge only submits the transactions collected
            between startBroadcast/stopBroadcast if run() completes
            without reverting, so a revert here means the
            `new L1Resolver` from `_deployOrReuse` is never actually sent.
    //////////////////////////////////////////////////////////////*/

    function _finalizePlan(
        Config memory c,
        ENS ens,
        L1Resolver resolver,
        bytes32 node,
        bytes memory dnsName,
        address currentResolver,
        bool planOnly
    ) internal returns (Plan memory plan) {
        // G13 (post-deploy half): the resolver holds the wrapper the operator named.
        require(
            address(resolver.nameWrapper()) == c.nameWrapper,
            "the deployed/reused resolver's nameWrapper does not match NAME_WRAPPER"
        );

        // G14. #420 custody: the printed transactions are for this signer,
        // and on mainnet it must be the Safe, not the hot key.
        bool wrapped = ens.owner(node) == address(resolver.nameWrapper());
        address nameOwner =
            wrapped ? INameWrapper(address(resolver.nameWrapper())).ownerOf(uint256(node)) : ens.owner(node);
        require(
            nameOwner == c.expectNameOwner,
            "#420 custody: PARENT_NAME's effective owner does not match EXPECT_NAME_OWNER - the printed transactions are for this signer, and on mainnet it must be the Safe, not the hot key"
        );

        // G17. The rollback is `setResolver(node, currentResolver)`. If the name
        // ALREADY points at this resolver — a rerun after the swap, reachable
        // only with ALLOW_FALLBACK_MISMATCH set — that calldata is a no-op that
        // would print under the heading "ROLLBACK" and be trusted at the worst
        // possible moment. Refuse: the rollback target belongs to the run that
        // preceded the swap, and lives in that run's record.
        require(
            currentResolver != address(resolver),
            "PARENT_NAME already points at this resolver - the printed rollback would be a no-op; take the rollback target from the record of the run that preceded the swap"
        );

        // Post-conditions, deploy mode only. Pure re-assertions of the
        // constructor arguments this same script just passed in - there is no
        // input this script could be given that makes them fail without also
        // failing something upstream, so they are an UNTESTABLE-BY-MUTATION
        // class: deleting any one of them cannot be caught by a unit test
        // here. Kept anyway as a live sanity check against a broadcast that
        // somehow lands differently than simulated.
        if (!planOnly) {
            require(resolver.owner() == c.resolverOwner, "resolver.owner() does not match RESOLVER_OWNER after deploy");
            require(
                resolver.signer() == c.gatewaySigner, "resolver.signer() does not match GATEWAY_SIGNER_ADDRESS after deploy"
            );
            require(
                keccak256(bytes(resolver.url())) == keccak256(bytes(c.gatewayUrl)),
                "resolver.url() does not match GATEWAY_URL after deploy"
            );
        }

        address swapTarget = wrapped ? address(resolver.nameWrapper()) : address(ens);

        plan = Plan({
            resolver: address(resolver),
            node: node,
            nameWrapper: address(resolver.nameWrapper()),
            wrapped: wrapped,
            nameOwner: nameOwner,
            currentResolver: currentResolver,
            configureCall: _configureCall(c, node, nameOwner),
            swapTarget: swapTarget,
            swapCall: abi.encodeWithSignature("setResolver(bytes32,address)", node, address(resolver)),
            rollbackCall: abi.encodeWithSignature("setResolver(bytes32,address)", node, currentResolver)
        });

        _printPlan(plan, dnsName);
    }

    /// @dev The one settings call the name owner sends: into its OWN slot,
    ///      with no module (the built-in signer path). Split out only for the
    ///      stack.
    function _configureCall(Config memory c, bytes32 node, address nameOwner) internal pure returns (bytes memory) {
        return abi.encodeCall(
            L1Resolver.configure,
            (
                node,
                nameOwner,
                L1Resolver.Settings({
                    chainId: c.l2ChainId,
                    registry: c.l2RegistryAddress,
                    fallbackResolver: c.fallbackResolver,
                    module: address(0),
                    moduleData: ""
                })
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                              CONSOLE OUTPUT
    //////////////////////////////////////////////////////////////*/

    function _printPlan(Plan memory plan, bytes memory dnsName) internal view {
        console.log("================================================================");
        console.log("NAME OWNER TRANSACTIONS - send from", plan.nameOwner);
        console.log(plan.wrapped ? "(wrapped: yes)" : "(wrapped: no)");
        console.log("================================================================");

        console.log("1. configure - the settings, into the name owner's own slot");
        console.log("   to:  ", plan.resolver);
        console.log("   data:");
        console.logBytes(plan.configureCall);

        console.log("2. SWAP setResolver");
        console.log("   to:  ", plan.swapTarget);
        console.log("   data:");
        console.logBytes(plan.swapCall);

        console.log("----------------------------------------------------------------");
        console.log("ROLLBACK (prepare before sending step 2)");
        console.log("   to:  ", plan.swapTarget);
        console.log("   data:");
        console.logBytes(plan.rollbackCall);
        console.log("----------------------------------------------------------------");

        bytes memory contenthashCall = abi.encodeWithSignature("contenthash(bytes32)", plan.node);
        console.log("Verify BEFORE sending the swap - routeFor must name the owner and the settings above:");
        console.log(
            string.concat(
                "  cast call ",
                vm.toString(plan.resolver),
                " \"routeFor(bytes)(bytes32,address,(uint64,address,address,address,bytes))\" ",
                vm.toString(dnsName)
            )
        );
        console.log(
            string.concat(
                "  cast call ",
                vm.toString(plan.resolver),
                " \"resolve(bytes,bytes)(bytes)\" ",
                vm.toString(dnsName),
                " ",
                vm.toString(contenthashCall)
            )
        );

        // Ask where the apex answers from NOW: through an L1Resolver that is its
        // fallback, since an L1Resolver stores no records of its own.
        (bool ok, bytes memory result) = _apexSource(plan.currentResolver, plan.node).staticcall(contenthashCall);
        if (ok) {
            console.log("The apex's contenthash(node) today (must match the verify call above):");
            console.logBytes(result);
        } else {
            console.log("The apex's contenthash(node) today: reverted");
        }
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT RECORD
    //////////////////////////////////////////////////////////////*/

    function _writeDeploymentRecord(Config memory c, Plan memory plan, bool planOnly) internal {
        vm.createDir("deployments", true);

        string memory obj = "l1resolver-deployment";
        vm.serializeAddress(obj, "resolver", plan.resolver);
        vm.serializeBytes32(obj, "node", plan.node);
        vm.serializeString(obj, "parentName", c.parentName);
        vm.serializeString(obj, "url", c.gatewayUrl);
        vm.serializeAddress(obj, "signer", c.gatewaySigner);
        vm.serializeAddress(obj, "owner", c.resolverOwner);
        vm.serializeAddress(obj, "nameWrapper", plan.nameWrapper);
        vm.serializeBool(obj, "wrapped", plan.wrapped);
        vm.serializeAddress(obj, "nameOwner", plan.nameOwner);
        vm.serializeAddress(obj, "currentResolver", plan.currentResolver);
        vm.serializeUint(obj, "l2ChainId", uint256(c.l2ChainId));
        vm.serializeAddress(obj, "l2Registry", c.l2RegistryAddress);
        vm.serializeAddress(obj, "fallbackResolver", c.fallbackResolver);
        vm.serializeBool(obj, "planOnly", planOnly);
        vm.serializeString(obj, "configureCall", vm.toString(plan.configureCall));
        vm.serializeString(obj, "swapCall", vm.toString(plan.swapCall));
        string memory json = vm.serializeString(obj, "rollbackCall", vm.toString(plan.rollbackCall));

        string memory path = string.concat("deployments/", vm.toString(block.chainid), "-l1resolver.json");
        vm.writeJson(json, path);
        console.log("Deployment record saved to:", path);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev True if `needle` occurs anywhere in `haystack`, byte-for-byte.
    function _contains(string memory haystack, string memory needle) internal pure returns (bool) {
        bytes memory h = bytes(haystack);
        bytes memory n = bytes(needle);
        if (n.length == 0) return true;
        if (n.length > h.length) return false;

        for (uint256 i = 0; i <= h.length - n.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < n.length; j++) {
                if (h[i + j] != n[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }
        return false;
    }
}
