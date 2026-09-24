// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ***********************************************
// ▗▖  ▗▖ ▗▄▖ ▗▖  ▗▖▗▄▄▄▖ ▗▄▄▖▗▄▄▄▖▗▄▖ ▗▖  ▗▖▗▄▄▄▖
// ▐▛▚▖▐▌▐▌ ▐▌▐▛▚▞▜▌▐▌   ▐▌     █ ▐▌ ▐▌▐▛▚▖▐▌▐▌
// ▐▌ ▝▜▌▐▛▀▜▌▐▌  ▐▌▐▛▀▀▘ ▝▀▚▖  █ ▐▌ ▐▌▐▌ ▝▜▌▐▛▀▀▘
// ▐▌  ▐▌▐▌ ▐▌▐▌  ▐▌▐▙▄▄▖▗▄▄▞▘  █ ▝▚▄▞▘▐▌  ▐▌▐▙▄▄▖
// ***********************************************

import {ENS} from "@ensdomains/ens-contracts/registry/ENS.sol";
import {IExtendedResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {HexUtils} from "@ensdomains/ens-contracts/utils/HexUtils.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {IAnswerModule, Lookup} from "./interfaces/IAnswerModule.sol";
import {SignatureVerifier} from "./lib/SignatureVerifier.sol";

interface IResolverService {
    function stuffedResolveCall(
        bytes calldata name,
        bytes calldata data,
        uint64 targetChainId,
        address targetRegistryAddress
    )
        external
        view
        returns (bytes memory result, uint64 expires, bytes memory sig);
}

interface INameWrapper {
    function ownerOf(uint256 id) external view returns (address owner);
    function isApprovedForAll(address account, address operator) external view returns (bool);
}

/// @author NameStone
/// @notice ENS resolver that bridges names to L2 registries through CCIP Read.
/// @dev Callers must implement EIP-3668 and ENSIP-10.
///
/// ┌──────────────────────────────────────────────────────────────────────────┐
/// │ VENDORED FROM DURIN, REBUILT BY WOCO FOR v2 (audit 964, #23).            │
/// │                                                                          │
/// │ A SHARED resolver meant to last: woco.eth and other owners' names point │
/// │ here, and every redeploy would cost each of them a `setResolver`.       │
/// │                                                                          │
/// │ · Names are read LABEL BY LABEL from the DNS bytes, never re-split as a  │
/// │   string, and the DEEPEST ancestor configured for its CURRENT owner      │
/// │   routes the query (audit 964 M-1, L-2).                                 │
/// │ · Settings are stored per (node, owner), so a sale leaves nothing behind │
/// │   for the buyer and a custody move is pre-positioned (audit 964 H-1).    │
/// │ · The signed hash binds the chain id (audit 964 M-2).                    │
/// │ · A per-name answer module, and an owner-set default, let resolution     │
/// │   move off the WoCo signer (e.g. to proofs) without a redeploy.          │
/// │ · Ownable2Step; renounce always reverts (audit 926).                     │
/// │                                                                          │
/// │ The built-in path's gateway request (`stuffedResolveCall`) is            │
/// │ byte-identical to upstream's, so the gateway's parsing is unchanged.     │
/// └──────────────────────────────────────────────────────────────────────────┘
contract L1Resolver is IExtendedResolver, Ownable2Step {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice How a node and everything beneath it resolve. A node counts as
    ///         configured when `registry`, `fallbackResolver` or `module` is
    ///         set; writing an all-empty `Settings` clears it.
    struct Settings {
        /// L2 chain of `registry`, carried into the gateway request.
        uint64 chainId;
        /// L2 registry the built-in path (or `defaultModule`) reads beneath this node.
        address registry;
        /// Ordinary L1 resolver that answers for this node ITSELF, never for
        /// anything beneath it. Keeps an apex record (woco.eth's contenthash)
        /// on L1 instead of behind a hot signer, an L2 RPC and an API server.
        address fallbackResolver;
        /// This name owner's own answer module. Zero = `defaultModule`, and zero
        /// there = the built-in WoCo signer path.
        address module;
        /// Handed to the module untouched.
        bytes moduleData;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    ENS public constant ens = ENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Fixed for good, and that is the safe choice: the mainnet
    ///         NameWrapper has no admin and no upgrade contract, so no wrapped
    ///         name can ever move to another wrapper (audit 964 I-3). Taken as a
    ///         constructor argument instead of read from `namewrapper.eth`,
    ///         whose registry owner is a single EOA.
    INameWrapper public immutable nameWrapper;

    string public url;
    address public signer;

    /// @notice The answer path for every name whose owner has not chosen a
    ///         module; zero = the built-in signer path.
    /// @dev TRUST, stated so it is not overstated: `owner()` decides the answer
    ///      path for every name whose owner has not chosen a module — the
    ///      identical power `setSigner`/`setURL` already give it, made visible
    ///      in code. A name owner's own module is outside `owner()`'s reach.
    address public defaultModule;

    mapping(bytes32 node => mapping(address owner => Settings)) internal _settings;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Configured(bytes32 indexed node, address indexed owner, address indexed by, Settings settings);
    event DefaultModuleChanged(address module);
    event GatewayChanged(string url);
    event SignerChanged(address signer);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error Unauthorized();
    error InvalidSignature();
    /// Root, a single label, a malformed encoding, or a 66-byte `[...]` label
    /// whose 64 inner characters are not all hex.
    error UnsupportedName();
    error NoConfiguredAncestor();
    /// The deepest configured node offers nothing for this query: no registry
    /// and no module beneath it, or no fallback for itself.
    error NotServed(bytes32 node);
    error RenounceDisabled();
    error NameWrapperHasNoCode();
    error FallbackResolverHasNoCode(address resolver);
    error ModuleNotSupported(address module);
    error OffchainLookup(
        address sender,
        string[] urls,
        bytes callData,
        bytes4 callbackFunction,
        bytes extraData
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @dev The wrapper is immutable, so a mistyped one could never be fixed;
    ///      refusing a codeless address is the one check that cannot wait for
    ///      the deploy script.
    constructor(
        string memory _url,
        address _signer,
        address _owner,
        INameWrapper _nameWrapper
    ) Ownable(_owner) {
        if (address(_nameWrapper).code.length == 0) revert NameWrapperHasNoCode();
        nameWrapper = _nameWrapper;
        url = _url;
        emit GatewayChanged(_url);
        signer = _signer;
        emit SignerChanged(_signer);
    }

    /*//////////////////////////////////////////////////////////////
                            PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Write `forOwner`'s settings for `node`.
    /// @dev Only `forOwner`'s slot is ever read while `forOwner` owns the node,
    ///      so a write needs no ownership check: anyone may fill their OWN slot
    ///      for any node. That is what lets a new custodian pre-position before
    ///      a transfer (zero downtime), and it is why a seller can never leave
    ///      settings for a buyer - the buyer's slot is the buyer's alone.
    ///
    ///      An operator may write for `forOwner` if ENS itself gives it full
    ///      control of `forOwner`'s names of this kind: a NameWrapper operator
    ///      (`isApprovedForAll` on the wrapper) for a wrapped node, a registry
    ///      operator otherwise. Such an operator can already repoint or take
    ///      the name, so writing its principal's settings gives it nothing new.
    ///      Accepting either kind for any node would let a holder's registry
    ///      operator steer that holder's wrapped names, which ENS does not
    ///      allow. The ENS PublicResolver's own, narrower delegate approvals
    ///      are NOT read here (audit 969 L-1). The .eth grace period and fuses
    ///      are not consulted, because this never repoints the name. The wrap
    ///      state checked is the node's CURRENT one, so an operator cannot
    ///      pre-position across a wrap or unwrap; the principal can.
    ///
    ///      A write for a node `forOwner` does not own succeeds and changes
    ///      nothing until it does; check a setup with `routeFor`, not with the
    ///      receipt.
    function configure(bytes32 node, address forOwner, Settings calldata s) external {
        if (forOwner == address(0)) revert Unauthorized();
        if (msg.sender != forOwner && !_isOperatorFor(node, forOwner, msg.sender)) {
            revert Unauthorized();
        }
        // A STATICCALL to an empty address succeeds with empty data, so a
        // mistyped fallback would answer "no record" - the app vanishing with
        // no error anywhere. Refused here, on the cold path.
        if (s.fallbackResolver != address(0) && s.fallbackResolver.code.length == 0) {
            revert FallbackResolverHasNoCode(s.fallbackResolver);
        }
        if (s.module != address(0)) _requireModule(s.module);

        Settings storage st = _settings[node][forOwner];
        st.chainId = s.chainId;
        st.registry = s.registry;
        st.fallbackResolver = s.fallbackResolver;
        st.module = s.module;
        st.moduleData = s.moduleData;
        emit Configured(node, forOwner, msg.sender, s);
    }

    /// @notice Resolves a name, as specified by ENSIP 10.
    /// @param name The DNS-encoded name to resolve.
    /// @param data The ABI encoded data for the underlying resolution function (Eg, addr(bytes32), text(bytes32,string), etc).
    /// @return The return data, ABI encoded identically to the underlying function.
    function resolve(
        bytes calldata name,
        bytes calldata data
    ) external view override returns (bytes memory) {
        (bool found, bytes32 node, , Settings memory s, bool isSelf) = _route(name);
        // Refused here rather than sent to the gateway with zero values: the
        // client fails either way, and this way without a round trip.
        if (!found) revert NoConfiguredAncestor();

        if (isSelf && s.fallbackResolver != address(0)) {
            return _resolveOnFallback(s.fallbackResolver, data);
        }
        // A fallback-only node says "I answer on L1; nothing beneath me is
        // served here". The default module does not override that.
        if (s.module == address(0) && s.registry == address(0)) revert NotServed(node);

        return _lookup(name, data, s);
    }

    /// @notice Callback used by CCIP read compatible clients to parse and verify the response.
    /// @dev The answer carries the authority of the module named in
    ///      `extraData` (zero = the WoCo signer); only a client that obtained
    ///      that `extraData` from `resolve()` may rely on it. The module is
    ///      taken from `extraData`, never from storage, so an answer judged by
    ///      one module can never be judged by another.
    function resolveWithProof(
        bytes calldata response,
        bytes calldata extraData
    ) external view returns (bytes memory) {
        (address module, Lookup memory q, bytes memory callData) =
            abi.decode(extraData, (address, Lookup, bytes));

        if (module == address(0)) {
            // Signed over `callData` (the gateway's request), not over the
            // wider `extraData`, so the gateway never learns this layout.
            (address recovered, bytes memory result) = SignatureVerifier.verify(callData, response);
            if (recovered != signer) revert InvalidSignature();
            return result;
        }
        return IAnswerModule(module).verify(q, callData, response);
    }

    function supportsInterface(bytes4 interfaceID) public pure returns (bool) {
        return
            interfaceID == type(IExtendedResolver).interfaceId ||
            interfaceID == 0x01ffc9a7; // ERC-165 interface
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice The address whose settings apply to `node` right now: the ENS
    ///         registry owner, unwrapped through the NameWrapper. A wrapped .eth
    ///         name reads as unowned once its wrapper expiry (grace included)
    ///         passes, so its settings stop applying.
    function effectiveOwner(bytes32 node) public view returns (address owner) {
        owner = ens.owner(node);
        if (owner == address(nameWrapper)) {
            owner = nameWrapper.ownerOf(uint256(node));
        }
    }

    function settings(bytes32 node, address owner) external view returns (Settings memory) {
        return _settings[node][owner];
    }

    function settingsOf(bytes32 node) external view returns (address owner, Settings memory s) {
        owner = effectiveOwner(node);
        s = _settings[node][owner];
    }

    /// @notice The node, owner and settings `resolve()` would route `name`
    ///         through; all zero when no ancestor is configured. Reverts only
    ///         on a malformed name. Same walk as `resolve()`, so they cannot drift.
    function routeFor(bytes calldata name) external view returns (bytes32 node, address owner, Settings memory s) {
        (, node, owner, s, ) = _route(name);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets the URL for the resolver service.
    function setURL(string calldata _url) external onlyOwner {
        url = _url;
        emit GatewayChanged(_url);
    }

    /// @notice Sets the signers for the resolver service.
    function setSigner(address _signer) external onlyOwner {
        signer = _signer;
        emit SignerChanged(_signer);
    }

    /// @notice Move every name whose owner has not chosen a module to `m`
    ///         (zero = the built-in signer path). See `defaultModule`.
    function setDefaultModule(address m) external onlyOwner {
        if (m != address(0)) _requireModule(m);
        defaultModule = m;
        emit DefaultModuleChanged(m);
    }

    /// @notice Disabled: always reverts `RenounceDisabled` (audit 926 findings
    ///         2 and 4, WoCo-Contracts #23).
    /// @dev Renouncing would freeze `setURL`, `setSigner` and `setDefaultModule`
    ///      for good: the gateway could never move and a leaked signer could
    ///      never be rotated. A Safe transaction builder has been seen to
    ///      pre-fill `renounceOwnership` (0x715018a6), so the refusal lives in
    ///      code, not in a signing checklist. Hand ownership on with
    ///      `transferOwnership` + `acceptOwnership` instead. `pure` and
    ///      unguarded: there is nothing left to authorise.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev The DEEPEST suffix of `name` configured for its current owner.
    ///      A node's settings are a complete statement for that node and its
    ///      subtree, so the walk never looks past it: the owner of a node owns
    ///      what is beneath it, as in ENS itself.
    function _route(bytes calldata name)
        internal
        view
        returns (bool found, bytes32 node, address owner, Settings memory s, bool isSelf)
    {
        bytes32[] memory nodes = _suffixNodes(name);
        // The last node is the TLD, which is never a route target: a
        // single-label name is refused, and no TLD owner is a tenant (audit 969 L-2).
        for (uint256 k; k + 1 < nodes.length; ++k) {
            address o = effectiveOwner(nodes[k]);
            // Slot zero can never be written (`configure` refuses it).
            if (o == address(0)) continue;
            Settings storage st = _settings[nodes[k]][o];
            if (st.registry == address(0) && st.fallbackResolver == address(0) && st.module == address(0)) {
                continue;
            }
            return (true, nodes[k], o, st, k == 0);
        }
    }

    /// @dev `nodes[k]` is the namehash of the suffix starting at label k, so
    ///      `nodes[0]` is the name's own node. Hashing each label's exact bytes
    ///      from the DNS encoding is what closes audit 964 M-1: a label that
    ///      contains a "." is one label, never two.
    ///
    ///      Strict where the UniversalResolver is lenient (missing terminator,
    ///      bytes after it): two encodings of one name should not both be
    ///      lookups. Root and single-label names are refused - no TLD can call
    ///      `configure`, so none can be configured here.
    function _suffixNodes(bytes calldata name) internal pure returns (bytes32[] memory nodes) {
        uint256 count;
        uint256 i;
        while (true) {
            if (i >= name.length) revert UnsupportedName();
            uint256 len = uint8(name[i]);
            if (len == 0) {
                if (i != name.length - 1) revert UnsupportedName();
                break;
            }
            i += 1 + len;
            ++count;
        }
        if (count < 2) revert UnsupportedName();

        uint256[] memory starts = new uint256[](count);
        i = 0;
        for (uint256 k; k < count; ++k) {
            starts[k] = i;
            i += 1 + uint8(name[i]);
        }

        nodes = new bytes32[](count);
        bytes32 node;
        for (uint256 k = count; k > 0; --k) {
            uint256 start = starts[k - 1];
            bytes32 label = _labelhash(name[start + 1:start + 1 + uint8(name[start])]);
            node = keccak256(abi.encodePacked(node, label));
            nodes[k - 1] = node;
        }
    }

    /// @dev A 66-byte `[` + 64 hex + `]` label IS its labelhash, exactly as the
    ///      UniversalResolver reads it; otherwise the node derived here would
    ///      differ from the one the UniversalResolver used to reach us. Unlike
    ///      the UniversalResolver, invalid hex is refused, not hashed.
    function _labelhash(bytes calldata label) internal pure returns (bytes32) {
        if (label.length == 66 && label[0] == "[" && label[65] == "]") {
            (bytes32 h, bool valid) = HexUtils.hexStringToBytes32(label, 1, 65);
            if (!valid) revert UnsupportedName();
            return h;
        }
        return keccak256(label);
    }

    /// @dev The built-in path, or the module's, for a query beneath (or at) a
    ///      configured node. `extraData` has ONE layout for both.
    function _lookup(bytes calldata name, bytes calldata data, Settings memory s)
        internal
        view
        returns (bytes memory)
    {
        address module = s.module != address(0) ? s.module : defaultModule;
        Lookup memory q =
            Lookup({name: name, data: data, chainId: s.chainId, registry: s.registry, moduleData: s.moduleData});

        string[] memory urls;
        bytes memory callData;
        if (module == address(0)) {
            callData = abi.encodeWithSelector(
                IResolverService.stuffedResolveCall.selector,
                name,
                data,
                s.chainId,
                s.registry
            );
            urls = new string[](1);
            urls[0] = url;
        } else {
            (urls, callData) = IAnswerModule(module).prepare(q);
            // A module that can answer onchain does so without a round trip.
            if (urls.length == 0) return callData;
        }

        revert OffchainLookup(
            address(this),
            urls,
            callData,
            L1Resolver.resolveWithProof.selector,
            abi.encode(module, q, callData)
        );
    }

    /// @dev Whether `operator` holds `forOwner`'s full ENS control over `node`:
    ///      an operator of whichever contract (NameWrapper or registry) holds the
    ///      node now.
    function _isOperatorFor(bytes32 node, address forOwner, address operator) internal view returns (bool) {
        if (ens.owner(node) == address(nameWrapper)) {
            return nameWrapper.isApprovedForAll(forOwner, operator);
        }
        return ens.isApprovedForAll(forOwner, operator);
    }

    /// @dev A codeless or non-conforming module would turn into a decode revert
    ///      for a whole subtree, so it is refused at set time.
    function _requireModule(address m) internal view {
        if (!ERC165Checker.supportsInterface(m, type(IAnswerModule).interfaceId)) {
            revert ModuleNotSupported(m);
        }
    }

    /// @dev Forwards the ENSIP-10 inner call to an ordinary L1 resolver and
    ///      returns its answer as `resolve()`'s return data.
    ///
    ///      A failure is bubbled, never swallowed. Returning empty bytes on
    ///      revert would turn "this resolver could not answer" into a confident
    ///      "there is no record", which for a contenthash query is the app
    ///      silently disappearing rather than visibly erroring.
    ///
    ///      RESIDUAL, stated so it is not rediscovered: the inner `data` is
    ///      passed through unexamined, so a caller that hand-builds a query can
    ///      have this contract read a record for a node OTHER than the name it
    ///      asked about. It grants no access — the fallback is a public resolver
    ///      anyone may call directly for the same answer — and honest clients
    ///      (the Universal Resolver, ethers, viem, eth.limo) build `data` from
    ///      the name they are resolving. The gateway performs the equivalent
    ///      node check on the offchain path, where a signature makes it matter.
    function _resolveOnFallback(
        address l1Fallback,
        bytes calldata data
    ) internal view returns (bytes memory) {
        (bool ok, bytes memory result) = l1Fallback.staticcall(data);
        if (!ok) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
        return result;
    }
}
