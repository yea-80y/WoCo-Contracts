// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ***********************************************
// ▗▖  ▗▖ ▗▄▖ ▗▖  ▗▖▗▄▄▄▖ ▗▄▄▖▗▄▄▄▖▗▄▖ ▗▖  ▗▖▗▄▄▄▖
// ▐▛▚▖▐▌▐▌ ▐▌▐▛▚▞▜▌▐▌   ▐▌     █ ▐▌ ▐▌▐▛▚▖▐▌▐▌
// ▐▌ ▝▜▌▐▛▀▜▌▐▌  ▐▌▐▛▀▀▘ ▝▀▚▖  █ ▐▌ ▐▌▐▌ ▝▜▌▐▛▀▀▘
// ▐▌  ▐▌▐▌ ▐▌▐▌  ▐▌▐▙▄▄▖▗▄▄▞▘  █ ▝▚▄▞▘▐▌  ▐▌▐▙▄▄▖
// ***********************************************

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";

import {ENSDNSUtils} from "./lib/ENSDNSUtils.sol";
import {L2Resolver} from "./L2Resolver.sol";

/// @title Durin Registry
/// @author NameStone
/// @notice Manages ENS subname registration and management on L2
/// @dev Combined Registry, BaseRegistrar and PublicResolver from the official .eth contracts
///
/// ┌──────────────────────────────────────────────────────────────────────────┐
/// │ VENDORED + MODIFIED BY WOCO — this is NOT pristine upstream Durin.       │
/// │                                                                          │
/// │ WoCo additions, all pure additions, nothing upstream removed:            │
/// │   #422 · `adminTransfer(node, newOwner)`  · event `AdminTransfer`        │
/// │        · errors AdminTransferToZero / BaseNode / Unregistered / SameOwner│
/// │   #464 · `release(node)` + `lastRelease[node]` · event `Released`        │
/// │        · errors ReleaseBaseNode / ReleaseUnregistered                    │
/// │        · `totalSupply` now counts LIVE names (decremented on release)    │
/// │                                                                          │
/// │ DO NOT resync this file from upstream without re-applying them. The      │
/// │ tripwires are test/L2RegistryAdminTransfer.t.sol and                     │
/// │ test/L2RegistryRelease.t.sol, which fail to compile if they are dropped —│
/// │ do not delete those files to make a sync pass.                           │
/// │                                                                          │
/// │ This contract is deployed as an EIP-1167 clone and CANNOT be upgraded.   │
/// │ Anything wrong here is permanent from the mainnet deploy onward.         │
/// └──────────────────────────────────────────────────────────────────────────┘
contract L2Registry is ERC721, Initializable, L2Resolver {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The base node for the registry
    /// @dev namehash of `name()`
    bytes32 public baseNode;

    /// @notice Number of names that currently exist, at any depth, including
    ///         the base name.
    /// @dev Upstream only ever incremented this. `release` (#464) decrements it,
    ///      so that it means what its name says rather than "ever minted".
    uint256 public totalSupply;

    string private _tokenName;
    string private _tokenSymbol;
    string private _tokenBaseURI;

    /// @notice Mapping of node (namehash) to name (DNS-encoded)
    mapping(bytes32 node => bytes name) public names;

    /// @notice Mapping of approved registrar controllers
    mapping(address registrar => bool approved) public registrars;

    /// @notice What the registry remembers about a name after `release`
    ///         (WoCo addition, #464). One storage slot.
    struct ReleaseRecord {
        address previousOwner;
        uint64 releasedAt;
    }

    /// @notice The most recent release of each node.
    ///
    /// @dev Written by `release`, read by nothing in this contract, and that is
    ///      deliberate. This registry is an EIP-1167 clone and cannot be
    ///      patched; the registrar that decides mint policy can be replaced at
    ///      will. A policy such as "for N days after a release only the previous
    ///      holder may take the label back" is therefore a registrar concern —
    ///      but it can only ever be enforced ON CHAIN if the frozen layer kept
    ///      the two facts it needs, because `release` is holder-only and never
    ///      passes through a registrar. A burn that forgot who it burned would
    ///      close that door permanently, to save one slot per release.
    ///
    ///      FOOTGUN FOR A FUTURE READER: this record SURVIVES a re-mint of the
    ///      same label, on purpose — it is history, and `createSubnode` is
    ///      upstream code left untouched. "Currently released" is
    ///      `owner(node) == address(0)`; check that first, and read this only
    ///      for who held it last and when they let go.
    mapping(bytes32 node => ReleaseRecord) public lastRelease;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a name is created at any level
    event SubnodeCreated(bytes32 indexed node, bytes name, address owner);

    /// @notice Emitted when a subnode is registered at any level
    /// @dev Same event signature as the ENS Registry
    event NewOwner(
        bytes32 indexed parentNode,
        bytes32 indexed labelhash,
        address owner
    );

    event RegistrarAdded(address registrar);
    event RegistrarRemoved(address registrar);
    event BaseURIUpdated(string baseURI);

    /// @notice A name was reassigned by the registry admin without the holder's
    ///         consent (WoCo addition, #422). Distinct from the ERC-721
    ///         `Transfer` this also emits, so that an admin reassignment is
    ///         legible on chain rather than indistinguishable from a sale.
    event AdminTransfer(
        bytes32 indexed node,
        address indexed previousOwner,
        address indexed newOwner
    );

    /// @notice A name was given back by its holder (WoCo addition, #464).
    ///         `operator` is the account that sent the transaction: the holder
    ///         themselves, or an ERC-721 approvee acting for them. Kept apart
    ///         from `previousOwner` so a dispute can tell the two cases apart.
    event Released(
        bytes32 indexed node,
        address indexed previousOwner,
        address indexed operator
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error LabelTooShort();
    error LabelTooLong(string label);
    error NotAvailable(string label, bytes32 parentNode);
    error AdminTransferToZero();
    error AdminTransferBaseNode();
    error AdminTransferUnregistered(bytes32 node);
    error AdminTransferSameOwner();
    error ReleaseBaseNode();
    error ReleaseUnregistered(bytes32 node);

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Only the owner of the node or a registrar can call the function
    modifier onlyOwnerOrRegistrar(bytes32 node) {
        if (owner(node) != msg.sender && !registrars[msg.sender]) {
            revert Unauthorized(node);
        }
        _;
    }

    modifier onlyOwner() {
        if (owner() != msg.sender) {
            revert Unauthorized(baseNode);
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() ERC721("", "") {
        _disableInitializers();
    }

    /// @notice Initializes the registry
    /// @param tokenName The parent ENS name, and name of the NFT collection
    /// @param tokenSymbol The symbol of the NFT collection
    /// @param baseURI The base URI of the NFT collection
    /// @param admin The address that will be granted admin role
    function initialize(
        string calldata tokenName,
        string calldata tokenSymbol,
        string calldata baseURI,
        address admin
    ) external initializer {
        (bytes memory dnsEncodedName, bytes32 node) = NameEncoder.dnsEncodeName(
            tokenName
        );

        // ERC721
        _tokenName = tokenName;
        _tokenSymbol = tokenSymbol;
        _setBaseURI(baseURI);

        // Registry
        baseNode = node;
        names[baseNode] = dnsEncodedName;
        _safeMint(admin, uint256(node));
        totalSupply++;
    }

    /*//////////////////////////////////////////////////////////////
                            PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a subnode from a parent node and label
    /// @dev Only callable by the owner of the parent node
    /// @param node The parent node, e.g. `namehash("name.eth")` for "name.eth"
    /// @param label The label of the subnode, e.g. "x" for "x.name.eth"
    /// @param _owner The address that will own the subnode
    /// @param data The encoded calldata for resolver setters
    /// @return The resulting subnode, e.g. `namehash("x.name.eth")` for "x.name.eth"
    function createSubnode(
        bytes32 node,
        string calldata label,
        address _owner,
        bytes[] calldata data
    ) external onlyOwnerOrRegistrar(node) returns (bytes32) {
        bytes32 subnode = makeNode(node, label);
        bytes32 labelhash = keccak256(bytes(label));
        bytes memory dnsEncodedName = _addLabel(label, names[node]);

        if (owner(subnode) != address(0)) {
            revert NotAvailable(label, node);
        }

        _safeMint(_owner, uint256(subnode));
        _multicall(subnode, data);
        names[subnode] = dnsEncodedName;
        totalSupply++;

        emit NewOwner(node, labelhash, _owner);
        emit SubnodeCreated(subnode, dnsEncodedName, _owner);
        return subnode;
    }

    /// @notice Helper to derive a node from a name
    /// @dev In practice, this should be performed offchain
    function namehash(string calldata _name) external pure returns (bytes32) {
        (, bytes32 node) = NameEncoder.dnsEncodeName(_name);
        return node;
    }

    /// @notice Helper to decode a DNS-encoded name
    /// @dev In practice, this should be performed offchain
    function decodeName(
        bytes calldata _name
    ) external pure returns (string memory) {
        return ENSDNSUtils.dnsDecode(_name);
    }

    /// @notice Helper to derive a node from a parent node and label
    /// @param parentNode The namehash of the parent, e.g. `namehash("name.eth")` for "name.eth"
    /// @param label The label of the subnode, e.g. "x" for "x.name.eth"
    /// @return The resulting subnode, e.g. `namehash("x.name.eth")` for "x.name.eth"
    function makeNode(
        bytes32 parentNode,
        string calldata label
    ) public pure returns (bytes32) {
        bytes32 labelhash = keccak256(bytes(label));
        return keccak256(abi.encodePacked(parentNode, labelhash));
    }

    /// @notice The admin of the registry
    function owner() public view returns (address) {
        return owner(baseNode);
    }

    /// @notice Returns the address that owns the specified node
    /// @dev We need this because `ERC721.ownerOf()` reverts if the token doesn't exist
    function owner(bytes32 node) public view returns (address) {
        return _ownerOf(uint256(node));
    }

    /// @notice The name of the NFT collection and base ENS name
    function name() public view override returns (string memory) {
        return _tokenName;
    }

    /// @notice The symbol of the NFT collection
    function symbol() public view override returns (string memory) {
        return _tokenSymbol;
    }

    /// @notice The base URI for NFT metadata
    function _baseURI() internal view override returns (string memory) {
        return _tokenBaseURI;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Adds a new registrar address
    /// @param registrar The address to grant registrar role to
    /// @dev Only callable by admin role
    function addRegistrar(address registrar) external onlyOwner {
        registrars[registrar] = true;
        emit RegistrarAdded(registrar);
    }

    /// @notice Removes a registrar address
    /// @param registrar The address to revoke registrar role from
    /// @dev Only callable by admin role
    function removeRegistrar(address registrar) external onlyOwner {
        registrars[registrar] = false;
        emit RegistrarRemoved(registrar);
    }

    /// @notice Sets the base URI for token metadata
    /// @param baseURI The new base URI
    /// @dev Only callable by admin role
    function setBaseURI(string calldata baseURI) external onlyOwner {
        _setBaseURI(baseURI);
    }

    /// @notice Reassign a name to a new owner, without the current owner's consent.
    ///
    /// @dev WoCo addition to the vendored Durin registry (WoCo-Event-App #422).
    ///      Upstream has no reclaim, no burn and no admin transfer, and the
    ///      registry is deployed as an EIP-1167 clone which cannot be upgraded —
    ///      so this had to exist before the mainnet deploy or never.
    ///
    ///      WHY TRANSFER AND NOT BURN: `createSubnode` reverts `NotAvailable`
    ///      for a node that already has an owner, so burning would strand the
    ///      name permanently and could never be reissued. The motivating case
    ///      (a label infringing a venue or brand) is only resolved by the name
    ///      reaching its rightful holder, which requires a transfer.
    ///
    ///      SCOPE, deliberately narrow. This does NOT let the admin mint over an
    ///      existing name, forge records as a third party, or bypass
    ///      `NotAvailable`. It moves one token and clears its records.
    ///
    ///      Records are cleared by bumping the node's resolver record version,
    ///      so the name stops resolving to the previous holder's site in the
    ///      same transaction. Without it a reassigned name keeps serving the
    ///      old contenthash until someone sends a second transaction — which
    ///      for the abuse cases this exists for is the whole point.
    ///      `clearRecords` itself is `authorised(node)` and so is not callable
    ///      by the admin for a node it does not own; the version counter is
    ///      inherited state and is incremented directly.
    ///
    ///      NO TIMELOCK (owner decision, 2026-08-29): the check on this power is
    ///      that `owner()` is the holder of `baseNode`, intended to be a DAO
    ///      multisig, plus the event trail below. A compromised admin key can
    ///      take names; that is the accepted cost of the power existing at all,
    ///      and it is why this must not sit on the hot sponsor key.
    ///
    /// @param node     The namehash of the name to reassign.
    /// @param newOwner The address that will own it. Cannot be the zero address —
    ///                 use of this function to burn is deliberately not possible.
    function adminTransfer(bytes32 node, address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert AdminTransferToZero();
        // Rotating registry admin means moving `baseNode`, which is an ordinary
        // ERC-721 transfer by its holder. Routing it through the abuse path
        // would let one call hand over the whole registry.
        if (node == baseNode) revert AdminTransferBaseNode();

        address previousOwner = owner(node);
        if (previousOwner == address(0)) revert AdminTransferUnregistered(node);
        // `_transfer` permits `from == to`. Without this guard, calling with the
        // CURRENT owner would move nothing yet still bump the record version —
        // a wipe-in-place, which is functionally the suspend/takedown power this
        // design deliberately excluded in favour of transfer-only. It has no
        // legitimate transfer use, and this contract cannot be patched after the
        // clone deploy, so it is refused here rather than left as latitude.
        if (newOwner == previousOwner) revert AdminTransferSameOwner();

        _transfer(previousOwner, newOwner, uint256(node));

        recordVersions[node]++;
        emit VersionChanged(node, recordVersions[node]);

        emit AdminTransfer(node, previousOwner, newOwner);
    }

    /*//////////////////////////////////////////////////////////////
                            HOLDER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Give a name back. Burns the token, wipes its records, and
    ///         remembers who let go of it and when. Afterwards the label is
    ///         available to anyone through the ordinary mint path.
    ///
    /// @dev WoCo addition to the vendored Durin registry (WoCo-Event-App #464).
    ///      Upstream has no burn: `transferFrom` refuses the zero address and
    ///      `adminTransfer` does so by design, so without this a name could
    ///      only ever change hands, never return to the pool — and since the
    ///      registry is an unpatchable clone, that had to be decided before the
    ///      mainnet deploy or never.
    ///
    ///      WHO MAY CALL IT: the holder, or an address the holder has approved
    ///      under ERC-721 — the same set that may transfer the token, checked
    ///      by the same OpenZeppelin predicate. NOT registrars and NOT the
    ///      registry admin: this function adds no platform power. The admin
    ///      already has `adminTransfer`; a platform-side burn would be the
    ///      takedown capability that design deliberately excluded.
    ///
    ///      WHY BURN RATHER THAN PARK: availability throughout this contract and
    ///      the registrar is exactly `owner(node) == address(0)`, so a burn makes
    ///      `createSubnode` and `available()` re-issue the label with no change
    ///      to either. Parking the token anywhere would have needed a second
    ///      mint path in the frozen layer.
    ///
    ///      WHY THE RECORD VERSION IS BUMPED HERE: `createSubnode` does not bump
    ///      it, so without this the next holder of the label would inherit the
    ///      previous holder's records — an `addr(60)` that is also a payment
    ///      alias, text records, a contenthash — until each was overwritten.
    ///      The same mechanism `adminTransfer` uses, for the same reason.
    ///
    ///      WHY `names[node]` IS LEFT IN PLACE: it is only read by `tokenURI`,
    ///      which refuses a burned token first, and by `createSubnode` for the
    ///      PARENT of a new name — and a re-mint of this label writes the same
    ///      bytes back. Clearing it would erase the only on-chain map from a
    ///      released node to its label, for a gas refund nobody needs.
    ///
    ///      RESIDUAL, stated so it is not rediscovered: names BENEATH a released
    ///      name are untouched. They keep their own holders and their own
    ///      records, and resolve exactly as before; what the next holder of the
    ///      parent gains is the ability to create NEW children beside them, not
    ///      control of the existing ones. The registry cannot enumerate
    ///      children, so this cannot be refused here; policy has to say it.
    ///
    /// @param node The namehash of the name to release.
    function release(bytes32 node) external {
        // The base name IS the registry: `owner()` is whoever holds it. Burning
        // it would leave no admin, forever.
        if (node == baseNode) revert ReleaseBaseNode();

        address holder = owner(node);
        if (holder == address(0)) revert ReleaseUnregistered(node);
        if (!_isAuthorized(holder, msg.sender, uint256(node))) {
            revert Unauthorized(node);
        }

        _burn(uint256(node));
        totalSupply--;

        recordVersions[node]++;
        emit VersionChanged(node, recordVersions[node]);

        lastRelease[node] = ReleaseRecord({
            previousOwner: holder,
            releasedAt: uint64(block.timestamp)
        });

        emit Released(node, holder, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _setBaseURI(string calldata baseURI) private {
        _tokenBaseURI = baseURI;
        emit BaseURIUpdated(baseURI);
    }

    function _addLabel(
        string memory label,
        bytes memory _name
    ) private pure returns (bytes memory ret) {
        if (bytes(label).length < 1) {
            revert LabelTooShort();
        }
        if (bytes(label).length > 255) {
            revert LabelTooLong(label);
        }
        return abi.encodePacked(uint8(bytes(label).length), label, _name);
    }

    /*//////////////////////////////////////////////////////////////
                               OVERRIDES
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns onchain JSON if no baseURI is set
    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        if (bytes(_tokenBaseURI).length == 0) {
            _requireOwned(tokenId);

            string memory json = string.concat(
                '{"name": "',
                ENSDNSUtils.dnsDecode(names[bytes32(tokenId)]),
                '"}'
            );

            return
                string.concat(
                    "data:application/json;base64,",
                    Base64.encode(bytes(json))
                );
        }

        return super.tokenURI(tokenId);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, L2Resolver) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
