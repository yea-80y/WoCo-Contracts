// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ***********************************************
// ▗▖  ▗▖ ▗▄▖ ▗▖  ▗▖▗▄▄▄▖ ▗▄▄▖▗▄▄▄▖▗▄▖ ▗▖  ▗▖▗▄▄▄▖
// ▐▛▚▖▐▌▐▌ ▐▌▐▛▚▞▜▌▐▌   ▐▌     █ ▐▌ ▐▌▐▛▚▖▐▌▐▌
// ▐▌ ▝▜▌▐▛▀▜▌▐▌  ▐▌▐▛▀▀▘ ▝▀▚▖  █ ▐▌ ▐▌▐▌ ▝▜▌▐▛▀▀▘
// ▐▌  ▐▌▐▌ ▐▌▐▌  ▐▌▐▙▄▄▖▗▄▄▞▘  █ ▝▚▄▞▘▐▌  ▐▌▐▙▄▄▖
// ***********************************************

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";

import {ENSDNSUtils} from "./lib/ENSDNSUtils.sol";
import {IUniversalSignatureValidator} from "./interfaces/IUniversalSignatureValidator.sol";
import {L2Resolver} from "./L2Resolver.sol";

/// @title Durin Registry
/// @author NameStone
/// @notice Manages ENS subname registration and management on L2
/// @dev Combined Registry, BaseRegistrar and PublicResolver from the official .eth contracts
///
/// VENDORED + MODIFIED BY WOCO. This is NOT pristine upstream Durin; do not
/// resync it from upstream.
///
/// WoCo additions carried from v1:
///   #422  `adminTransfer` · event `AdminTransfer`
///   #464  `release`, `releaseWithSignature`, `releaseDigest`, `lastRelease` ·
///         event `Released` · `totalSupply` counts live names
///
/// v2 (WoCo-Contracts #21, after audits 924 and 927):
///   - ONE rule for who may write records, `_canWriteRecords`; the signed
///     record setters are gone from `L2Resolver`.
///   - A name's records reset on EVERY ownership change, in `_update`.
///   - The base name, which is the admin seat, moves only through
///     `nominateAdmin` + `acceptAdmin`.
///   - `_mint`, never `_safeMint`: nothing is called on a recipient.
///   - Labels are 1..63 bytes with no '.', '"', '\' or control bytes, and a
///     whole name is at most 255 bytes.
///   - A registrar creates names beneath the base name only.
///   - `clearRecords` belongs to the holder's side only.
///   - `releaseWithSignature` checks plain ECDSA before the ERC-6492 validator.
///   - `addRegistrar(address(0))` is refused.
///
/// The tests that freeze these are the L2Registry*.t.sol suites and
/// SubEnsV2AuditRegression.t.sol. This contract is deployed as an EIP-1167
/// clone and CANNOT be upgraded: anything wrong here is permanent.
contract L2Registry is ERC721, Initializable, L2Resolver {
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Domain tag of the message `releaseWithSignature` verifies (WoCo
    ///         addition, #464). Named fields, so a client can rebuild the
    ///         digest — but `releaseDigest` is the reference and clients should
    ///         read it rather than re-derive it.
    bytes32 public constant RELEASE_TYPEHASH = keccak256(
        "WoCoRelease(address registry,uint256 chainId,bytes32 node,uint64 recordVersion,uint256 expiration)"
    );

    /// @dev The DNS limits (RFC 1035 §2.3.4), in wire format: 63 bytes per
    ///      label, and 255 for a whole name counting its length bytes and the
    ///      terminating zero. The CCIP-Read gateway refuses a name past either,
    ///      so a name this contract let past them would mint and never resolve.
    uint256 private constant MAX_LABEL_BYTES = 63;
    uint256 private constant MAX_NAME_BYTES = 255;

    /// @dev ERC-6492 validator: ERC-1271 for deployed contract accounts, and a
    ///      counterfactual deployment for undeployed ones. Consulted only by
    ///      `releaseWithSignature`, and only for a signature that does not
    ///      already recover to its signer as plain ECDSA.
    IUniversalSignatureValidator internal immutable universalSignatureValidator =
        IUniversalSignatureValidator(0x164af34fAF9879394370C7f09064127C043A35E9);

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
    ///      same label, on purpose — it is history. "Currently released" is
    ///      `owner(node) == address(0)`; check that first, and read this only
    ///      for who held it last and when they let go.
    mapping(bytes32 node => ReleaseRecord) public lastRelease;

    /// @notice The address the admin has nominated to take the admin seat, or
    ///         zero when no handover is open. See `nominateAdmin`.
    address public pendingAdmin;

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
    ///         `operator` is the account that AUTHORISED it — the holder, or an
    ///         ERC-721 approvee acting for them: `msg.sender` under `release`,
    ///         the signer under `releaseWithSignature`. Kept apart from
    ///         `previousOwner` so a dispute can tell the two cases apart. The
    ///         relayer that merely paid for a signed release is on the
    ///         transaction, deliberately not here: this event answers "who let
    ///         go", and a relayer never did.
    event Released(
        bytes32 indexed node,
        address indexed previousOwner,
        address indexed operator
    );

    /// @notice The admin opened a handover of the admin seat to `nominee`, or
    ///         cancelled an open one (`nominee` is zero).
    event AdminNominated(address indexed admin, address indexed nominee);

    /// @notice `newAdmin` accepted the admin seat from `previousAdmin`.
    event AdminAccepted(address indexed previousAdmin, address indexed newAdmin);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error LabelTooShort();
    error LabelTooLong(string label);
    error LabelInvalidCharacter(string label);
    error NameTooLong(string label);
    error NotAvailable(string label, bytes32 parentNode);
    error RegistrarIsZeroAddress();
    error AdminTransferToZero();
    error AdminTransferBaseNode();
    error AdminTransferUnregistered(bytes32 node);
    error AdminTransferSameOwner();
    error AdminHandoverRequired();
    error NomineeIsAdmin();
    error NotPendingAdmin(address caller);
    error ReleaseBaseNode();
    error ReleaseUnregistered(bytes32 node);
    error SignatureExpired();

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (owner() != msg.sender) {
            revert Unauthorized(baseNode);
        }
        _;
    }

    modifier unexpiredSignature(uint256 expiration) {
        if (block.timestamp > expiration) {
            revert SignatureExpired();
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
    /// @dev Must run in the transaction that creates the clone — see
    ///      `WoCoSubEnsDeployer`. Until it runs, anyone can call it, and whoever
    ///      does takes the admin seat.
    ///
    ///      `_mint`, not `_safeMint`: `admin` is a multisig or a DAO, and the
    ///      admin seat must not depend on it answering an ERC-721 receiver hook.
    /// @param tokenName The parent ENS name, and name of the NFT collection
    /// @param tokenSymbol The symbol of the NFT collection
    /// @param baseURI The base URI of the NFT collection
    /// @param admin The address that will hold the admin seat (the base name)
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
        totalSupply++;
        _mint(admin, uint256(node));
    }

    /*//////////////////////////////////////////////////////////////
                            PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a subnode from a parent node and label
    /// @dev WHO MAY CALL IT. The parent's holder, for any name it holds; a
    ///      registrar, beneath the base name only. v1 let a registrar name any
    ///      parent, including one never minted, whose child then carried an
    ///      undecodable name (audit 924 F-8).
    ///
    ///      ORDER. `names` and `totalSupply` are written before the mint, and the
    ///      mint is `_mint`, which calls nothing on the recipient. v1's
    ///      `_safeMint` handed a contract recipient control mid-mint: releasing
    ///      the name from there made the registrar's record writes land on a
    ///      freed label, where the next registrant found them (audit 927 H3). A
    ///      receiver check protects a sender from its own mistake; here the
    ///      platform chooses the recipient, and `adminTransfer` is the recovery.
    ///
    ///      The new name starts with empty records: the mint is an ownership
    ///      change, and `_update` gives it a fresh record version.
    /// @param node The parent node, e.g. `namehash("name.eth")` for "name.eth"
    /// @param label The label of the subnode, e.g. "x" for "x.name.eth"
    /// @param _owner The address that will own the subnode
    /// @param data The encoded calldata for resolver setters, run after the mint
    ///             with the caller's own record authority
    /// @return The resulting subnode, e.g. `namehash("x.name.eth")` for "x.name.eth"
    function createSubnode(
        bytes32 node,
        string calldata label,
        address _owner,
        bytes[] calldata data
    ) external returns (bytes32) {
        if (owner(node) != msg.sender && !(node == baseNode && registrars[msg.sender])) {
            revert Unauthorized(node);
        }

        bytes32 subnode = makeNode(node, label);
        bytes32 labelhash = keccak256(bytes(label));
        bytes memory dnsEncodedName = _addLabel(label, names[node]);

        if (owner(subnode) != address(0)) {
            revert NotAvailable(label, node);
        }

        names[subnode] = dnsEncodedName;
        totalSupply++;
        _mint(_owner, uint256(subnode));
        _multicall(subnode, data);

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

    /// @notice The admin of the registry: the holder of the base name
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
    /// @dev Only callable by admin role. A registrar may create names beneath
    ///      the base name and write the records of every name that exists; see
    ///      `_canWriteRecords`. The zero address is refused: no transaction can
    ///      come from it, so enrolling it could only ever make an authorisation
    ///      check that is handed an unset address succeed — the shape of the v1
    ///      defect (audit 924 F-1, F-18).
    /// @param registrar The address to grant registrar role to
    function addRegistrar(address registrar) external onlyOwner {
        if (registrar == address(0)) revert RegistrarIsZeroAddress();
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

    /// @notice Start handing the admin seat to `nominee`, who must call
    ///         `acceptAdmin` to take it. Nominating the zero address cancels an
    ///         open handover; nominating again replaces it.
    ///
    /// @dev The admin seat IS the base name's token: `owner()` is its holder. v1
    ///      moved it with an ordinary ERC-721 transfer, so one wrong address — or
    ///      an operator-for-all the holder had once approved (audit 924 F-2) —
    ///      handed over the whole registry in a single call, with no way back.
    ///      `_update` now refuses every move of the base name except the one
    ///      `acceptAdmin` makes, and only the address nominated here can make it,
    ///      so the seat only ever reaches an address that has shown it can
    ///      transact. This is how a DAO takes the seat from the Safe.
    ///
    ///      The current admin is refused as a nominee: accepting would move
    ///      nothing, reset the base name's records, and log a handover that did
    ///      not happen.
    /// @param nominee The address that may accept the seat.
    function nominateAdmin(address nominee) external onlyOwner {
        if (nominee == msg.sender) revert NomineeIsAdmin();
        pendingAdmin = nominee;
        emit AdminNominated(msg.sender, nominee);
    }

    /// @notice Take the admin seat. Callable only by the nominee.
    /// @dev Moves the base name through the same bookkeeping as every other
    ///      ownership change, `_updateAndBumpVersion`, so the base name's own
    ///      records reset like any name's. It skips only `_update`'s refusal,
    ///      which exists to make this the one way in.
    ///
    ///      With no handover open, `pendingAdmin` is zero, and zero is refused
    ///      outright rather than left to "no transaction comes from the zero
    ///      address": if one ever did, the move below would be a burn of the
    ///      admin seat.
    function acceptAdmin() external {
        address nominee = pendingAdmin;
        if (nominee == address(0) || msg.sender != nominee) revert NotPendingAdmin(msg.sender);

        address previousAdmin = owner();
        delete pendingAdmin;
        _updateAndBumpVersion(nominee, uint256(baseNode), address(0));

        emit AdminAccepted(previousAdmin, nominee);
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
    ///      WHAT IT DOES. It moves one token. Like every ownership change, the
    ///      move resets the name's records (`_update`), so the name stops
    ///      resolving to the previous holder's site in the same transaction. It
    ///      cannot mint over a live name, bypass `NotAvailable`, or move the base
    ///      name, which changes hands only through `nominateAdmin`.
    ///
    ///      WHAT THE ADMIN SEAT CAN DO WITHOUT IT, stated so no policy claims
    ///      more than this contract delivers: rewrite any name's records while
    ///      leaving it where it is. The seat may enrol itself, or any address,
    ///      with `addRegistrar`, and a registrar may write the records of every
    ///      name that exists. Owner decision 2026-09-14: accepted. The check on
    ///      that power is who holds the seat — the Safe now, a DAO later through
    ///      `nominateAdmin` / `acceptAdmin` — together with `RegistrarAdded`,
    ///      which puts every enrolment on chain. There is no per-name manager
    ///      that bounds it, and this contract cannot gain one.
    ///
    ///      NO TIMELOCK (owner decision, 2026-08-29): a compromised admin seat
    ///      can take names; that is the accepted cost of the power existing at
    ///      all, and it is why the seat must never be the hot sponsor key.
    ///
    /// @param node     The namehash of the name to reassign.
    /// @param newOwner The address that will own it. Cannot be the zero address —
    ///                 use of this function to burn is deliberately not possible.
    function adminTransfer(bytes32 node, address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert AdminTransferToZero();
        // Named here, although `_update` would refuse it too, so the admin is
        // told which door to use.
        if (node == baseNode) revert AdminTransferBaseNode();

        address previousOwner = owner(node);
        if (previousOwner == address(0)) revert AdminTransferUnregistered(node);
        // `_transfer` permits `from == to`, which would move nothing yet reset
        // the name's records: a one-call wipe-in-place with no transfer use.
        if (newOwner == previousOwner) revert AdminTransferSameOwner();

        _transfer(previousOwner, newOwner, uint256(node));

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
    ///      RECORDS: the burn is an ownership change, so `_update` resets the
    ///      name's records in the same transaction, and whoever mints the label
    ///      next starts from empty records.
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

        _release(node, holder, msg.sender);
    }

    /// @notice The exact 32 bytes a holder signs to authorise `releaseWithSignature`
    ///         for `node` until `expiration`. EIP-191 personal-sign shape, so a
    ///         plain wallet signs it with `personal_sign` and a contract wallet
    ///         answers for it through ERC-1271 / ERC-6492.
    ///
    /// @dev Everything that makes the signature single-purpose is in here:
    ///      `RELEASE_TYPEHASH`, so no other message a holder signs hashes to it;
    ///      `address(this)` + `block.chainid`, so neither another registry nor
    ///      this registry's address on another chain accepts it; and
    ///      `recordVersions[node]`, which moves on every ownership change of the
    ///      name and on `clearRecords`. One signature therefore releases at most
    ///      once, and dies the moment the name changes hands — including a
    ///      re-mint of the same label to the same holder.
    function releaseDigest(bytes32 node, uint256 expiration) public view returns (bytes32) {
        return keccak256(
            abi.encode(RELEASE_TYPEHASH, address(this), block.chainid, node, recordVersions[node], expiration)
        ).toEthSignedMessageHash();
    }

    /// @notice `release`, authorised by a signature instead of by `msg.sender`,
    ///         so that whoever submits the transaction need not be the holder.
    ///
    /// @dev WoCo addition (WoCo-Event-App #464, decided 2026-09-03). WHY IT
    ///      EXISTS: `release` is holder-only by `msg.sender`, which means a
    ///      holder with a plain wallet pays gas for it and a holder with no gas
    ///      at all cannot release. A paymaster solves that only for smart
    ///      accounts. This function is the same burn, gated on the holder's
    ///      SIGNATURE, so the platform (or anyone) can submit it and pay.
    ///
    ///      WHAT IT DOES NOT ADD: platform power. The relayer submits only what
    ///      the holder signed, for the node and the deadline the holder chose,
    ///      and can refuse to relay but never forge; the holder can always call
    ///      `release` directly instead. The same OpenZeppelin predicate as
    ///      `release` decides WHO may sign — the holder or an ERC-721 approvee —
    ///      and it is checked BEFORE the signature is examined, so a stranger's
    ///      perfectly valid signature is refused without reaching the validator
    ///      (which, for an ERC-6492 wrapper, would deploy the signer's account).
    ///
    ///      HOW THE SIGNATURE IS CHECKED. Plain ECDSA first: if `signature`
    ///      recovers to `signer`, the key behind `signer` signed, and the
    ///      validator is not consulted. `signer` is non-zero here, because
    ///      `_isAuthorized` refuses the zero address, so a failed recovery —
    ///      which yields the zero address — can never match it. Otherwise the
    ///      ERC-6492 validator decides: ERC-1271 for a deployed contract
    ///      account, a counterfactual deployment for an undeployed one.
    ///
    ///      The order matters for an EOA with an EIP-7702 delegation. It has
    ///      code, so the validator asks its delegate through ERC-1271, and a
    ///      delegate need not accept a raw signature from the account's own key
    ///      — which pushed exactly those holders onto an own-gas `release`
    ///      (audit 924 F-11). Accepting the key's signature grants nothing new:
    ///      the key can always transact from the account, or re-delegate it. A
    ///      contract account has no key that recovers to its address, so it
    ///      still goes through ERC-1271.
    ///
    ///      The message is `releaseDigest(node, expiration)`; see there for why
    ///      it can be used once, here, and for nothing else.
    ///
    /// @param node       The namehash of the name to release.
    /// @param expiration Unix seconds; the signature is void after it.
    /// @param signer     Who signed: the holder or an approvee.
    /// @param signature  Their signature over `releaseDigest(node, expiration)`.
    function releaseWithSignature(
        bytes32 node,
        uint256 expiration,
        address signer,
        bytes calldata signature
    ) external unexpiredSignature(expiration) {
        if (node == baseNode) revert ReleaseBaseNode();

        address holder = owner(node);
        if (holder == address(0)) revert ReleaseUnregistered(node);
        if (!_isAuthorized(holder, signer, uint256(node))) {
            revert Unauthorized(node);
        }

        bytes32 digest = releaseDigest(node, expiration);
        (address recovered, , ) = ECDSA.tryRecoverCalldata(digest, signature);
        if (recovered != signer && !universalSignatureValidator.isValidSig(signer, digest, signature)) {
            revert Unauthorized(node);
        }

        _release(node, holder, signer);
    }

    /// @notice Wipe `node`'s records by moving it to a fresh record version.
    /// @dev The holder's side only: the holder, its per-token approvee, or its
    ///      operator-for-all — the addresses that could already release or
    ///      transfer the name, which would reset its records anyway.
    ///
    ///      Registrars, and the registry admin enrolled as one, are refused. No
    ///      registrar flow needs this now that every ownership change resets
    ///      records in `_update`, and in v1 it was the second step of the
    ///      admin's wipe-in-place (audit 927 H1).
    ///
    ///      The inherited body still runs its own `authorised` check, which the
    ///      holder's side always passes. Moving the version also voids any
    ///      outstanding `releaseDigest` signature for the name.
    function clearRecords(bytes32 node) public override {
        if (!_isAuthorized(owner(node), msg.sender, uint256(node))) {
            revert Unauthorized(node);
        }
        super.clearRecords(node);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev ONE rule for who may write a name's records. The name must exist,
    ///      and the writer must be:
    ///        - a registrar; or
    ///        - someone who may act for the holder under ERC-721 — the holder,
    ///          its per-token approvee, or its operator-for-all. That is
    ///          OpenZeppelin's `_isAuthorized`, the predicate `release` uses.
    ///
    ///      `_isAuthorized` refuses the zero address outright, which is what the
    ///      v1 check failed to do (audit 924 F-1). It also extends record
    ///      authority to operators-for-all, as the ENS PublicResolver does; an
    ///      operator can already transfer or release the name.
    ///
    ///      Existence is required of registrars too, so nothing can be written to
    ///      a label before it is minted and reach its first holder (audit 927
    ///      H2 / 924 F-3); `_updateAndBumpVersion` covers every later holder.
    ///
    ///      The registry admin needs no branch here: it can enrol itself with
    ///      `addRegistrar`. That is accepted; see `adminTransfer`.
    function _canWriteRecords(address writer, bytes32 node) internal view override returns (bool) {
        address holder = _ownerOf(uint256(node));
        return holder != address(0) && (registrars[writer] || _isAuthorized(holder, writer, uint256(node)));
    }

    /// @dev Every change of a name's owner comes through here — `_mint`,
    ///      `transferFrom` / `safeTransferFrom`, `adminTransfer`'s `_transfer`,
    ///      `release`'s `_burn` — except `acceptAdmin`, which enters one step
    ///      further in. Refuses to move an existing base name; see `nominateAdmin`.
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        if (bytes32(tokenId) == baseNode && _ownerOf(tokenId) != address(0)) {
            revert AdminHandoverRequired();
        }
        return _updateAndBumpVersion(to, tokenId, auth);
    }

    /// @dev The one place an ownership change moves a record version. Records
    ///      are stored per version, so moving it makes every record of the
    ///      previous holding unreadable at once.
    ///
    ///      WHY HERE AND NOT IN EACH CALLER: v1 bumped in `release` and
    ///      `adminTransfer` only. A mint did not, so records written to a label
    ///      before or during its mint reached the new holder (audit 924 F-3 /
    ///      927 H2, H3), and a plain transfer did not, so a buyer received the
    ///      seller's records (924 F-5) and the seller's outstanding release
    ///      signature. A path added later cannot forget a bump that no path
    ///      performs itself.
    function _updateAndBumpVersion(address to, uint256 tokenId, address auth) private returns (address from) {
        from = super._update(to, tokenId, auth);

        bytes32 node = bytes32(tokenId);
        recordVersions[node]++;
        emit VersionChanged(node, recordVersions[node]);
    }

    /// @dev The burn both release paths share. Callers have already decided
    ///      that `holder` owns `node` and that `operator` may act for them.
    function _release(bytes32 node, address holder, address operator) internal {
        _burn(uint256(node));
        totalSupply--;

        lastRelease[node] = ReleaseRecord({
            previousOwner: holder,
            releasedAt: uint64(block.timestamp)
        });

        emit Released(node, holder, operator);
    }

    function _setBaseURI(string calldata baseURI) private {
        _tokenBaseURI = baseURI;
        emit BaseURIUpdated(baseURI);
    }

    /// @dev The label rules every consumer of a name depends on. Case, unicode
    ///      and minimum length stay registrar policy.
    ///        - 1..63 bytes, and at most 255 for the whole wire-format name: the
    ///          DNS limits the gateway enforces (audit 924 F-14).
    ///        - No '.': the name would decode with one label more than the node
    ///          was hashed from, so it would not namehash to its own node.
    ///        - No '"', '\' or bytes below 0x20: `tokenURI` builds JSON by
    ///          concatenation, and these are exactly the characters JSON
    ///          requires escaped (924 F-15).
    function _addLabel(
        string memory label,
        bytes memory _name
    ) private pure returns (bytes memory ret) {
        bytes memory b = bytes(label);
        if (b.length < 1) {
            revert LabelTooShort();
        }
        if (b.length > MAX_LABEL_BYTES) {
            revert LabelTooLong(label);
        }
        for (uint256 i; i < b.length; ++i) {
            bytes1 c = b[i];
            // 0x2e '.', 0x22 '"', 0x5c '\'
            if (c < 0x20 || c == 0x2e || c == 0x22 || c == 0x5c) {
                revert LabelInvalidCharacter(label);
            }
        }
        ret = abi.encodePacked(uint8(b.length), label, _name);
        if (ret.length > MAX_NAME_BYTES) {
            revert NameTooLong(label);
        }
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
