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
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

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
///   - `releaseWithSignature` checks plain ECDSA before the ERC-6492 validator.
///   - `addRegistrar(address(0))` is refused.
///
/// v2.1 (after audits 937 and 938):
///   - A name's records, `clearRecords` and `release` belong to its HOLDER. A
///     move to the holder itself changes nothing of this registry's own
///     (948 / 949).
///   - The base name's records are written by its holder only, never by a
///     registrar.
///   - Every name records the name above it (`parentOf`) and counts the live
///     names directly beneath it (`childCount`). A name with children cannot
///     be released. The holder of a name may move (`parentTransfer`) or
///     release the names directly beneath it, one level at a time; beneath
///     the base name that door is the admin's `adminTransfer` instead.
///     `adminTransfer` is never blocked by what hangs beneath a name.
///   - `createSubnode` refuses to finish if its own batch moved the new name.
///   - Release signatures are EIP-712 typed data and expire within
///     `MAX_RELEASE_SIGNATURE_TTL`; the validator runs with bounded gas and
///     its failure is a refusal.
///   - No name is ever sent to the registry itself.
///   - `initialize` holds the base name to the same label rules as any other.
///   - `ABI` answers for every `contentTypes` (`L2Resolver`).
///
/// v2.2 (after audit 950; Fable design consult, Branch A):
///   - No ERC-721 delegation. `approve` and `setApprovalForAll` revert
///     `DelegationNotSupported`, and only the holder moves a name. v2.1 said
///     an approval moved the token and did nothing else; that could never
///     hold, because moving the token to oneself IS every holder power here.
///   - No public `multicall` (`L2Resolver`). `createSubnode`'s batch is
///     internal, node-checked, and fails with its inner reason.
///   - A registrar grant lasts only as long as the admin seat that made it:
///     `acceptAdmin` drops every registrar, WoCoRegistrar included.
///   - Only one word of the ERC-6492 validator's answer is ever copied.
///   - Only the contract that created the implementation may initialise a
///     clone of it.
///
/// The tests that freeze these are the L2Registry*.t.sol suites and the
/// SubEnsV2*Audit*Regression.t.sol files. This
/// contract is deployed as an EIP-1167 clone and CANNOT be upgraded: anything
/// wrong here is permanent.
contract L2Registry is ERC721, EIP712, Initializable, L2Resolver {
    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice EIP-712 type of the message `releaseWithSignature` verifies.
    ///         `name` is the whole name as a wallet should show it, e.g.
    ///         "alice.woco.eth"; the registry and the chain are in the domain
    ///         ("WoCo Names", version "2").
    bytes32 public constant RELEASE_TYPEHASH =
        keccak256("Release(string name,bytes32 node,uint64 recordVersion,uint256 expiration)");

    /// @notice The furthest ahead of the submitting block a release signature
    ///         may expire.
    /// @dev WHAT IT BOUNDS, exactly: a signature is never ACCEPTED more than
    ///      this long before its expiration. It does not bound a signature's
    ///      age — no contract can know when a signature was made — so one
    ///      signed with an expiration years ahead is refused until the last
    ///      48 hours before it, and accepted then (audit 950 Low 4). What ends
    ///      a signature early is the record version it names: any change of
    ///      holder, and the holder's own `clearRecords`, void it. A ceiling,
    ///      not the product's policy: WoCo's relay accepts 15 minutes and its
    ///      client asks for 10. Without any ceiling a signature could be made
    ///      acceptable for as long as the name stood still (937 F2, F3).
    ///
    ///      WHY THIS LONG: the clock it is compared with is the Arbitrum
    ///      sequencer's, which may run up to a day behind real time (937 F25)
    ///      and up to an hour ahead. Behind: a signature that expires ten
    ///      minutes from the wallet's clock must still be in range. Ahead: a
    ///      short one may arrive already expired, so a relay should take the
    ///      expiration from the chain's latest block rather than the wall
    ///      clock (950 Low 13).
    ///
    ///      NOT FOR CENSORSHIP: a transaction forced in through L1 is stamped a
    ///      day or more after it was sent, when a ten-minute signature has long
    ///      expired (950 Low 14). The censorship-resistant path is the holder's
    ///      own `release`, which has no deadline.
    uint256 public constant MAX_RELEASE_SIGNATURE_TTL = 48 hours;

    /// @dev The DNS limits (RFC 1035 §2.3.4), in wire format: 63 bytes per
    ///      label, and 255 for a whole name counting its length bytes and the
    ///      terminating zero. The CCIP-Read gateway refuses a name past either,
    ///      so a name this contract let past them would mint and never resolve.
    uint256 private constant MAX_LABEL_BYTES = 63;
    uint256 private constant MAX_NAME_BYTES = 255;

    /// @dev Gas forwarded to the ERC-6492 validator. Enough for an undeployed
    ///      passkey account — a factory deployment plus a P-256 verification in
    ///      Solidity, together about 600k — while bounding what one signature
    ///      can cost whoever submits it (audit 938 M-5). A frozen constant, so
    ///      it errs high.
    uint256 private constant VALIDATOR_GAS = 1_000_000;

    /// @dev ERC-6492 validator: ERC-1271 for deployed contract accounts, and a
    ///      counterfactual deployment for undeployed ones. Consulted only by
    ///      `releaseWithSignature`, and only for a signature that does not
    ///      already recover to the holder as plain ECDSA.
    IUniversalSignatureValidator internal immutable universalSignatureValidator =
        IUniversalSignatureValidator(0x164af34fAF9879394370C7f09064127C043A35E9);

    /// @dev The contract that created this implementation, the only one that
    ///      may initialise a clone of it (audit 950 Low 16). An immutable lives
    ///      in the implementation's code, so every clone reads the same value.
    address private immutable _deployer;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The base node for the registry
    /// @dev namehash of `name()`
    bytes32 public baseNode;

    /// @notice Number of names that currently exist, at any depth, including
    ///         the base name.
    /// @dev Kept by the ownership funnel, `_updateAndBumpVersion`: a mint adds
    ///      one and a burn takes one away, whichever path made them.
    uint256 public totalSupply;

    string private _tokenName;
    string private _tokenSymbol;
    string private _tokenBaseURI;

    /// @notice Mapping of node (namehash) to name (DNS-encoded)
    mapping(bytes32 node => bytes name) public names;

    /// @dev Registrar enrolments, each stamped with the admin seat that made
    ///      it: `adminEpoch + 1` at the time of the grant, zero when never
    ///      granted or removed. Read through `registrars`, which counts only a
    ///      grant made under the CURRENT seat.
    mapping(address registrar => uint64 grantedEpoch) private _registrarEpoch;

    /// @notice What the registry remembers about a name after `release`
    ///         (WoCo addition, #464). One storage slot.
    struct ReleaseRecord {
        address previousOwner;
        uint64 releasedAt;
    }

    /// @notice The most recent release of each node: who HELD the name, and
    ///         when it was burned — whoever authorised the burn, the holder or
    ///         the holder of the name above it. `Released` says which.
    ///
    /// @dev Read by nothing in this contract, and that is deliberate. This
    ///      registry is an EIP-1167 clone and cannot be patched; the registrar
    ///      that decides mint policy can be replaced at will. A policy such as
    ///      "for N days after a release only the previous holder may take the
    ///      label back" is therefore a registrar concern — but it can only
    ///      ever be enforced ON CHAIN if the frozen layer kept the two facts it
    ///      needs, because `release` never passes through a registrar. A burn
    ///      that forgot who it burned would close that door permanently, to
    ///      save one slot per release.
    ///
    ///      FOOTGUN FOR A FUTURE READER: this record SURVIVES a re-mint of the
    ///      same label, on purpose — it is history. "Currently released" is
    ///      `owner(node) == address(0)`; check that first, and read this only
    ///      for who held it last and when it went.
    mapping(bytes32 node => ReleaseRecord) public lastRelease;

    /// @notice The address the admin has nominated to take the admin seat, or
    ///         zero when no handover is open. See `nominateAdmin`.
    address public pendingAdmin;

    /// @notice The admin-seat epoch: bumped by every `acceptAdmin`, so a
    ///         registrar grant is valid only under the seat that made it
    ///         (audit 950 Medium 3). Declared beside `pendingAdmin` so the two
    ///         share a storage slot.
    /// @dev A counter, not a block number: on Arbitrum `block.number` is the
    ///      L1 block, which many L2 transactions share.
    uint64 public adminEpoch;

    /// @notice The name directly above `node`. Zero for the base name and for
    ///         a node never minted.
    /// @dev Written when the name is created and never cleared; a re-mint of
    ///      the same label writes the same value. It is structure, not state:
    ///      whether the name is live is `owner(node)`.
    mapping(bytes32 node => bytes32 parent) public parentOf;

    /// @notice How many live names sit directly beneath `node`, the base name
    ///         included. A name cannot be released while this is non-zero.
    mapping(bytes32 node => uint256 count) public childCount;

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

    /// @notice A name was reassigned by the holder of the name directly above
    ///         it, without its own holder's consent. See `parentTransfer`.
    ///         Like `AdminTransfer`, kept apart from the ERC-721 `Transfer` so
    ///         that it does not read as a sale.
    event ParentTransfer(
        bytes32 indexed node,
        address indexed previousOwner,
        address indexed newOwner
    );

    /// @notice A name was burned (WoCo addition, #464). `previousOwner` held
    ///         it. `operator` is the account that AUTHORISED the burn: the
    ///         holder, or — under `release` only — the holder of the name
    ///         directly above it. Under `releaseWithSignature` it is the
    ///         signer, which is always the holder. The relayer that merely paid
    ///         for a signed release is on the transaction, deliberately not
    ///         here: this event answers "who let go", and a relayer never did.
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
    error ExpirationTooFar();
    error HasChildren(bytes32 node, uint256 count);
    error ParentTransferToZero();
    error ParentTransferUnregistered(bytes32 node);
    error ParentTransferSameOwner();
    error RecipientIsRegistry();
    error SubnodeMovedDuringCreation(bytes32 node);
    error DelegationNotSupported();
    error NotDeployer(address caller);

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (owner() != msg.sender) {
            revert Unauthorized(baseNode);
        }
        _;
    }

    /// @dev Expiration is L2 sequencer time: `block.timestamp` on Arbitrum,
    ///      which the sequencer sets and which may trail real time.
    modifier unexpiredSignature(uint256 expiration) {
        if (block.timestamp > expiration) {
            revert SignatureExpired();
        }
        if (expiration > block.timestamp + MAX_RELEASE_SIGNATURE_TTL) {
            revert ExpirationTooFar();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @dev The EIP-712 name and version are immutables of the implementation;
    ///      each clone rebuilds the domain with its own address and chain.
    ///      Both strings MUST stay within 31 bytes. A longer one is read back
    ///      by `eip712Domain()` from the implementation's STORAGE, which a clone
    ///      does not share, so every clone would report an empty name and a
    ///      wallet that builds the domain from ERC-5267 would sign for the
    ///      wrong one.
    ///
    ///      Records its creator as the one address that may initialise a clone.
    constructor() ERC721("", "") EIP712("WoCo Names", "2") {
        _deployer = msg.sender;
        _disableInitializers();
    }

    /// @notice Initializes the registry
    /// @dev Callable only by the contract that created the implementation, and
    ///      run in the transaction that creates the clone — see
    ///      `WoCoSubEnsDeployer`. v2.1 let anyone initialise an uninitialised
    ///      clone and take its admin seat, which the deployer contract made
    ///      unreachable by procedure only; the pin makes it structural, for a
    ///      clone of the production implementation made by anyone (audit 950
    ///      Low 16).
    ///
    ///      `_mint`, not `_safeMint`: `admin` is a multisig or a DAO, and the
    ///      admin seat must not depend on it answering an ERC-721 receiver hook.
    ///
    ///      Every label of `tokenName` passes the rules a child label does
    ///      (`_addLabel`): every child's wire name, and so `tokenURI`'s JSON,
    ///      starts with these bytes (audit 937 F9 / 938 M-3).
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
        if (msg.sender != _deployer) revert NotDeployer(msg.sender);
        (bytes memory dnsEncodedName, bytes32 node) = _encodeName(tokenName);

        // ERC721
        _tokenName = tokenName;
        _tokenSymbol = tokenSymbol;
        _setBaseURI(baseURI);

        // Registry
        baseNode = node;
        names[baseNode] = dnsEncodedName;
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
    ///      ORDER. `names` and the parent link are written before the mint, and
    ///      the mint is `_mint`, which calls nothing on the recipient. v1's
    ///      `_safeMint` handed a contract recipient control mid-mint: releasing
    ///      the name from there made the registrar's record writes land on a
    ///      freed label, where the next registrant found them (audit 927 H3). A
    ///      receiver check protects a sender from its own mistake; here the
    ///      platform chooses the recipient, and `adminTransfer` is the recovery.
    ///
    ///      The new name starts with empty records: the mint is an ownership
    ///      change, and `_update` gives it a fresh record version.
    ///
    ///      THE BATCH. `data` runs after the mint and the two events, with the
    ///      caller's own authority, and must leave the new name where the mint
    ///      put it: same holder, same record version. It is for record writes,
    ///      so it does something only for a registrar or a caller minting to
    ///      itself — nobody else may write the new name's records. A batch that
    ///      moved, burned or cleared the name would have announced a name that
    ///      no longer exists (audit 937 F1 / 938 M-8). Every item must name the
    ///      new node as its first argument (`BatchNodeMismatch`), and a failing
    ///      item reverts the whole mint with its own reason (v2.1's inherited
    ///      batch dropped it, audit 950 Low 6).
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
        if (owner(node) != msg.sender && !(node == baseNode && registrars(msg.sender))) {
            revert Unauthorized(node);
        }

        bytes32 subnode = makeNode(node, label);
        bytes32 labelhash = keccak256(bytes(label));
        bytes memory dnsEncodedName = _addLabel(label, names[node]);

        if (owner(subnode) != address(0)) {
            revert NotAvailable(label, node);
        }

        names[subnode] = dnsEncodedName;
        parentOf[subnode] = node;
        childCount[node]++;
        _mint(_owner, uint256(subnode));

        emit NewOwner(node, labelhash, _owner);
        emit SubnodeCreated(subnode, dnsEncodedName, _owner);

        uint64 version = recordVersions[subnode];
        _multicall(subnode, data);
        if (_ownerOf(uint256(subnode)) != _owner || recordVersions[subnode] != version) {
            revert SubnodeMovedDuringCreation(subnode);
        }

        return subnode;
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

    /// @notice Whether `registrar` is enrolled under the CURRENT admin seat.
    ///         Same ABI as the mapping getter it replaces.
    /// @dev Equality with `adminEpoch + 1`, not "greater than the epoch", so a
    ///      grant from any earlier seat never reads as live.
    function registrars(address registrar) public view returns (bool) {
        return _registrarEpoch[registrar] == adminEpoch + 1;
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
    ///      the base name and write the records of every name that exists
    ///      except the base name; see `_canWriteRecords`. The zero address is
    ///      refused: no transaction can come from it, so enrolling it could only
    ///      ever make an authorisation check that is handed an unset address
    ///      succeed — the shape of the v1 defect (audit 924 F-1, F-18).
    ///
    ///      An enrolment lasts only as long as the admin seat that made it.
    ///      `acceptAdmin` bumps `adminEpoch`, and a grant stamped under an
    ///      earlier epoch reads as not enrolled — including one the outgoing
    ///      admin made after the nominee last looked (audit 950 Medium 3; v2.1
    ///      left the incoming admin to prune, which raced the outgoing one,
    ///      938 M-4). The incoming admin enrols what it wants in the same
    ///      executor batch as `acceptAdmin`. No `RegistrarRemoved` is logged
    ///      for the grants a handover ends: read `AdminAccepted` as "every
    ///      registrar removed".
    /// @param registrar The address to grant registrar role to
    function addRegistrar(address registrar) external onlyOwner {
        if (registrar == address(0)) revert RegistrarIsZeroAddress();
        _registrarEpoch[registrar] = adminEpoch + 1;
        emit RegistrarAdded(registrar);
    }

    /// @notice Removes a registrar address
    /// @param registrar The address to revoke registrar role from
    /// @dev Only callable by admin role
    function removeRegistrar(address registrar) external onlyOwner {
        delete _registrarEpoch[registrar];
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
    ///      transact. This is how a DAO takes the seat from the Safe. (Since
    ///      v2.2 there are no operators at all.)
    ///
    ///      The current admin is refused as a nominee: accepting would move
    ///      nothing and log a handover that did not happen.
    ///
    ///      The handover resets the base name's records like any ownership
    ///      change: the incoming admin writes them again.
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
    ///
    ///      EVERY REGISTRAR IS DROPPED, WoCoRegistrar included: `adminEpoch`
    ///      moves, and no grant made under the previous seat counts (audit 950
    ///      Medium 3). The nominee sends this and `addRegistrar` for the
    ///      registrars it keeps as ONE executor batch — a Safe MultiSend, or a
    ///      DAO proposal's calls. Accepted alone, it stops new names and the
    ///      registrar's record writes until the second call lands; existing
    ///      names keep resolving and holders' own writes are unaffected.
    function acceptAdmin() external {
        address nominee = pendingAdmin;
        if (nominee == address(0) || msg.sender != nominee) revert NotPendingAdmin(msg.sender);

        address previousAdmin = owner();
        delete pendingAdmin;
        adminEpoch++; // every registrar grant made under the previous seat is dead
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
    ///      name, which changes hands only through `nominateAdmin`. Names beneath
    ///      the moved one stay where they are, and nothing beneath a name can
    ///      block this: the new holder may take them with `parentTransfer`, one
    ///      level at a time, and the admin may chase any of them here.
    ///
    ///      WHAT THE ADMIN SEAT CAN DO WITHOUT IT, stated so no policy claims
    ///      more than this contract delivers:
    ///        - rewrite the records of any name but the base name while leaving
    ///          it where it is. The seat may enrol itself, or any address, with
    ///          `addRegistrar`, and a registrar may write those records. Owner
    ///          decision 2026-09-14: accepted. The check on that power is who
    ///          holds the seat — the Safe now, a DAO later through
    ///          `nominateAdmin` / `acceptAdmin` — together with
    ///          `RegistrarAdded`, which puts every enrolment on chain. There is
    ///          no per-name manager that bounds it, and this contract cannot
    ///          gain one.
    ///        - end a name altogether, by moving it to an address the seat
    ///          controls and releasing it there as its holder. `release` itself
    ///          grants the seat nothing; this is two visible steps.
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
        // `_transfer` permits `from == to`. The funnel no longer resets records
        // for it (948 / 949), but this path would still log an `AdminTransfer`
        // for a seizure that did not happen. Refuse it by name.
        if (newOwner == previousOwner) revert AdminTransferSameOwner();

        _transfer(previousOwner, newOwner, uint256(node));

        emit AdminTransfer(node, previousOwner, newOwner);
    }

    /*//////////////////////////////////////////////////////////////
                            HOLDER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Give a name back. Burns the token, wipes its records, and
    ///         remembers who held it and when. Afterwards the label is
    ///         available to anyone through the ordinary mint path.
    ///
    /// @dev WoCo addition to the vendored Durin registry (WoCo-Event-App #464).
    ///      Upstream has no burn: `transferFrom` refuses the zero address and
    ///      `adminTransfer` does so by design, so without this a name could
    ///      only ever change hands, never return to the pool — and since the
    ///      registry is an unpatchable clone, that had to be decided before the
    ///      mainnet deploy or never.
    ///
    ///      WHO MAY CALL IT: the holder, and the holder of the name directly
    ///      above it — except beneath the base name, where the admin's door is
    ///      `adminTransfer`, so this function adds no platform power. NOT a
    ///      registrar, NOT the registry admin as such. There are no approvees
    ///      or operators to exclude: v2.1 refused them here (audit 938 M-7) and
    ///      they still reached a burn by moving the name to themselves first,
    ///      so v2.2 refuses delegation outright (audit 950).
    ///
    ///      A NAME WITH CHILDREN CANNOT BE RELEASED (`HasChildren`). Its
    ///      children would otherwise outlive it and pass, with their records,
    ///      to whoever takes the label next (audit 938 H-2 / 937 F8). Each child
    ///      is released first — by its holder, or by this name's holder.
    ///      `parentTransfer` changes a child's holder, not its parent, so it
    ///      never clears this gate. A child's holder may hang names beneath it,
    ///      which this name's holder then unwinds bottom-up — take the child
    ///      with `parentTransfer`, release beneath it, release it — before its
    ///      own release: a bounded nuisance, always unwindable (950 Low 7).
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
    ///      WHY `names[node]` IS LEFT IN PLACE: it is read by `tokenURI`, which
    ///      refuses a burned token first; by `createSubnode` for the PARENT of a
    ///      new name, which must be live; and by `releaseDigest`. A re-mint of
    ///      this label writes the same bytes back. Clearing it would erase the
    ///      only on-chain map from a released node to its label, for a gas
    ///      refund nobody needs.
    ///
    /// @param node The namehash of the name to release.
    function release(bytes32 node) external {
        // The base name IS the registry: `owner()` is whoever holds it. Burning
        // it would leave no admin, forever.
        if (node == baseNode) revert ReleaseBaseNode();

        address holder = owner(node);
        if (holder == address(0)) revert ReleaseUnregistered(node);
        if (msg.sender != holder) {
            address parentHolder = _parentHolder(node);
            if (parentHolder == address(0) || msg.sender != parentHolder) revert Unauthorized(node);
        }

        _release(node, holder, msg.sender);
    }

    /// @notice The EIP-712 digest a holder signs to authorise
    ///         `releaseWithSignature` for `node` until `expiration`.
    ///
    /// @dev Typed data, so a wallet can show what is being signed: a Release
    ///      of the name, by its full name, until a time. Domain "WoCo Names" /
    ///      "2" with this registry's address and chain, so neither another
    ///      registry nor this registry's address on another chain accepts it
    ///      (audit 937 F3 / 938 M-2: the v2 digest looked like EIP-712 and was
    ///      not).
    ///
    ///      `recordVersions[node]` moves on every ownership change of the name
    ///      and on `clearRecords`. One signature therefore releases at most
    ///      once, and dies the moment the name changes hands — including a
    ///      re-mint of the same label to the same holder. A signature made for
    ///      a version the name has not reached yet is bounded by
    ///      `MAX_RELEASE_SIGNATURE_TTL` like any other (937 F2).
    ///
    ///      Reverts for a node that was never minted: there is no name to show.
    function releaseDigest(bytes32 node, uint256 expiration) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RELEASE_TYPEHASH,
                    keccak256(bytes(ENSDNSUtils.dnsDecode(names[node]))),
                    node,
                    recordVersions[node],
                    expiration
                )
            )
        );
    }

    /// @notice `release`, authorised by the holder's signature instead of by
    ///         `msg.sender`, so that whoever submits the transaction need not be
    ///         the holder.
    ///
    /// @dev WoCo addition (WoCo-Event-App #464, decided 2026-09-03). WHY IT
    ///      EXISTS: `release` is authorised by `msg.sender`, which means a
    ///      holder with a plain wallet pays gas for it and a holder with no gas
    ///      at all cannot release. A paymaster solves that only for smart
    ///      accounts. This function is the same burn, gated on the holder's
    ///      SIGNATURE, so the platform (or anyone) can submit it and pay.
    ///
    ///      WHAT IT DOES NOT ADD: platform power. The relayer submits only what
    ///      the holder signed, for the node and the deadline the holder chose,
    ///      and can refuse to relay but never forge; the holder can always call
    ///      `release` directly instead. ONLY the holder may sign — not the
    ///      holder of the name above, who releases by direct call — and that is
    ///      checked BEFORE the signature is examined,
    ///      so any other signer is refused without reaching the validator
    ///      (which, for an ERC-6492 wrapper, would run the wrapper's factory
    ///      call). Every rule of `release` applies, `HasChildren` included.
    ///
    ///      HOW THE SIGNATURE IS CHECKED. Plain ECDSA first: if `signature`
    ///      recovers to `signer`, the key behind `signer` signed, and the
    ///      validator is not consulted. `signer` is the holder, which is never
    ///      the zero address, so a failed recovery — which yields the zero
    ///      address — can never match it. Otherwise the ERC-6492 validator
    ///      decides: ERC-1271 for a deployed contract account, a counterfactual
    ///      deployment for an undeployed one. It runs with `VALIDATOR_GAS`, and
    ///      anything but a clean `true` — a revert, running out of gas, a
    ///      malformed answer — is `Unauthorized` (audit 938 M-5 / 937 F18,
    ///      F19). The record version is then read again, and a name that moved
    ///      or was cleared meanwhile is refused (938 L-7). That is defence
    ///      against a validator that acts before it answers: the pinned one
    ///      cannot — its ERC-1271 call is static and its counterfactual
    ///      deployment is undone — so the guard is pinned by a test that puts
    ///      an acting validator in its place.
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
    ///      A different ECDSA encoding of the same holder's signature is the
    ///      same authorisation, and the record version still makes it single
    ///      use (937 F17 / 938 L-2).
    ///
    ///      The message is `releaseDigest(node, expiration)`; see there for why
    ///      it can be used once, here, and for nothing else.
    ///
    /// @param node       The namehash of the name to release.
    /// @param expiration Unix seconds, L2 sequencer time; the signature is void
    ///                   after it, and refused if it is more than
    ///                   `MAX_RELEASE_SIGNATURE_TTL` ahead.
    /// @param signer     Who signed: the holder.
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
        if (signer != holder) revert Unauthorized(node);

        uint64 version = recordVersions[node];
        bytes32 digest = releaseDigest(node, expiration);
        (address recovered, , ) = ECDSA.tryRecoverCalldata(digest, signature);
        if (recovered != signer) {
            if (!_validatorAccepts(signer, digest, signature)) revert Unauthorized(node);
            // Every change of holder moves the version too, so this one
            // comparison says the name is still the one that was signed for.
            if (recordVersions[node] != version) revert Unauthorized(node);
        }

        _release(node, holder, signer);
    }

    /// @notice Move a name directly beneath one of yours to `newOwner`, without
    ///         its holder's consent.
    ///
    /// @dev The owner's decision of 2026-09-17: a name issued beneath another
    ///      is never wholly its holder's. The holder of the parent may take it
    ///      back or hand it on — an organiser recovering a stallholder's lost
    ///      name, as the admin can for organisers — and a sale of the parent
    ///      sells that authority with it.
    ///
    ///      ONE LEVEL AT A TIME. Only the holder of `parentOf[node]` may call
    ///      it; a grandparent first takes the child, and then holds the
    ///      grandchild's parent. Beneath the base name it is refused: the admin
    ///      seat's door there is `adminTransfer`, which keeps `AdminTransfer`
    ///      the one signal of a platform reassignment.
    ///
    ///      It moves the name and resets its records, as every ownership
    ///      change does; it grants no record authority of its own. It is never
    ///      blocked by what hangs beneath the name. A direct call only: an
    ///      organiser on a smart account sends it as a user operation.
    /// @param node     The namehash of the name to move.
    /// @param newOwner Its new holder. Not the zero address: to end the name,
    ///                 `release` it.
    function parentTransfer(bytes32 node, address newOwner) external {
        if (newOwner == address(0)) revert ParentTransferToZero();

        address previousOwner = owner(node);
        if (previousOwner == address(0)) revert ParentTransferUnregistered(node);

        address parentHolder = _parentHolder(node);
        if (parentHolder == address(0) || msg.sender != parentHolder) revert Unauthorized(node);

        // `_transfer` permits `from == to`: a `ParentTransfer` logged for a
        // take-back that did not happen, as in `adminTransfer`.
        if (newOwner == previousOwner) revert ParentTransferSameOwner();

        _transfer(previousOwner, newOwner, uint256(node));

        emit ParentTransfer(node, previousOwner, newOwner);
    }

    /// @notice Wipe `node`'s records by moving it to a fresh record version.
    /// @dev The holder only. Registrars, and the registry admin enrolled as
    ///      one, are refused: in v1 this was the second step of the admin's
    ///      wipe-in-place (audit 927 H1). (v2 let an operator wipe the base
    ///      name with it, 938 M-9; v2.2 has no operators.)
    ///
    ///      Its real use is that it moves `recordVersions[node]`, and that is
    ///      what voids an outstanding `releaseDigest` signature. So only the
    ///      holder, whose signature it is, may do it.
    ///
    ///      The inherited body still runs its own `authorised` check —
    ///      `_canWriteRecords`, which the holder always passes and which already
    ///      refuses everyone but the holder and a registrar, and a name nobody
    ///      holds. This override's own job is refusing registrars, whom
    ///      `_canWriteRecords` lets write records.
    function clearRecords(bytes32 node) public override {
        if (msg.sender != owner(node)) {
            revert Unauthorized(node);
        }
        super.clearRecords(node);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev ONE rule for who may write a name's records. The name must exist,
    ///      and the writer must be:
    ///        - its holder; or
    ///        - a registrar, for any name but the base name.
    ///
    ///      Nobody acting for the holder. v2.1 refused ERC-721 approvees and
    ///      operators here (audit 938 H-1 / 937 F4); v2.2 has none (audit 950).
    ///      `writer == holder` also refuses the zero address, because a live
    ///      name's holder never is.
    ///
    ///      The base name's records are its holder's alone — the admin seat's
    ///      own. No registrar writes them (937 F7).
    ///
    ///      Existence is required of registrars too, so a registrar cannot write
    ///      records under a node that does not exist at all, where `resolve`
    ///      would still read them back. That records written before a mint never
    ///      reach the first holder is the mint's own version bump
    ///      (`_updateAndBumpVersion`, audit 927 H2 / 924 F-3), the same bump
    ///      every later change of holder makes.
    ///
    ///      The registry admin needs no branch here: it can enrol itself with
    ///      `addRegistrar`. That is accepted; see `adminTransfer`.
    function _canWriteRecords(address writer, bytes32 node) internal view override returns (bool) {
        address holder = _ownerOf(uint256(node));
        return holder != address(0) && (writer == holder || (registrars(writer) && node != baseNode));
    }

    /// @dev The holder of the name directly above `node`, when that holder may
    ///      act on it; otherwise zero. Zero for the base name and for names
    ///      directly beneath it, whose parent's holder is the admin seat — its
    ///      door is `adminTransfer`. A live name's parent is always live,
    ///      because `_release` refuses a name with children.
    function _parentHolder(bytes32 node) internal view returns (address) {
        bytes32 parent = parentOf[node];
        if (parent == bytes32(0) || parent == baseNode) return address(0);
        return _ownerOf(uint256(parent));
    }

    /// @dev Every change of a name's owner comes through here — `_mint`,
    ///      `transferFrom` / `safeTransferFrom`, `adminTransfer`'s and
    ///      `parentTransfer`'s `_transfer`, `release`'s `_burn` — except
    ///      `acceptAdmin`, which enters one step further in. Refuses to move an
    ///      existing base name; see `nominateAdmin`.
    ///
    ///      RECEIVER HOOKS. Nothing this contract does calls a recipient: mints,
    ///      burns, `adminTransfer` and `parentTransfer` all move the token
    ///      without one. The inherited `safeTransferFrom` still calls
    ///      `onERC721Received`, after every state change here is complete, so a
    ///      recipient can act again before that call returns. An integrator that
    ///      acts on "the recipient now holds it" re-reads `owner(node)` after a
    ///      `safeTransferFrom`, or uses `transferFrom` (audit 938 L-9).
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        if (bytes32(tokenId) == baseNode && _ownerOf(tokenId) != address(0)) {
            revert AdminHandoverRequired();
        }
        return _updateAndBumpVersion(to, tokenId, auth);
    }

    /// @dev The one place an ownership change is accounted for, `acceptAdmin`
    ///      included.
    ///
    ///      RECORDS. Records are stored per version, so moving it makes every
    ///      record of the previous holding unreadable at once. v1 bumped in
    ///      `release` and `adminTransfer` only. A mint did not, so records
    ///      written to a label before or during its mint reached the new holder
    ///      (audit 924 F-3 / 927 H2, H3), and a plain transfer did not, so a
    ///      buyer received the seller's records (924 F-5) and the seller's
    ///      outstanding release signature. A path added later cannot forget a
    ///      bump that no path performs itself.
    ///
    ///      A MOVE TO THE CURRENT HOLDER IS NOT ONE. `transferFrom` permits
    ///      `from == to`. In v2.1 an ERC-721 approvee or operator could call it,
    ///      and bumping there let exactly the party the registry excluded from
    ///      records wipe them and void an outstanding release signature,
    ///      repeatably, without the name ever moving (audits 948 / 949, both
    ///      Medium; the same defect in v2). Since v2.2 only the holder can make
    ///      that call, and it still changes nothing of this registry's own: it
    ///      emits OpenZeppelin's `Transfer`, and no event of this registry's
    ///      fires.
    ///      `adminTransfer` and `parentTransfer` refuse a same-owner move by
    ///      name for a DIFFERENT reason: they would log a seizure or a take-back
    ///      that did not happen. Mint, burn and `acceptAdmin` can never reach
    ///      the guard: one side is always the zero address, and a nominee is
    ///      never the sitting admin.
    ///
    ///      SUPPLY. A mint adds one to `totalSupply` and a burn takes one away
    ///      (938 L-5).
    ///
    ///      THE REGISTRY HOLDS NOTHING. A name sent here could never move again:
    ///      the registry calls nothing on its own behalf (937 F19, 938 L-3).
    function _updateAndBumpVersion(address to, uint256 tokenId, address auth) private returns (address from) {
        if (to == address(this)) revert RecipientIsRegistry();

        from = super._update(to, tokenId, auth);

        if (from == address(0)) {
            totalSupply++;
        } else if (to == address(0)) {
            totalSupply--;
        }

        if (from != to) {
            bytes32 node = bytes32(tokenId);
            recordVersions[node]++;
            emit VersionChanged(node, recordVersions[node]);
        }
    }

    /// @dev The burn both release paths share. Callers have already decided
    ///      that `holder` owns `node` and that `operator` may release it. The
    ///      child check lives here so that every path to a burn shares it.
    function _release(bytes32 node, address holder, address operator) internal {
        uint256 children = childCount[node];
        if (children != 0) revert HasChildren(node, children);

        _burn(uint256(node));
        childCount[parentOf[node]]--;

        lastRelease[node] = ReleaseRecord({
            previousOwner: holder,
            releasedAt: uint64(block.timestamp)
        });

        emit Released(node, holder, operator);
    }

    /// @dev Whether the ERC-6492 validator says `signer` signed `digest`, asked
    ///      with bounded gas. A low-level call rather than `try`: `try` still
    ///      bubbles a failure to decode the answer. Anything but exactly `true`
    ///      is no.
    ///
    ///      In assembly so that nothing but one word of the answer is ever
    ///      copied: Solidity's `call` copies ALL return data into memory before
    ///      any length check, so a validator answering with a huge buffer would
    ///      bill the submitter for the memory (audit 950 Low 12). A call to an
    ///      address with no code succeeds with no return data, and is refused.
    function _validatorAccepts(address signer, bytes32 digest, bytes calldata signature)
        private
        returns (bool accepted)
    {
        bytes memory data = abi.encodeCall(IUniversalSignatureValidator.isValidSig, (signer, digest, signature));
        address validator = address(universalSignatureValidator);
        uint256 gasBudget = VALIDATOR_GAS;
        assembly ("memory-safe") {
            let ok := call(gasBudget, validator, 0, add(data, 0x20), mload(data), 0, 0)
            // Exactly one word back, equal to 1. Scratch space only.
            if and(ok, eq(returndatasize(), 32)) {
                returndatacopy(0, 0, 32)
                accepted := eq(mload(0), 1)
            }
        }
    }

    function _setBaseURI(string calldata baseURI) private {
        _tokenBaseURI = baseURI;
        emit BaseURIUpdated(baseURI);
    }

    /// @dev `name_` in DNS wire format, and its namehash, with every label
    ///      held to `_addLabel`'s rules. Split on '.' from the right, so an
    ///      empty label — a leading, trailing or doubled dot, or an empty name —
    ///      is refused as `LabelTooShort`.
    function _encodeName(string calldata name_) private pure returns (bytes memory wire, bytes32 node) {
        bytes calldata b = bytes(name_);
        wire = hex"00";
        uint256 end = b.length;
        for (uint256 i = b.length; i > 0; --i) {
            if (b[i - 1] == ".") {
                (wire, node) = _prependLabel(string(b[i:end]), wire, node);
                end = i - 1;
            }
        }
        (wire, node) = _prependLabel(string(b[:end]), wire, node);
    }

    function _prependLabel(string memory label, bytes memory wire, bytes32 node)
        private
        pure
        returns (bytes memory, bytes32)
    {
        return (_addLabel(label, wire), keccak256(abi.encodePacked(node, keccak256(bytes(label)))));
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

    /*//////////////////////////////////////////////////////////////
                         NO ERC-721 DELEGATION
    //////////////////////////////////////////////////////////////*/

    /// @notice This registry has no approvees and no operators: only the
    ///         holder of a name moves it. An approval is a custody delegation,
    ///         and here custody is every holder power (records, release, the
    ///         names beneath), so "an approval moves the token and does nothing
    ///         else" was never a property this contract could keep (audits 937
    ///         F4, 938 H-1 / M-7, 948 / 949, 950). Names are therefore not
    ///         listable on approval-based marketplaces; a sale is the holder's
    ///         own `transferFrom`, or a push into an escrow contract.
    /// @dev EIP-721 says `approve` throws unless the caller is the holder or an
    ///      operator; here it always throws, and so does `setApprovalForAll`.
    ///      `getApproved` and `isApprovedForAll` are inherited and truthful:
    ///      zero and false for every live name and pair.
    ///
    ///      FOR INTEGRATORS. Custody is push-only: a vault or escrow receives a
    ///      name by its holder's `safeTransferFrom`; it cannot pull one. And a
    ///      name held in custody is not custodial-safe by ERC-721 norms: the
    ///      admin may `adminTransfer` it, and the holder of the name above may
    ///      `parentTransfer` or `release` it, whoever holds it (audit 950 Low 8).
    function approve(address, uint256) public pure override {
        revert DelegationNotSupported();
    }

    /// @notice See `approve`.
    function setApprovalForAll(address, bool) public pure override {
        revert DelegationNotSupported();
    }

    /// @dev `_update` clears the per-token approval on every move by calling
    ///      this with `to == address(0)` (OpenZeppelin 5.6.1 ERC721.sol:227);
    ///      that must stay, or every transfer, mint and burn would revert. Any
    ///      other `to` is refused, so no code path can write a non-zero
    ///      `_tokenApprovals`.
    function _approve(address to, uint256 tokenId, address auth, bool emitEvent) internal override {
        if (to != address(0)) revert DelegationNotSupported();
        super._approve(to, tokenId, auth, emitEvent);
    }

    /// @dev The only writer of `_operatorApprovals`; nothing may call it.
    function _setApprovalForAll(address, address, bool) internal pure override {
        revert DelegationNotSupported();
    }

    /// @dev Only the holder moves a name. Stated directly rather than left to
    ///      the two approval mappings being permanently empty. `adminTransfer`,
    ///      `parentTransfer`, `acceptAdmin`, mint and burn pass no `auth` and
    ///      never reach this.
    function _isAuthorized(address holder, address spender, uint256) internal pure override returns (bool) {
        return spender != address(0) && holder == spender;
    }

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
