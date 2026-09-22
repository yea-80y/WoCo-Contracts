// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IL2Registry} from "./durin/interfaces/IL2Registry.sol";
import {IUniversalSignatureValidator} from "./durin/interfaces/IUniversalSignatureValidator.sol";

/// @title WoCoRegistrar
/// @author WoCo
/// @notice Platform-sponsored registrar that mints organiser sub-ENS names
///         (`label.woco.eth`) on WoCo's L2Registry on Arbitrum, and relays the
///         pointer writes their HOLDERS sign.
/// @dev WHAT THE SPONSOR CAN DO, and nothing more (Fable sponsor-key consult,
///      2026-09-19; owner adopted it the same day):
///        - create an EMPTY name for a recipient: `register` writes the name,
///          its holder and the holder's own address records, never what the
///          name points at;
///        - pay for what a holder signed: `setContenthashWithSignature` writes
///          a name's contenthash only under its holder's EIP-712 signature, and
///          anyone may submit it.
///      A sponsor key on its own can repoint no name. Its reach is bounded by
///      two mint caps, per recipient and for the registrar as a whole.
///
///      v2 (WoCo-Contracts #22) removed `registerWithPermit` and everything only
///      it used: `platformSigner`, `setPlatformSigner`, `usedPermits`,
///      `PERMIT_TYPEHASH`, `PERMIT_TTL`, `DOMAIN_SEPARATOR`. Its permit signed
///      only the label, the owner and the expiry, so whoever submitted a permit
///      chose the records written with it (audit 925 finding 1), and the gasless
///      rail that used it was deleted in WoCo-Event-App #501.
///
///      v2.2 removed the sponsor-only `setContenthash`, and with it the last
///      standing authority the hot sponsor key held over names: it could
///      repoint ANY name beneath the base name, checked only by the server
///      (WoCo-Event-App routes). `register` no longer takes a contenthash or
///      text records. The mint caps gained a registrar-wide window (#469).
///
///      The registrar writes records because the registry lists it in
///      `registrars` (`addRegistrar`). The registry lets a registrar write only
///      names that exist, never the base name, and its admin can replace this
///      contract at any time with `addRegistrar` / `removeRegistrar`. A holder
///      never needs this contract to write its own records: it may call the
///      registry directly, which is the path for a holder whose signature
///      cannot verify on this chain (a Coinbase Smart Wallet signs for Base).
///
///      v2.1 (audit 937): the owner is not stored. It is the registry's admin,
///      read live (`owner()`), so a handover of the admin seat hands over this
///      registrar in the same transaction and nothing is left behind (937 F13,
///      938 M-4). With it went `Ownable2Step` and its renounce.
///
///      Its ENROLMENT does not follow the seat. Since registry v2.2 an
///      `acceptAdmin` drops every registrar (audit 950 Medium 3), so the
///      incoming admin re-enrols this contract with `addRegistrar` in the same
///      executor batch as `acceptAdmin`, or new names stop until it does.
contract WoCoRegistrar is EIP712 {
    /// @notice The Durin L2Registry this registrar mints into.
    IL2Registry public immutable registry;

    /// @notice ENSIP-11 coinType for the chain this registrar is deployed on.
    uint256 public immutable coinType;

    /// @notice Platform wallets permitted to call `register` (the sponsored mint path).
    mapping(address sponsor => bool authorised) public authorisedSponsors;

    /// @notice Reserved labels (keyed by labelhash) that can never be minted.
    mapping(bytes32 labelhash => bool reserved) public reserved;

    /// @notice Mint accounting for a rate cap. One slot.
    /// @dev The window's END is stored, not its start, so a window keeps the
    ///      length it was opened with when the owner retunes (audit 937 F6).
    struct MintWindow {
        uint64 end;
        uint32 count;
    }

    /// @notice How many names each RECIPIENT has been minted in its current
    ///         window, and when that window ends.
    ///
    /// @dev Keyed on the address that RECEIVES the name, never on
    ///      `msg.sender`. Every mint is submitted by the sponsor key on the
    ///      organiser's behalf, so a cap keyed on the sender would cap the
    ///      whole platform at one organiser's allowance.
    ///
    ///      WHAT THIS BOUNDS (WoCo-Event-App #464): a server bug that mints for
    ///      the same account in a loop, and an account that churns names
    ///      through the product. It does NOT bound whoever holds the sponsor
    ///      key, who chooses the recipient and can use a fresh one per mint:
    ///      that is `globalMintWindow`'s job.
    ///
    ///      Fixed window, opened by the recipient's first mint after the last
    ///      one ended. At the boundary a recipient can therefore mint up to
    ///      twice the cap across a few seconds; accepted for a backstop, in
    ///      exchange for one slot per recipient and no loops.
    ///
    ///      A sponsor chooses the recipient, so it can spend someone's
    ///      allowance on names they did not ask for (937 F12). The recipient
    ///      can release those; `resetMintWindow` gives the allowance back.
    ///      Taking back a label the recipient itself released costs nothing
    ///      (`register`).
    mapping(address recipient => MintWindow) public mintWindow;

    /// @notice Names one recipient may be minted per window. Owner-tunable.
    /// @dev Default 30 per 30 days. Sized so no legitimate organiser meets it —
    ///      a profile name, a name per site and a name per event is the intended
    ///      use — and erring HIGH deliberately: the owner is a multisig, so a cap
    ///      set too low fails a real organiser at the worst moment and needs a
    ///      multisig round to fix, while a cap set high costs nothing until
    ///      abuse that this cap does not bound anyway.
    uint32 public maxMintsPerWindow;

    /// @notice Length of the per-recipient window in seconds. Owner-tunable,
    ///         at most `MAX_MINT_WINDOW_SECONDS`.
    uint64 public mintWindowSeconds;

    /// @notice How many names this registrar has minted in the current
    ///         registrar-wide window, and when that window ends (#469).
    ///
    /// @dev What bounds whoever holds a sponsor key, recipient by recipient:
    ///      without it such a key was bounded only by its ETH. Hitting it is
    ///      also the DETECTOR — `globalMintAllowance` is watched by
    ///      `/api/health` — and the response is `removeSponsor`, which stops
    ///      exactly the mint path; the holder-signed pointer relay stays open
    ///      because a sponsor key adds nothing to it. Same fixed-window shape as
    ///      the per-recipient cap. A retake of one's own released label is
    ///      charged to neither.
    MintWindow public globalMintWindow;

    /// @notice Names the whole registrar may mint per registrar-wide window.
    /// @dev Default 300 per hour. Hourly rather than daily on purpose: an
    ///      organiser refused at a spike waits at most an hour, and what a key
    ///      other than WoCo's can take is 300 names per hour of multisig
    ///      latency, not a day's budget in one minute. The owner raises it
    ///      ahead of a known spike, as with the per-recipient cap.
    uint32 public maxGlobalMintsPerWindow;

    /// @notice Length of the registrar-wide window in seconds. Owner-tunable,
    ///         at most `MAX_MINT_WINDOW_SECONDS`.
    uint64 public globalMintWindowSeconds;

    /// @notice Per-node counter behind `setContenthashWithSignature`: every
    ///         signature names the current value, and a successful write moves
    ///         it, so a signature is good for one write.
    mapping(bytes32 node => uint256 nonce) public pointerNonce;

    /// @notice EIP-712 type of the message `setContenthashWithSignature`
    ///         verifies. `name` is the whole name as a wallet should show it,
    ///         e.g. "alice.woco.eth"; the registrar and the chain are in the
    ///         domain ("WoCo Registrar", version "1"), which is not the
    ///         registry's release domain, so a pointer signature can never be a
    ///         release signature or the reverse.
    bytes32 public constant SET_CONTENTHASH_TYPEHASH =
        keccak256("SetContenthash(string name,bytes32 node,bytes contenthash,uint256 nonce,uint256 expiration)");

    /// @notice The furthest ahead of the submitting block a pointer signature
    ///         may expire.
    /// @dev The same ceiling, for the same reasons, as
    ///      `L2Registry.MAX_RELEASE_SIGNATURE_TTL`: it bounds how early a
    ///      signature is ACCEPTED, not its age, and it is this long because the
    ///      clock it is compared with is Arbitrum's, which may run a day behind.
    ///      The nonce makes every signature single use.
    uint256 public constant MAX_POINTER_SIGNATURE_TTL = 48 hours;

    uint256 public constant MIN_LABEL_LENGTH = 3;
    uint256 public constant MAX_LABEL_LENGTH = 63;

    /// @notice The longest window either rate-cap setter accepts.
    /// @dev The window arithmetic (`now + windowSeconds`) is checked `uint64`,
    ///      so an unbounded window let one owner call make every mint revert on
    ///      overflow (audit 925 finding 3). A year is far beyond any window
    ///      worth setting.
    uint64 public constant MAX_MINT_WINDOW_SECONDS = 366 days;

    /// @dev Gas forwarded to the ERC-6492 validator, as in `L2Registry`: enough
    ///      for an undeployed passkey account, bounded for whoever submits.
    uint256 private constant VALIDATOR_GAS = 1_000_000;

    /// @dev ERC-6492 validator, the same pinned address the registry uses:
    ///      ERC-1271 for deployed contract accounts, a counterfactual deployment
    ///      for undeployed ones. Consulted only for a signature that does not
    ///      already recover to the holder as plain ECDSA.
    IUniversalSignatureValidator internal immutable universalSignatureValidator =
        IUniversalSignatureValidator(0x164af34fAF9879394370C7f09064127C043A35E9);

    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event LabelReservedSet(string label, bool reserved);
    /// @dev Indexed by `node`: an indexed string is stored only as its hash,
    ///      and the label could not be read back from the log (audit 937 F36).
    event NameRegistered(bytes32 indexed node, string label, address indexed owner);
    event ContenthashUpdated(bytes32 indexed node, string label, bytes contenthash);
    event MintRateCapSet(uint32 maxMintsPerWindow, uint64 mintWindowSeconds);
    event GlobalMintRateCapSet(uint32 maxMintsPerWindow, uint64 mintWindowSeconds);
    event MintWindowReset(address indexed recipient);

    error NotAuthorisedSponsor(address caller);
    error SponsorIsZeroAddress();
    error LabelIsReserved(string label);
    error InvalidLabel(string label);
    error LabelNotRegistered(string label);
    error EmptyContenthash();
    error NameMovedDuringRegistration(bytes32 node);
    error MintRateCapExceeded(address recipient, uint64 windowResetsAt);
    error GlobalMintCapExceeded(uint64 windowResetsAt);
    error InvalidMintRateCap();
    error NotRegistryAdmin(address caller);
    error SignatureExpired();
    error ExpirationTooFar();
    error NotHolderSignature(bytes32 node);

    modifier onlySponsor() {
        if (!authorisedSponsors[msg.sender]) revert NotAuthorisedSponsor(msg.sender);
        _;
    }

    /// @dev The registry's admin, whoever holds the seat at this block.
    modifier onlyOwner() {
        if (msg.sender != owner()) revert NotRegistryAdmin(msg.sender);
        _;
    }

    /// @param _registry       The registry to mint into, and whose admin owns
    ///                        this registrar. Immutable: a new registry means a
    ///                        new registrar.
    /// @param _sponsor        The first authorised sponsor. Not the zero address.
    /// @param _reservedLabels Labels no one may ever mint. Each must be a label
    ///                        `register` would accept.
    constructor(address _registry, address _sponsor, string[] memory _reservedLabels)
        EIP712("WoCo Registrar", "1")
    {
        registry = IL2Registry(_registry);
        coinType = (0x80000000 | block.chainid);

        maxMintsPerWindow = 30;
        mintWindowSeconds = 30 days;
        emit MintRateCapSet(30, 30 days);

        maxGlobalMintsPerWindow = 300;
        globalMintWindowSeconds = 1 hours;
        emit GlobalMintRateCapSet(300, 1 hours);

        _addSponsor(_sponsor);

        for (uint256 i; i < _reservedLabels.length; ++i) {
            _setReserved(_reservedLabels[i], true);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                MINTING
    //////////////////////////////////////////////////////////////*/

    /// @notice Sponsor-submitted mint, the only way this registrar creates a
    ///         name: the name, its holder, and the holder's own address records.
    /// @dev Nothing else. What a name POINTS at is written only under its
    ///      holder's signature (`setContenthashWithSignature`) or by the holder
    ///      at the registry; a sponsor never decides what a name says. The
    ///      address records are not a choice either: they are the recipient's
    ///      own address, for the chain's ENSIP-11 coinType and for ETH (60), so
    ///      the name doubles as the organiser's receive alias.
    function register(string calldata label, address owner_) external onlySponsor returns (bytes32 node) {
        if (!_validLabel(label)) revert InvalidLabel(label);
        if (reserved[keccak256(bytes(label))]) revert LabelIsReserved(label);

        bytes32 base = registry.baseNode();
        _chargeUnlessRetaken(base, label, owner_);

        node = registry.createSubnode(base, label, owner_, new bytes[](0));

        bytes memory addr = abi.encodePacked(owner_);
        registry.setAddr(node, coinType, addr);
        registry.setAddr(node, 60, addr);

        // ONE check, after the last write: the name still belongs to the
        // address it was minted to, so every record above was written to that
        // holder's name. The v2 registry calls nothing outside itself during a
        // registration, so today this cannot fail; it is what keeps that true of
        // any registry that does. In v1 a recipient released the name from its
        // ERC-721 receiver hook, and these writes landed on the freed label for
        // its next registrant (audit 927 H3).
        if (registry.owner(node) != owner_) revert NameMovedDuringRegistration(node);

        emit NameRegistered(node, label, owner_);
    }

    /*//////////////////////////////////////////////////////////////
                      HOLDER-SIGNED POINTER WRITE
    //////////////////////////////////////////////////////////////*/

    /// @notice The EIP-712 digest a holder signs to point `node` at
    ///         `contenthash` until `expiration`, for the node's current
    ///         `pointerNonce`.
    /// @dev The name is decoded from the registry, so a wallet shows the same
    ///      string the release flow shows. Reverts for a node never minted:
    ///      there is no name to show.
    function setContenthashDigest(bytes32 node, bytes calldata contenthash, uint256 expiration)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    SET_CONTENTHASH_TYPEHASH,
                    keccak256(bytes(registry.decodeName(registry.names(node)))),
                    node,
                    keccak256(contenthash),
                    pointerNonce[node],
                    expiration
                )
            )
        );
    }

    /// @notice Point a name at `contenthash`, authorised by its HOLDER's
    ///         signature over `setContenthashDigest`. Anyone may submit it: the
    ///         platform's sponsor is only ever a relayer here, and it adds
    ///         nothing a stranger could not.
    ///
    /// @dev WHO: only the name's current holder may sign. A signature from
    ///      anyone else — the seller of a name since sold, a registrar, the
    ///      registry admin — is refused. The holder's authority over a pointer
    ///      does not otherwise depend on this contract: it may write its own
    ///      records at the registry, which is the path for a holder whose
    ///      signature cannot verify here.
    ///
    ///      HOW THE SIGNATURE IS CHECKED, as `L2Registry.releaseWithSignature`
    ///      checks it: plain ECDSA first; otherwise the pinned ERC-6492
    ///      validator, with bounded gas, where anything but a clean `true` is a
    ///      refusal and only one word of its answer is ever copied. After the
    ///      validator answers, the holder is read again, and a name that moved
    ///      meanwhile is refused: defence against a validator that acts before
    ///      it answers (938 L-7 in the registry). The pinned one cannot.
    ///
    ///      REPLAY: the nonce is consumed before the validator is called
    ///      (signatures checklist S-04), so a signature is good for one write
    ///      and cannot be re-entered with.
    ///
    ///      The label rules match `register`'s: this registrar never touches a
    ///      name it would not have minted, such as a reserved one the platform
    ///      took through another registrar (audit 937 F5). An unminted label is
    ///      refused by name (925 finding 2 / 927 H2).
    /// @param label       The label beneath the base name, e.g. "alice".
    /// @param contenthash The EIP-1577 contenthash to write. Not empty.
    /// @param expiration  Unix seconds, Arbitrum time; see `MAX_POINTER_SIGNATURE_TTL`.
    /// @param signature   The holder's signature over `setContenthashDigest`.
    function setContenthashWithSignature(
        string calldata label,
        bytes calldata contenthash,
        uint256 expiration,
        bytes calldata signature
    ) external {
        if (!_validLabel(label)) revert InvalidLabel(label);
        if (reserved[keccak256(bytes(label))]) revert LabelIsReserved(label);
        if (contenthash.length == 0) revert EmptyContenthash();
        if (block.timestamp > expiration) revert SignatureExpired();
        if (expiration > block.timestamp + MAX_POINTER_SIGNATURE_TTL) revert ExpirationTooFar();

        bytes32 node = registry.makeNode(registry.baseNode(), label);
        address holder = registry.owner(node);
        if (holder == address(0)) revert LabelNotRegistered(label);

        bytes32 digest = setContenthashDigest(node, contenthash, expiration);
        pointerNonce[node]++;

        (address recovered,,) = ECDSA.tryRecoverCalldata(digest, signature);
        if (recovered != holder) {
            if (!_validatorAccepts(holder, digest, signature)) revert NotHolderSignature(node);
            if (registry.owner(node) != holder) revert NotHolderSignature(node);
        }

        registry.setContenthash(node, contenthash);
        emit ContenthashUpdated(node, label, contenthash);
    }

    /*//////////////////////////////////////////////////////////////
                              AVAILABILITY
    //////////////////////////////////////////////////////////////*/

    /// @notice True if `label` is valid, not reserved, and unminted.
    /// @dev Says nothing about either allowance — those are properties of who
    ///      is receiving and of the moment, not of the label. See
    ///      `mintAllowance` and `globalMintAllowance`.
    function available(string calldata label) external view returns (bool) {
        if (!_validLabel(label)) return false;
        if (reserved[keccak256(bytes(label))]) return false;
        bytes32 node = registry.makeNode(registry.baseNode(), label);
        return registry.owner(node) == address(0);
    }

    /// @notice How many more names `recipient` may be minted right now, and
    ///         when their window resets. For the server and UI to say "you can
    ///         register N more until <date>" instead of surfacing a failed tx.
    /// @dev With no window open, `windowResetsAt` is when a window opened by a
    ///      mint in this block would end. Otherwise it is the open window's
    ///      recorded end, which a retune does not move.
    function mintAllowance(address recipient) external view returns (uint32 remaining, uint64 windowResetsAt) {
        return _allowance(mintWindow[recipient], maxMintsPerWindow, mintWindowSeconds);
    }

    /// @notice How many more names the whole registrar may mint right now, and
    ///         when the registrar-wide window resets. Watched by `/api/health`.
    function globalMintAllowance() external view returns (uint32 remaining, uint64 windowResetsAt) {
        return _allowance(globalMintWindow, maxGlobalMintsPerWindow, globalMintWindowSeconds);
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice This registrar's owner: the registry's admin, read live.
    /// @dev Not stored, so it cannot drift from the registry's. The seat moves
    ///      only through the registry's `nominateAdmin` / `acceptAdmin`, so this
    ///      changes in the same transaction, never leaving a moment with no
    ///      owner or two. The coupling is deliberate: a seat that cannot
    ///      transact freezes both contracts' admin functions at once.
    function owner() public view returns (address) {
        return registry.owner();
    }

    function addSponsor(address sponsor) external onlyOwner {
        _addSponsor(sponsor);
    }

    /// @notice Stop `sponsor` minting. The response to a sponsor key held by
    ///         anyone but WoCo: it closes the mint path, and nothing else is
    ///         the sponsor's to close.
    function removeSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = false;
        emit SponsorRemoved(sponsor);
    }

    function setReserved(string calldata label, bool isReserved) external onlyOwner {
        _setReserved(label, isReserved);
    }

    /// @notice Retune the per-recipient mint cap. The new cap applies to every
    ///         recipient's next mint; the new length only to windows opened
    ///         after this call. An open window keeps its end.
    /// @dev Zero is refused for both: a zero cap would be a mint pause dressed
    ///      as a tuning, and a zero window would make the cap vanish. Pausing
    ///      already exists — `removeSponsor` closes the mint path. A window
    ///      over `MAX_MINT_WINDOW_SECONDS` is refused; see there.
    function setMintRateCap(uint32 max, uint64 windowSeconds) external onlyOwner {
        if (max == 0 || windowSeconds == 0 || windowSeconds > MAX_MINT_WINDOW_SECONDS) {
            revert InvalidMintRateCap();
        }
        maxMintsPerWindow = max;
        mintWindowSeconds = windowSeconds;
        emit MintRateCapSet(max, windowSeconds);
    }

    /// @notice Retune the registrar-wide mint cap, with the same rules and the
    ///         same "an open window keeps its end" semantics as
    ///         `setMintRateCap`. Raising the cap lifts a refusal at once.
    function setGlobalMintRateCap(uint32 max, uint64 windowSeconds) external onlyOwner {
        if (max == 0 || windowSeconds == 0 || windowSeconds > MAX_MINT_WINDOW_SECONDS) {
            revert InvalidMintRateCap();
        }
        maxGlobalMintsPerWindow = max;
        globalMintWindowSeconds = windowSeconds;
        emit GlobalMintRateCapSet(max, windowSeconds);
    }

    /// @notice Give `recipient` its full allowance back now.
    /// @dev For a recipient whose allowance a sponsor spent on names it did not
    ///      ask for (audit 937 F12). Closes the open window; the next mint opens
    ///      a fresh one. The registrar-wide window is not touched.
    function resetMintWindow(address recipient) external onlyOwner {
        delete mintWindow[recipient];
        emit MintWindowReset(recipient);
    }

    /*//////////////////////////////////////////////////////////////
                             INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev The zero address is refused. No transaction comes from it, so
    ///      enrolling it authorises nobody — but `authorisedSponsors(address(0))`
    ///      reading true would let a deploy handed an unset sponsor pass its
    ///      checks with no working one. The registry refuses
    ///      `addRegistrar(address(0))` for the same reason.
    function _addSponsor(address sponsor) internal {
        if (sponsor == address(0)) revert SponsorIsZeroAddress();
        authorisedSponsors[sponsor] = true;
        emit SponsorAdded(sponsor);
    }

    /// @dev Only a label `register` would accept. The check is exact bytes, so
    ///      "WoCo" reserved nothing while "woco" stayed free (audit 937 F11).
    function _setReserved(string memory label, bool isReserved) internal {
        if (!_validLabel(label)) revert InvalidLabel(label);
        reserved[keccak256(bytes(label))] = isReserved;
        emit LabelReservedSet(label, isReserved);
    }

    /// @dev Taking back a label you yourself released is not a new name, and a
    ///      capped holder must not watch someone else take it first (audit 937
    ///      F21). A retake is charged to neither window. Churning one label is
    ///      bounded by the relay's own limits and the sponsor's gas.
    function _chargeUnlessRetaken(bytes32 base, string calldata label, address recipient) internal {
        (address releasedBy,) = registry.lastRelease(registry.makeNode(base, label));
        if (releasedBy != recipient) {
            _consumeMintAllowance(recipient);
            _consumeGlobalAllowance();
        }
    }

    /// @dev Charges one mint to `recipient`'s window, opening a fresh window if
    ///      the last one has ended. Reverts with the reset time when the window
    ///      is full, so a caller can report it.
    function _consumeMintAllowance(address recipient) internal {
        MintWindow memory w = mintWindow[recipient];
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= w.end) {
            w.end = nowTs + mintWindowSeconds;
            w.count = 0;
        }
        if (w.count >= maxMintsPerWindow) {
            revert MintRateCapExceeded(recipient, w.end);
        }
        w.count += 1;
        mintWindow[recipient] = w;
    }

    /// @dev The registrar-wide twin of `_consumeMintAllowance`.
    function _consumeGlobalAllowance() internal {
        MintWindow memory w = globalMintWindow;
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= w.end) {
            w.end = nowTs + globalMintWindowSeconds;
            w.count = 0;
        }
        if (w.count >= maxGlobalMintsPerWindow) {
            revert GlobalMintCapExceeded(w.end);
        }
        w.count += 1;
        globalMintWindow = w;
    }

    function _allowance(MintWindow memory w, uint32 max, uint64 windowSeconds)
        internal
        view
        returns (uint32 remaining, uint64 windowResetsAt)
    {
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= w.end) {
            return (max, nowTs + windowSeconds);
        }
        remaining = w.count >= max ? 0 : max - w.count;
        windowResetsAt = w.end;
    }

    /// @dev Whether the ERC-6492 validator says `signer` signed `digest`, asked
    ///      with bounded gas: the same assembly as `L2Registry._validatorAccepts`
    ///      (audit 950 Low 12). Only one word of the answer is ever copied, a
    ///      validator with no code fails closed, and anything but exactly
    ///      `true` is no.
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

    /// @dev Allowed: 3-63 chars, lowercase a-z / 0-9 / hyphen, no leading/trailing/double hyphen.
    function _validLabel(string memory label) internal pure returns (bool) {
        bytes memory b = bytes(label);
        uint256 len = b.length;
        if (len < MIN_LABEL_LENGTH || len > MAX_LABEL_LENGTH) return false;
        for (uint256 i; i < len; ++i) {
            bytes1 c = b[i];
            bool isLower = (c >= 0x61 && c <= 0x7a);
            bool isDigit = (c >= 0x30 && c <= 0x39);
            bool isHyphen = (c == 0x2d);
            if (!(isLower || isDigit || isHyphen)) return false;
            if (isHyphen) {
                if (i == 0 || i == len - 1) return false;
                if (b[i - 1] == 0x2d) return false;
            }
        }
        return true;
    }
}
