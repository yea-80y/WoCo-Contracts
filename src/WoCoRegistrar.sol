// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IL2Registry} from "./durin/interfaces/IL2Registry.sol";

/// @title WoCoRegistrar
/// @author WoCo
/// @notice Platform-sponsored registrar that mints organiser sub-ENS names
///         (`label.woco.eth`) on WoCo's L2Registry on Arbitrum and writes the
///         organiser's Swarm site pointer + profile records in the same flow.
/// @dev ONE minting path: `register`, submitted by an authorised sponsor wallet.
///
///      v2 (WoCo-Contracts #22) removed `registerWithPermit` and everything only
///      it used: `platformSigner`, `setPlatformSigner`, `usedPermits`,
///      `PERMIT_TYPEHASH`, `PERMIT_TTL`, `DOMAIN_SEPARATOR`. Its permit signed
///      only the label, the owner and the expiry, so whoever submitted a permit
///      chose the records written with it (audit 925 finding 1), and the gasless
///      rail that used it was deleted in WoCo-Event-App #501. Removing it also
///      retires the platform-signer role the hot sponsor key held.
///
///      The registrar writes records because the registry lists it in
///      `registrars` (`addRegistrar`). The registry lets a registrar write only
///      names that exist, and its admin can replace this contract at any time
///      with `addRegistrar` / `removeRegistrar`.
contract WoCoRegistrar is Ownable2Step {
    /// @notice The Durin L2Registry this registrar mints into.
    IL2Registry public immutable registry;

    /// @notice ENSIP-11 coinType for the chain this registrar is deployed on.
    uint256 public immutable coinType;

    /// @notice Platform wallets permitted to call register() directly (sponsored mint path).
    mapping(address sponsor => bool authorised) public authorisedSponsors;

    /// @notice Reserved labels (keyed by labelhash) that can never be minted.
    mapping(bytes32 labelhash => bool reserved) public reserved;

    /// @notice Per-recipient mint accounting for the rate cap. One slot.
    struct MintWindow {
        uint64 start;
        uint32 count;
    }

    /// @notice How many names each RECIPIENT has been minted in its current
    ///         window, and when that window began.
    ///
    /// @dev Keyed on the address that RECEIVES the name, never on
    ///      `msg.sender`. Every mint is submitted by the sponsor key on the
    ///      organiser's behalf, so a cap keyed on the sender would cap the
    ///      whole platform at one organiser's allowance.
    ///
    ///      WHAT THIS BOUNDS, stated honestly (WoCo-Event-App #464): a server
    ///      bug that mints for the same account in a loop, and an account that
    ///      churns names through the product. It does NOT bound whoever holds
    ///      the sponsor key, who chooses the recipient and can use a fresh one
    ///      per mint; bounding that needs a cap on the registrar as a whole,
    ///      which is a separate decision with a launch-day sizing question
    ///      attached (WoCo-Event-App #469). This contract is replaceable
    ///      (`addRegistrar` / `removeRegistrar`), so that can follow.
    ///
    ///      Fixed window, anchored at the recipient's first mint in it. At the
    ///      boundary a recipient can therefore mint up to twice the cap across a
    ///      few seconds; accepted for a backstop, in exchange for one slot per
    ///      recipient and no loops.
    mapping(address recipient => MintWindow) public mintWindow;

    /// @notice Names one recipient may be minted per window. Owner-tunable.
    /// @dev Default 30 per 30 days. Sized so no legitimate organiser meets it —
    ///      a profile name, a name per site and a name per event is the intended
    ///      use — and erring HIGH deliberately: the owner is a multisig, so a cap
    ///      set too low fails a real organiser at the worst moment and needs a
    ///      multisig round to fix, while a cap set high costs nothing until
    ///      abuse that this cap does not bound anyway.
    uint32 public maxMintsPerWindow;

    /// @notice Length of the window in seconds. Owner-tunable, at most
    ///         `MAX_MINT_WINDOW_SECONDS`.
    uint64 public mintWindowSeconds;

    uint256 public constant MIN_LABEL_LENGTH = 3;
    uint256 public constant MAX_LABEL_LENGTH = 63;

    /// @notice The longest window `setMintRateCap` accepts.
    /// @dev The window arithmetic (`start + mintWindowSeconds`) is checked
    ///      `uint64`, so an unbounded window let one owner call make every
    ///      repeat mint revert on overflow (audit 925 finding 3). A year is far
    ///      beyond any window worth setting.
    uint64 public constant MAX_MINT_WINDOW_SECONDS = 366 days;

    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event LabelReservedSet(string label, bool reserved);
    event NameRegistered(string indexed label, address indexed owner, bytes contenthash);
    event ContenthashUpdated(string indexed label, bytes contenthash);
    event MintRateCapSet(uint32 maxMintsPerWindow, uint64 mintWindowSeconds);

    error NotAuthorisedSponsor(address caller);
    error SponsorIsZeroAddress();
    error LabelIsReserved(string label);
    error InvalidLabel(string label);
    error LabelNotRegistered(string label);
    error EmptyContenthash();
    error ArrayLengthMismatch();
    error NameMovedDuringRegistration(bytes32 node);
    error MintRateCapExceeded(address recipient, uint64 windowResetsAt);
    error InvalidMintRateCap();
    error RenounceDisabled();

    modifier onlySponsor() {
        if (!authorisedSponsors[msg.sender]) revert NotAuthorisedSponsor(msg.sender);
        _;
    }

    /// @param _registry       The registry to mint into. Immutable: a new
    ///                        registry means a new registrar.
    /// @param _owner          The owner from the first block — the Safe. Set
    ///                        here rather than transferred after setup, so no
    ///                        deployer key ever holds the role.
    /// @param _sponsor        The first authorised sponsor. Not the zero address.
    /// @param _reservedLabels Labels no one may ever mint.
    constructor(address _registry, address _owner, address _sponsor, string[] memory _reservedLabels)
        Ownable(_owner)
    {
        registry = IL2Registry(_registry);
        coinType = (0x80000000 | block.chainid);

        maxMintsPerWindow = 30;
        mintWindowSeconds = 30 days;
        emit MintRateCapSet(30, 30 days);

        _addSponsor(_sponsor);

        for (uint256 i; i < _reservedLabels.length; ++i) {
            _setReserved(_reservedLabels[i], true);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                MINTING
    //////////////////////////////////////////////////////////////*/

    /// @notice Sponsor-submitted mint: the only way this registrar creates a name.
    function register(
        string calldata label,
        address owner_,
        bytes calldata contenthash,
        string[] calldata textKeys,
        string[] calldata textValues
    ) external onlySponsor returns (bytes32 node) {
        if (!_validLabel(label)) revert InvalidLabel(label);
        if (reserved[keccak256(bytes(label))]) revert LabelIsReserved(label);
        if (textKeys.length != textValues.length) revert ArrayLengthMismatch();
        _consumeMintAllowance(owner_);

        node = registry.createSubnode(registry.baseNode(), label, owner_, new bytes[](0));

        // Forward address records: chain ENSIP-11 coinType + ETH (coinType 60).
        // The sub-ENS name doubles as a USDC receive-alias for the organiser.
        bytes memory addr = abi.encodePacked(owner_);
        registry.setAddr(node, coinType, addr);
        registry.setAddr(node, 60, addr);

        if (contenthash.length > 0) {
            registry.setContenthash(node, contenthash);
        }
        for (uint256 i; i < textKeys.length; ++i) {
            registry.setText(node, textKeys[i], textValues[i]);
        }

        // ONE check, after the last write: the name still belongs to the
        // address it was minted to, so every record above was written to that
        // holder's name. The v2 registry calls nothing outside itself during a
        // registration, so today this cannot fail; it is what keeps that true of
        // any registry that does. In v1 a recipient released the name from its
        // ERC-721 receiver hook, and these writes landed on the freed label for
        // its next registrant (audit 927 H3).
        if (registry.owner(node) != owner_) revert NameMovedDuringRegistration(node);

        emit NameRegistered(label, owner_, contenthash);
    }

    /// @notice Updates a name's Swarm site pointer (called on each site redeploy).
    ///
    /// @dev This is the ONLY post-mint record write the platform retains
    ///      (owner decision, 2026-08-29, WoCo-Event-App #422). `setText` was
    ///      removed in the same pass: it was never called by the server, so it
    ///      was standing authority over holders' profile records purchased with
    ///      no operational benefit at all.
    ///
    ///      A label nobody holds is refused. The registry refuses the write too,
    ///      but only here does the refusal name the label; in v1 neither
    ///      refused, and a pointer set on an unminted label became its first
    ///      holder's site (audit 925 finding 2 / 927 H2).
    ///
    ///      RESIDUAL, STATED PLAINLY SO IT IS NOT REDISCOVERED: this function
    ///      takes an ARBITRARY label. Because the registrar sits in the
    ///      registry's `registrars` set, and a registrar may write the records
    ///      of any name that exists, an authorised sponsor can repoint ANY
    ///      name's contenthash, including one it did not mint. That is retained
    ///      deliberately — automated site redeploy needs it and the organiser is
    ///      not present to sign — but it is real standing authority sitting on
    ///      the hot key `WOCO_SPONSOR_PRIVATE_KEY`.
    ///
    ///      What bounds it: the server calls this only after comparing the
    ///      label's on-chain holder (`getLabelOwner`) with the verified
    ///      `parentAddress` of the authenticated caller — `refuseUnlessOwner` in
    ///      routes/sub-ens.ts, the site-deploy path in routes/sites.ts, and
    ///      `verifyAndBindProfileName` in routes/profiles.ts (WoCo-Event-App).
    ///      That check is application code, not a contract guarantee.
    ///
    ///      WHY THE RESIDUAL IS ACCEPTED RATHER THAN CLOSED NOW, stated
    ///      accurately: a per-redeploy holder signature would defeat automated
    ///      redeploy, but that is not the only shape available — a REVERSIBLE
    ///      per-node "platform-managed" toggle (default on at mint, holder may
    ///      opt out and back in) would bound this at the cost of one signature
    ///      per opt-out, not per redeploy. It is deferred, not ruled out.
    ///
    ///      What makes deferring it safe: unlike the registry, THIS contract is
    ///      not frozen. The registry reaches it through `registrars`, so a
    ///      successor registrar can narrow this post-launch via `addRegistrar` /
    ///      `removeRegistrar`. No registrar-level scheme can bind the registry
    ///      ADMIN, which can enrol any address as a registrar — see
    ///      `L2Registry.adminTransfer`.
    ///
    ///      The blast radius is where a name POINTS, never what it owns or where
    ///      its funds go: address records are written once inside `register`
    ///      and there is no post-mint `setAddr` on this contract.
    function setContenthash(string calldata label, bytes calldata contenthash) external onlySponsor {
        if (contenthash.length == 0) revert EmptyContenthash();
        bytes32 node = registry.makeNode(registry.baseNode(), label);
        if (registry.owner(node) == address(0)) revert LabelNotRegistered(label);
        registry.setContenthash(node, contenthash);
        emit ContenthashUpdated(label, contenthash);
    }

    /*//////////////////////////////////////////////////////////////
                              AVAILABILITY
    //////////////////////////////////////////////////////////////*/

    /// @notice True if `label` is valid, not reserved, and unminted.
    /// @dev Says nothing about the recipient's allowance — that is a property
    ///      of who is receiving, not of the label. See `mintAllowance`.
    function available(string calldata label) external view returns (bool) {
        if (!_validLabel(label)) return false;
        if (reserved[keccak256(bytes(label))]) return false;
        bytes32 node = registry.makeNode(registry.baseNode(), label);
        return registry.owner(node) == address(0);
    }

    /// @notice How many more names `recipient` may be minted right now, and
    ///         when their window resets. For the server and UI to say "you can
    ///         register N more until <date>" instead of surfacing a failed tx.
    function mintAllowance(address recipient) external view returns (uint32 remaining, uint64 windowResetsAt) {
        MintWindow memory w = mintWindow[recipient];
        uint64 nowTs = uint64(block.timestamp);
        if (w.start == 0 || nowTs >= w.start + mintWindowSeconds) {
            return (maxMintsPerWindow, nowTs + mintWindowSeconds);
        }
        remaining = w.count >= maxMintsPerWindow ? 0 : maxMintsPerWindow - w.count;
        windowResetsAt = w.start + mintWindowSeconds;
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    function addSponsor(address sponsor) external onlyOwner {
        _addSponsor(sponsor);
    }

    function removeSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = false;
        emit SponsorRemoved(sponsor);
    }

    function setReserved(string calldata label, bool isReserved) external onlyOwner {
        _setReserved(label, isReserved);
    }

    /// @notice Retune the per-recipient mint cap. Takes effect for every
    ///         recipient's NEXT mint; windows already open keep their start.
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

    /// @notice Disabled: always reverts `RenounceDisabled`.
    /// @dev Renouncing would leave this registrar with no owner for good, and
    ///      every `onlyOwner` power with it: a leaked sponsor key could never be
    ///      removed, and only the registry admin removing the whole registrar
    ///      would stop it minting. `Ownable2Step` makes transfers two-step but
    ///      leaves renounce a single call. `pure` and unguarded, as in
    ///      `WoCoTicketLedger`: there is nothing left to authorise, so every
    ///      caller gets the same answer.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
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

    function _setReserved(string memory label, bool isReserved) internal {
        reserved[keccak256(bytes(label))] = isReserved;
        emit LabelReservedSet(label, isReserved);
    }

    /// @dev Charges one mint to `recipient`'s window, opening a fresh window if
    ///      none is open or the current one has elapsed. Reverts with the reset
    ///      time when the window is full, so a caller can report it.
    function _consumeMintAllowance(address recipient) internal {
        MintWindow memory w = mintWindow[recipient];
        uint64 nowTs = uint64(block.timestamp);
        if (w.start == 0 || nowTs >= w.start + mintWindowSeconds) {
            w.start = nowTs;
            w.count = 0;
        }
        if (w.count >= maxMintsPerWindow) {
            revert MintRateCapExceeded(recipient, w.start + mintWindowSeconds);
        }
        w.count += 1;
        mintWindow[recipient] = w;
    }

    /// @dev Allowed: 3-63 chars, lowercase a-z / 0-9 / hyphen, no leading/trailing/double hyphen.
    function _validLabel(string calldata label) internal pure returns (bool) {
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
