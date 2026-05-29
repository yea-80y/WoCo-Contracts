// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IL2Registry} from "./durin/interfaces/IL2Registry.sol";

/// @title WoCoRegistrar
/// @author WoCo
/// @notice Platform-sponsored registrar that mints organiser sub-ENS names
///         (`label.woco.eth`) on a Durin L2Registry on Arbitrum and writes the
///         organiser's Swarm site pointer + profile records in the same flow.
/// @dev Built on Durin's audited L2Registry (NameStone). This contract is only the
///      minting-policy layer Durin expects you to customise — the registry holds the
///      names and records. Hybrid storage: only small pointers live on-chain
///      (`contenthash` = Swarm bzz ref, `avatar` = Swarm ref); heavy data stays on Swarm.
///      The registrar is granted record-setting authority by being added to the
///      registry's `registrars` set (`addRegistrar`), so the platform can set the
///      Swarm pointer for email-only organisers and update it on each redeploy without
///      the organiser ever signing a transaction.
contract WoCoRegistrar is Ownable {
    /// @notice The Durin L2Registry this registrar mints into.
    IL2Registry public immutable registry;

    /// @notice ENSIP-11 coinType for the chain this registrar is deployed on.
    uint256 public immutable coinType;

    /// @notice Platform wallets permitted to mint (the gas sponsor). Mirrors the
    ///         authorised-sponsor model used by WoCoEvent.
    mapping(address sponsor => bool authorised) public authorisedSponsors;

    /// @notice Reserved labels (keyed by labelhash) that can never be minted.
    mapping(bytes32 labelhash => bool reserved) public reserved;

    uint256 public constant MIN_LABEL_LENGTH = 3;
    uint256 public constant MAX_LABEL_LENGTH = 63;

    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event LabelReservedSet(string label, bool reserved);
    event NameRegistered(string indexed label, address indexed owner, bytes contenthash);
    event ContenthashUpdated(string indexed label, bytes contenthash);

    error NotAuthorisedSponsor(address caller);
    error LabelIsReserved(string label);
    error InvalidLabel(string label);
    error EmptyContenthash();
    error ArrayLengthMismatch();

    modifier onlySponsor() {
        if (!authorisedSponsors[msg.sender]) revert NotAuthorisedSponsor(msg.sender);
        _;
    }

    constructor(address _registry, address _owner) Ownable(_owner) {
        registry = IL2Registry(_registry);
        coinType = (0x80000000 | block.chainid);
    }

    /*//////////////////////////////////////////////////////////////
                                MINTING
    //////////////////////////////////////////////////////////////*/

    /// @notice Mints `label.woco.eth` to `owner_` and sets its records in one flow.
    /// @param label The subname label (validated: 3-63 chars, [a-z0-9-], no edge/double hyphen).
    /// @param owner_ The address that will own the subname NFT (the organiser).
    /// @param contenthash The Swarm site pointer (ENS contenthash bytes); skipped if empty.
    /// @param textKeys Profile text-record keys (e.g. "avatar", "description"); values point at Swarm where large.
    /// @param textValues Matching text-record values.
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

        node = registry.createSubnode(registry.baseNode(), label, owner_, new bytes[](0));

        // Forward address records: the chain's ENSIP-11 coinType + ETH (coinType 60).
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

        emit NameRegistered(label, owner_, contenthash);
    }

    /// @notice Updates a name's Swarm site pointer (called on each site redeploy).
    /// @dev Authorised because this registrar is in the registry's `registrars` set,
    ///      so it can update records even though the organiser owns the name.
    function setContenthash(string calldata label, bytes calldata contenthash) external onlySponsor {
        if (contenthash.length == 0) revert EmptyContenthash();
        bytes32 node = registry.makeNode(registry.baseNode(), label);
        registry.setContenthash(node, contenthash);
        emit ContenthashUpdated(label, contenthash);
    }

    /// @notice Updates a single profile text record for a name.
    function setText(string calldata label, string calldata key, string calldata value) external onlySponsor {
        bytes32 node = registry.makeNode(registry.baseNode(), label);
        registry.setText(node, key, value);
    }

    /*//////////////////////////////////////////////////////////////
                              AVAILABILITY
    //////////////////////////////////////////////////////////////*/

    /// @notice True if `label` is valid, not reserved, and unminted.
    function available(string calldata label) external view returns (bool) {
        if (!_validLabel(label)) return false;
        if (reserved[keccak256(bytes(label))]) return false;
        bytes32 node = registry.makeNode(registry.baseNode(), label);
        return registry.owner(node) == address(0);
    }

    /*//////////////////////////////////////////////////////////////
                                 ADMIN
    //////////////////////////////////////////////////////////////*/

    function addSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = true;
        emit SponsorAdded(sponsor);
    }

    function removeSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = false;
        emit SponsorRemoved(sponsor);
    }

    function setReserved(string calldata label, bool isReserved) external onlyOwner {
        reserved[keccak256(bytes(label))] = isReserved;
        emit LabelReservedSet(label, isReserved);
    }

    /*//////////////////////////////////////////////////////////////
                               VALIDATION
    //////////////////////////////////////////////////////////////*/

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
                if (i == 0 || i == len - 1) return false; // no leading/trailing hyphen
                if (b[i - 1] == 0x2d) return false; // no consecutive hyphens
            }
        }
        return true;
    }
}
