// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ContentHashRegistry
 * @notice On-chain registry for verified frontend/dapp content hashes.
 *
 * Project owners register their deployment content hashes (Swarm, IPFS, web)
 * so wallets and users can verify a frontend is genuine before interacting.
 *
 * Design:
 *   - No admin key, no proxy, no pause — fully immutable trust anchor
 *   - Owner-based: msg.sender registers, only they can update/revoke
 *   - bytes32 content hash — Swarm refs are natively 32 bytes;
 *     IPFS CIDv0 can be keccak256'd; web bundles use keccak256(bundle)
 *   - Revocation is soft-delete; revoked hashes can be re-registered by anyone
 *   - Events emitted for off-chain indexing (subgraphs, frontends)
 */
contract ContentHashRegistry {

    struct Registration {
        address owner;          // msg.sender who registered this hash
        string projectName;     // human-readable: "WoCo Events", "Uniswap", etc.
        string platform;        // "swarm", "ipfs", "web"
        string ensName;         // optional: "woco.eth", "" if none
        string repoUrl;         // optional: "https://github.com/..."
        uint256 registeredAt;   // block.timestamp of registration
        bool revoked;           // true = soft-deleted by owner
    }

    // Content hash → registration details
    mapping(bytes32 => Registration) private _registrations;

    // Owner → list of content hashes they've registered
    mapping(address => bytes32[]) private _ownerHashes;

    // Total number of registrations (including revoked)
    uint256 public registrationCount;

    // ── Events ──

    event HashRegistered(
        bytes32 indexed contentHash,
        address indexed owner,
        string projectName,
        string platform
    );

    event HashUpdated(
        bytes32 indexed contentHash,
        address indexed owner
    );

    event HashRevoked(
        bytes32 indexed contentHash,
        address indexed owner
    );

    // ── Modifiers ──

    modifier onlyOwner(bytes32 contentHash) {
        require(
            _registrations[contentHash].owner == msg.sender,
            "Not registration owner"
        );
        _;
    }

    // ── Write functions ──

    /**
     * @notice Register a content hash. Reverts if already registered and not revoked.
     * @param contentHash   32-byte content hash (Swarm ref, keccak256 of IPFS CID, etc.)
     * @param projectName   Human-readable project name
     * @param platform      Hosting platform: "swarm", "ipfs", "web"
     * @param ensName       Optional ENS name (pass "" if none)
     * @param repoUrl       Optional source repo URL (pass "" if none)
     */
    function register(
        bytes32 contentHash,
        string calldata projectName,
        string calldata platform,
        string calldata ensName,
        string calldata repoUrl
    ) external {
        require(contentHash != bytes32(0), "Empty content hash");
        require(bytes(projectName).length > 0, "Project name required");
        require(bytes(platform).length > 0, "Platform required");

        Registration storage reg = _registrations[contentHash];
        require(
            reg.owner == address(0) || reg.revoked,
            "Hash already registered"
        );

        // If re-registering a revoked hash, it's a fresh registration
        bool isNew = reg.owner == address(0);

        _registrations[contentHash] = Registration({
            owner: msg.sender,
            projectName: projectName,
            platform: platform,
            ensName: ensName,
            repoUrl: repoUrl,
            registeredAt: block.timestamp,
            revoked: false
        });

        _ownerHashes[msg.sender].push(contentHash);

        if (isNew) {
            registrationCount++;
        }

        emit HashRegistered(contentHash, msg.sender, projectName, platform);
    }

    /**
     * @notice Update metadata for a registered hash. Only the owner can update.
     * @param contentHash   The content hash to update
     * @param projectName   New project name
     * @param platform      New platform
     * @param ensName       New ENS name
     * @param repoUrl       New repo URL
     */
    function update(
        bytes32 contentHash,
        string calldata projectName,
        string calldata platform,
        string calldata ensName,
        string calldata repoUrl
    ) external onlyOwner(contentHash) {
        require(!_registrations[contentHash].revoked, "Hash is revoked");
        require(bytes(projectName).length > 0, "Project name required");
        require(bytes(platform).length > 0, "Platform required");

        Registration storage reg = _registrations[contentHash];
        reg.projectName = projectName;
        reg.platform = platform;
        reg.ensName = ensName;
        reg.repoUrl = repoUrl;

        emit HashUpdated(contentHash, msg.sender);
    }

    /**
     * @notice Revoke a registration. Only the owner can revoke.
     *         The hash can be re-registered by anyone after revocation.
     * @param contentHash   The content hash to revoke
     */
    function revoke(bytes32 contentHash) external onlyOwner(contentHash) {
        require(!_registrations[contentHash].revoked, "Already revoked");

        _registrations[contentHash].revoked = true;

        emit HashRevoked(contentHash, msg.sender);
    }

    // ── View functions ──

    /**
     * @notice Check if a content hash is verified (registered and not revoked).
     * @param contentHash   The content hash to check
     * @return True if the hash is registered and not revoked
     */
    function isVerified(bytes32 contentHash) external view returns (bool) {
        Registration storage reg = _registrations[contentHash];
        return reg.owner != address(0) && !reg.revoked;
    }

    /**
     * @notice Get the full registration details for a content hash.
     * @param contentHash   The content hash to look up
     * @return owner         The address that registered this hash
     * @return projectName   The project name
     * @return platform      The hosting platform
     * @return ensName       The ENS name (may be empty)
     * @return repoUrl       The repo URL (may be empty)
     * @return registeredAt  The timestamp of registration
     * @return revoked       Whether the registration has been revoked
     */
    function getRegistration(bytes32 contentHash) external view returns (
        address owner,
        string memory projectName,
        string memory platform,
        string memory ensName,
        string memory repoUrl,
        uint256 registeredAt,
        bool revoked
    ) {
        Registration storage reg = _registrations[contentHash];
        return (
            reg.owner,
            reg.projectName,
            reg.platform,
            reg.ensName,
            reg.repoUrl,
            reg.registeredAt,
            reg.revoked
        );
    }

    /**
     * @notice Get all content hashes registered by an address.
     * @param owner   The address to look up
     * @return Array of content hashes (may include revoked entries)
     */
    function getOwnerHashes(address owner) external view returns (bytes32[] memory) {
        return _ownerHashes[owner];
    }

    /**
     * @notice Get the number of hashes registered by an address.
     * @param owner   The address to look up
     * @return The count of registered hashes
     */
    function getOwnerHashCount(address owner) external view returns (uint256) {
        return _ownerHashes[owner].length;
    }
}
