// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev The live v1 resolver's interface (mainnet 0x172031E6…3Ed8A), for fork
///      tests that read or drive it. v2 changed the settings API, not this one.
interface IL1ResolverV1 {
    function url() external view returns (string memory);
    function signer() external view returns (address);
    function owner() external view returns (address);
    function l2Registry(bytes32 node) external view returns (uint64 chainId, address registryAddress);
    function fallbackResolver(bytes32 node) external view returns (address);
    function setL2Registry(bytes32 node, uint64 targetChainId, address targetRegistryAddress) external;
    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory);
}
