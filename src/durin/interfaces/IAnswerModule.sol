// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice One query as `L1Resolver` hands it to an answer module. `name` and
///         `data` are byte-identical to the ENSIP-10 call; the other three are
///         the settings of the deepest configured ancestor that routed it here.
struct Lookup {
    bytes name;
    bytes data;
    uint64 chainId;
    address registry;
    /// Opaque to `L1Resolver`, set by the name owner. A module ignores data it
    /// does not recognise.
    bytes moduleData;
}

/// @notice A pluggable way to answer the names routed to it: a proof verifier,
///         a name owner's own signer, or an onchain source.
/// @dev Both calls are views made by `L1Resolver`, which stays the EIP-3668
///      `sender`; a module never reverts `OffchainLookup` itself.
interface IAnswerModule is IERC165 {
    /// @return urls     Gateway URLs for the `OffchainLookup`. EMPTY means
    ///                  `callData` is already the final answer.
    /// @return callData The request the gateway receives, and exactly what
    ///                  `verify` is later handed.
    function prepare(Lookup calldata q) external view returns (string[] memory urls, bytes memory callData);

    /// @dev Reverts on anything it cannot vouch for; never returns empty bytes
    ///      to mean "could not verify".
    function verify(Lookup calldata q, bytes calldata callData, bytes calldata response)
        external
        view
        returns (bytes memory result);
}
