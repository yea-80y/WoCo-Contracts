// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*//////////////////////////////////////////////////////////////
    Shared ENS / NameWrapper / PublicResolver test doubles for the
    L1Resolver suite.

    Extracted from `L1ResolverFallback.t.sol` for WoCo-Event-App #419 so
    `DeployL1Resolver.t.sol` can reuse the same mocks instead of forking a
    second copy that drifts from the first.
//////////////////////////////////////////////////////////////*/

contract MockENS {
    mapping(bytes32 => address) internal _owner;
    mapping(bytes32 => address) internal _resolver;
    mapping(address => mapping(address => bool)) internal _operators;

    function owner(bytes32 node) external view returns (address) {
        return _owner[node];
    }

    function resolver(bytes32 node) external view returns (address) {
        return _resolver[node];
    }

    /// @dev The real registry answers `(owner, operator)`, keyed on the
    ///      approving account - the same shape as ERC-1155's.
    function isApprovedForAll(address account, address operator) external view returns (bool) {
        return _operators[account][operator];
    }

    function setOwner(bytes32 node, address o) external {
        _owner[node] = o;
    }

    function setResolver(bytes32 node, address r) external {
        _resolver[node] = r;
    }

    function setApproval(address account, address operator, bool approved) external {
        _operators[account][operator] = approved;
    }
}

/// @dev `ownerOf` returning zero stands in for a wrapped .eth name past its
///      wrapper expiry (`_clearOwnerAndFuses`), which is what the real
///      NameWrapper does once PARENT_CANNOT_CONTROL is burned.
contract MockNameWrapper {
    mapping(uint256 => address) internal _owner;
    mapping(address => mapping(address => bool)) internal _operators;

    function ownerOf(uint256 id) external view returns (address) {
        return _owner[id];
    }

    function isApprovedForAll(address account, address operator) external view returns (bool) {
        return _operators[account][operator];
    }

    function setOwner(uint256 id, address o) external {
        _owner[id] = o;
    }

    function setApproval(address account, address operator, bool approved) external {
        _operators[account][operator] = approved;
    }

    /// @dev The real NameWrapper exposes exactly this signature and forwards
    ///      it to the ENS registry's own `setResolver` — the wrapper does not
    ///      store resolvers itself, the registry does. Added for #419 so a
    ///      deploy script's SWAP step (`setResolver` on whichever of the
    ///      registry/wrapper actually owns the node) can be executed against
    ///      these mocks exactly as it would run against the real contracts.
    function setResolver(bytes32 node, address r) external {
        MockENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e).setResolver(node, r);
    }
}

/// @dev Stands in for the ENS Public Resolver `0x231b0Ee1…8E63`.
contract MockPublicResolver {
    mapping(bytes32 => bytes) internal _contenthash;
    mapping(bytes32 => mapping(string => string)) internal _text;

    function contenthash(bytes32 node) external view returns (bytes memory) {
        return _contenthash[node];
    }

    function text(bytes32 node, string calldata key) external view returns (string memory) {
        return _text[node][key];
    }

    function setContenthash(bytes32 node, bytes calldata h) external {
        _contenthash[node] = h;
    }

    function setText(bytes32 node, string calldata key, string calldata value) external {
        _text[node][key] = value;
    }
}

contract RevertingResolver {
    error Nope();

    fallback() external {
        revert Nope();
    }
}
