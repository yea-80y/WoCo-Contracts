// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title WoCoKeyRing
/// @notice Each account's CURRENT KEY RING: the Swarm reference of the blob that seals the
///         account's current secret to every passkey that should hold it (WoCo-Event-App #186).
///
///         The account sets its own entry, in the same operation that changes who may sign for
///         it: removing a passkey is one batch [renew(list without it), setRing(prev, next)], so
///         the key it lost and its place on the list go together or not at all. Readers trust
///         exactly the ring this names and check the blob against the reference, so the ring
///         needs no signature of its own.
///
///         No owner, no admin, no proxy, no pause: nobody but the account moves its entry, and
///         nothing can clear one - an account that once had a ring never reads as having none,
///         which would send readers back to keys a removed passkey still holds.
/// @dev    `expectedPrev` makes every write a compare-and-swap, so two devices changing the
///         account at once cannot silently overwrite each other: the second batch reverts whole.
contract WoCoKeyRing {
    /// @notice The account's current ring reference; zero = the account never set one.
    mapping(address account => bytes32 ring) public ringOf;

    event RingSet(address indexed account, bytes32 indexed prev, bytes32 ring);

    /// @notice The entry moved since the caller read it.
    error StaleRing(bytes32 current);
    /// @notice A ring reference cannot be zero.
    error NoRing();

    function setRing(bytes32 expectedPrev, bytes32 ring) external {
        if (ring == bytes32(0)) revert NoRing();
        bytes32 current = ringOf[msg.sender];
        if (current != expectedPrev) revert StaleRing(current);
        ringOf[msg.sender] = ring;
        emit RingSet(msg.sender, expectedPrev, ring);
    }
}
