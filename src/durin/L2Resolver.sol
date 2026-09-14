// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ***********************************************
// ▗▖  ▗▖ ▗▄▖ ▗▖  ▗▖▗▄▄▄▖ ▗▄▄▖▗▄▄▄▖▗▄▖ ▗▖  ▗▖▗▄▄▄▖
// ▐▛▚▖▐▌▐▌ ▐▌▐▛▚▞▜▌▐▌   ▐▌     █ ▐▌ ▐▌▐▛▚▖▐▌▐▌
// ▐▌ ▝▜▌▐▛▀▜▌▐▌  ▐▌▐▛▀▀▘ ▝▀▚▖  █ ▐▌ ▐▌▐▌ ▝▜▌▐▛▀▀▘
// ▐▌  ▐▌▐▌ ▐▌▐▌  ▐▌▐▙▄▄▖▗▄▄▞▘  █ ▝▚▄▞▘▐▌  ▐▌▐▙▄▄▖
// ***********************************************

import {ABIResolver} from "@ensdomains/ens-contracts/resolvers/profiles/ABIResolver.sol";
import {AddrResolver} from "@ensdomains/ens-contracts/resolvers/profiles/AddrResolver.sol";
import {ContentHashResolver} from "@ensdomains/ens-contracts/resolvers/profiles/ContentHashResolver.sol";
import {ExtendedResolver} from "@ensdomains/ens-contracts/resolvers/profiles/ExtendedResolver.sol";
import {IExtendedResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {Multicallable} from "@ensdomains/ens-contracts/resolvers/Multicallable.sol";
import {TextResolver} from "@ensdomains/ens-contracts/resolvers/profiles/TextResolver.sol";

/// @title Durin Resolver
/// @author NameStone
/// @notice Resolver to store standard ENS records
/// @dev Inherited by L2Registry, which holds the ownership state and so decides
///      who may write a name's records.
///
/// VENDORED + MODIFIED BY WOCO — v2 (WoCo-Contracts #21).
///
/// REMOVED: the four `set*WithSignature` setters, and with them the `nonces`
/// WoCo had added for them (#10). Their shared authorisation check accepted
/// `signer = address(0)` for any name without a per-token approval, and the
/// ERC-6492 validator's ECDSA fallback accepts an all-zero signature for that
/// signer, so any caller could rewrite any name's records (audit 924 F-1).
/// Nothing called them. A relayed record write, if one is ever wanted, belongs
/// in a registrar, which the registry admin can replace.
///
/// CHANGED: `isAuthorisedForAddress` is gone. Every record write reaches ONE
/// predicate, `_canWriteRecords`, which the registry implements.
///
/// ADDED: `supportsInterface` reports `IExtendedResolver`, which this contract
/// has always implemented (audit 924 F-16).
abstract contract L2Resolver is
    Multicallable,
    ABIResolver,
    AddrResolver,
    ContentHashResolver,
    TextResolver,
    ExtendedResolver
{
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error Unauthorized(bytes32 node);

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Whether `writer` may change `node`'s records. Every inherited record
    ///      setter and `clearRecords` reach it through `isAuthorised`, with
    ///      `msg.sender` as the writer — so there is one rule to audit, not one
    ///      per setter.
    function _canWriteRecords(address writer, bytes32 node) internal view virtual returns (bool);

    /*//////////////////////////////////////////////////////////////
                           REQUIRED OVERRIDES
    //////////////////////////////////////////////////////////////*/

    /// @dev Reverts instead of returning false so the modifier that uses this function has better error messages
    function isAuthorised(bytes32 node) internal view override returns (bool) {
        if (!_canWriteRecords(msg.sender, node)) {
            revert Unauthorized(node);
        }
        return true;
    }

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(
            Multicallable,
            ABIResolver,
            AddrResolver,
            ContentHashResolver,
            TextResolver
        )
        returns (bool)
    {
        return
            interfaceId == type(IExtendedResolver).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
