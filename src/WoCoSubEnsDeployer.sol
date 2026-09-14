// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {L2Registry} from "./durin/L2Registry.sol";
import {WoCoRegistrar} from "./WoCoRegistrar.sol";

/// @title WoCoSubEnsDeployer
/// @author WoCo
/// @notice Creates WoCo's sub-ENS registry and its registrar in ONE
///         transaction, with both admin roles on `admin` from the start.
///
/// @dev WHY A CONTRACT (WoCo-Contracts #21, audits 924 F-10 / 927 M9). A forge
///      script sends every call as its own transaction, and v1's deploy created
///      the registry clone in one transaction and initialised it in the next.
///      Between the two, anyone could have called `initialize` and taken the
///      admin seat. Here the clone is initialised inside the transaction that
///      creates it, so no such moment exists.
///
///      WHY NO ROTATION. v1 minted the admin seat to the deployer key, then moved
///      it and the registrar's ownership to the Safe with two single-step,
///      irreversible transfers that the whole trust model rested on. Here the
///      seat is minted straight to `admin` and the registrar is constructed
///      owned by it: there is nothing to rotate, and the deployer key never holds
///      a role.
///
///      It keeps no power afterwards; it only records the three addresses. The
///      registrar is NOT wired into the registry: `addRegistrar` is the admin's
///      own transaction.
contract WoCoSubEnsDeployer {
    string public constant TOKEN_SYMBOL = "WoCo Names";

    L2Registry public immutable implementation;
    L2Registry public immutable registry;
    WoCoRegistrar public immutable registrar;

    /// @param parentName     The parent ENS name, e.g. "woco.eth".
    /// @param admin          Holder of the admin seat and owner of the registrar.
    /// @param sponsor        The registrar's first authorised sponsor.
    /// @param reservedLabels Labels the registrar will never mint.
    constructor(string memory parentName, address admin, address sponsor, string[] memory reservedLabels) {
        implementation = new L2Registry();
        registry = L2Registry(Clones.clone(address(implementation)));
        registry.initialize(parentName, TOKEN_SYMBOL, "", admin);
        registrar = new WoCoRegistrar(address(registry), admin, sponsor, reservedLabels);
    }
}
