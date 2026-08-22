// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WoCoGuardianHook} from "../src/recovery/WoCoGuardianHook.sol";

/// @title DeployGuardianHook
/// @notice Deploys the WoCo guardian hook as a CREATE2 singleton via the canonical
///         deterministic-deployment proxy (0x4e59b44847b379578588920cA78FbF26c0B4956C),
///         so the SAME address comes out on every chain the proxy exists on — the
///         "permissionless cross-chain singleton" WoCo-Event-App #164 asks for.
///         No constructor args, no owner: anyone may redeploy it anywhere, and it
///         does the same thing.
/// @dev   forge script script/DeployGuardianHook.s.sol --rpc-url arb_sepolia --broadcast
///        Env: DEPLOYER_PRIVATE_KEY — pays gas only; holds no power over the contract.
///        Re-running on a chain where it already exists reverts (CREATE2 collision):
///        that is the intended "already deployed" signal, not an error to work around.
contract DeployGuardianHook is Script {
    /// @dev Bump the version string to deploy a NEW singleton address; never reuse a
    ///      salt for changed bytecode (the proxy would just revert anyway).
    bytes32 public constant SALT = keccak256("woco/recovery/guardian-hook/v1");

    function predict() public pure returns (address) {
        bytes32 initCodeHash = keccak256(type(WoCoGuardianHook).creationCode);
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), address(0x4e59b44847b379578588920cA78FbF26c0B4956C), SALT, initCodeHash)
                    )
                )
            )
        );
    }

    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        console.log("predicted address:", predict());
        console.log("deployer (gas only):", vm.addr(deployerPk));

        vm.startBroadcast(deployerPk);
        WoCoGuardianHook hook = new WoCoGuardianHook{salt: SALT}();
        vm.stopBroadcast();

        require(address(hook) == predict(), "address != prediction");
        console.log("WoCoGuardianHook:", address(hook));
        console.log("salt:");
        console.logBytes32(SALT);
        console.log("creationCode hash:");
        console.logBytes32(keccak256(type(WoCoGuardianHook).creationCode));
    }
}
