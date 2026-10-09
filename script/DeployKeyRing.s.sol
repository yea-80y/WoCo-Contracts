// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WoCoKeyRing} from "../src/WoCoKeyRing.sol";

/// @title DeployKeyRing
/// @notice Deploys the WoCo key-ring anchor as a CREATE2 singleton via the canonical
///         deterministic-deployment proxy (0x4e59b44847b379578588920cA78FbF26c0B4956C), so the
///         SAME address comes out on every chain the proxy exists on. No constructor args, no
///         owner: anyone may redeploy it anywhere, and it does the same thing.
/// @dev   forge script script/DeployKeyRing.s.sol --rpc-url <chain> --broadcast
///        Env: DEPLOYER_PRIVATE_KEY - pays gas only; holds no power over the contract.
///        Re-running on a chain where it already exists reverts (CREATE2 collision): that is the
///        intended "already deployed" signal, not an error to work around.
contract DeployKeyRing is Script {
    /// @dev Bump the version string to deploy a NEW singleton address; never reuse a salt for
    ///      changed bytecode.
    bytes32 public constant SALT = keccak256("woco/keyring/anchor/v1");

    function predict() public pure returns (address) {
        bytes32 initCodeHash = keccak256(type(WoCoKeyRing).creationCode);
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
        WoCoKeyRing reg = new WoCoKeyRing{salt: SALT}();
        vm.stopBroadcast();

        require(address(reg) == predict(), "address != prediction");
        console.log("WoCoKeyRing:", address(reg));
        console.log("creationCode hash:");
        console.logBytes32(keccak256(type(WoCoKeyRing).creationCode));
    }
}
