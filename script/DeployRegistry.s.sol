// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/ContentHashRegistry.sol";

contract DeployContentHashRegistry is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerKey);

        ContentHashRegistry registry = new ContentHashRegistry();

        vm.stopBroadcast();

        console.log("ContentHashRegistry deployed to:", address(registry));
    }
}
