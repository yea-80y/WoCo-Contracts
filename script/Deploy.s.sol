// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/WoCoEscrow.sol";

contract DeployWoCoEscrow is Script {
    function run() external {
        uint256 deployerKey  = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address arbitrator   = vm.envAddress("ARBITRATOR_ADDRESS");
        address feeRecipient = vm.envAddress("FEE_RECIPIENT_ADDRESS");

        vm.startBroadcast(deployerKey);

        WoCoEscrow escrow = new WoCoEscrow(arbitrator, feeRecipient);

        vm.stopBroadcast();

        console.log("WoCoEscrow deployed to:", address(escrow));
        console.log("  arbitrator:    ", arbitrator);
        console.log("  feeRecipient:  ", feeRecipient);
    }
}
