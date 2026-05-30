// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {IL2Registry} from "../src/durin/interfaces/IL2Registry.sol";

/// @notice Minimal interface to Durin's canonical L2RegistryFactory.
interface IL2RegistryFactory {
    function deployRegistry(string calldata name, string memory symbol, string memory baseURI, address admin)
        external
        returns (address);
}

/// @title DeploySubEnsRegistry
/// @notice Creates WoCo's sub-ENS registry on an L2 via Durin's canonical factory,
///         deploys WoCoRegistrar, wires it in, and seeds sponsor + reserved names.
/// @dev Run against Arbitrum Sepolia first:
///        forge script script/DeploySubEnsRegistry.s.sol --rpc-url arb_sepolia --broadcast
///      Env: DEPLOYER_PRIVATE_KEY (deployer = registry admin + registrar owner), SPONSOR_ADDRESS
///      (platform gas-sponsor wallet authorised to mint). PARENT_NAME defaults to "woco.eth".
contract DeploySubEnsRegistry is Script {
    // Durin's L2RegistryFactory — same address on every supported chain (incl. Arbitrum + Arb Sepolia).
    address constant L2_REGISTRY_FACTORY = 0xDddddDdDDD8Aa1f237b4fa0669cb46892346d22d;

    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);
        address sponsor = vm.envAddress("SPONSOR_ADDRESS");
        // Platform signer: address whose off-chain signature authorises registerWithPermit.
        // For buildathon: same address as sponsor. Post-buildathon: use a separate cold key.
        address platformSigner = vm.envOr("PLATFORM_SIGNER_ADDRESS", sponsor);
        string memory parentName = vm.envOr("PARENT_NAME", string("woco.eth"));

        vm.startBroadcast(deployerPk);

        // 1. Create our registry via the canonical factory (deployer = admin / owner of the base node).
        address registryAddr =
            IL2RegistryFactory(L2_REGISTRY_FACTORY).deployRegistry(parentName, "WoCo Names", "", deployer);
        IL2Registry registry = IL2Registry(registryAddr);

        // 2. Deploy our minting-policy layer.
        WoCoRegistrar registrar = new WoCoRegistrar(registryAddr, deployer, platformSigner);

        // 3. Grant the registrar record-setting + minting authority on the registry.
        registry.addRegistrar(address(registrar));

        // 4. Authorise the platform gas-sponsor wallet to mint.
        registrar.addSponsor(sponsor);

        // 5. Reserve platform / impersonation-risk labels.
        string[8] memory reservedLabels =
            ["woco", "admin", "support", "help", "www", "api", "app", "mail"];
        for (uint256 i; i < reservedLabels.length; ++i) {
            registrar.setReserved(reservedLabels[i], true);
        }

        vm.stopBroadcast();

        console.log("Parent name:      ", parentName);
        console.log("L2Registry:       ", registryAddr);
        console.log("WoCoRegistrar:    ", address(registrar));
        console.log("Registry admin:   ", deployer);
        console.log("Authorised sponsor:", sponsor);
        console.log("Platform signer:  ", platformSigner);
    }
}
