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
///         deploys WoCoRegistrar, wires it in, seeds sponsor + reserved names, and
///         hands both admin roles to `REGISTRY_ADMIN` before it returns.
///
/// @dev Run against Arbitrum Sepolia first:
///        forge script script/DeploySubEnsRegistry.s.sol --rpc-url arb_sepolia --broadcast
///
///      Required env:
///        DEPLOYER_PRIVATE_KEY — deployer EOA. Holds both admin roles only for the
///                               length of this script; see the rotation step below.
///        SPONSOR_ADDRESS      — platform gas-sponsor wallet authorised to mint.
///        REGISTRY_ADMIN       — the address that ENDS UP holding `baseNode` and
///                               owning WoCoRegistrar. REQUIRED, no default.
///      Optional env:
///        PLATFORM_SIGNER_ADDRESS — signer for registerWithPermit (defaults to sponsor).
///        PARENT_NAME             — defaults to "woco.eth".
///        ALLOW_EOA_ADMIN         — testnet escape hatch; see the guard below.
///
/// WHY THE ROTATION IS IN THE SCRIPT AND NOT A RUNBOOK STEP
///
/// Registry admin is not a role flag — it is ownership of the `baseNode` ERC-721
/// (`L2Registry.owner()` returns `owner(baseNode)`, and `initialize` mints that
/// token to whoever the factory was handed as `admin`). Whoever holds it can call
/// `addRegistrar(itself)` and then write records — `setAddr` included — for ANY
/// name in the registry, because `onlyOwnerOrRegistrar` scopes to registrar
/// MEMBERSHIP, not to a node. It can also `adminTransfer` any name to itself.
///
/// The registry is an EIP-1167 clone and cannot be upgraded, and the #422
/// decision to ship `adminTransfer` with NO TIMELOCK rests entirely on that
/// power sitting behind a multisig rather than one key. A deploy that ends with
/// the deployer EOA still holding `baseNode` therefore does not merely leave a
/// chore outstanding — it invalidates the premise the contract was reviewed on,
/// silently, and the previous version of this script did exactly that.
///
/// ⚠️ BOTH TRANSFERS BELOW ARE SINGLE-STEP AND IRREVERSIBLE. `baseNode` sent to
/// an address that cannot transact is the whole registry lost with no recovery
/// path; `WoCoRegistrar` is plain `Ownable` (not `Ownable2Step`), so the same
/// mistake there permanently freezes `addSponsor` / `setReserved` /
/// `setPlatformSigner`. Verify `REGISTRY_ADMIN` on a block explorer before
/// broadcasting. The guard below rejects an EOA, which catches a typo'd or
/// forgotten value, but it CANNOT catch a well-formed address you do not control.
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

        // Required, not defaulted. Defaulting this to `deployer` is precisely the
        // outcome the header describes, and a console warning is not a safeguard
        // because forge script output scrolls past.
        address registryAdmin = vm.envAddress("REGISTRY_ADMIN");
        require(registryAdmin != address(0), "REGISTRY_ADMIN must not be the zero address");

        // A multisig is a contract; the deployer EOA is not. This is a coarse
        // check and deliberately so — it cannot verify signers or a threshold,
        // only that the deploy is not ending on a bare key. Testnet iteration
        // sets ALLOW_EOA_ADMIN=true and accepts that the #422 premise does not
        // hold there.
        bool allowEoaAdmin = vm.envOr("ALLOW_EOA_ADMIN", false);
        require(
            allowEoaAdmin || registryAdmin.code.length > 0,
            "REGISTRY_ADMIN has no code - expected a multisig; set ALLOW_EOA_ADMIN=true for testnet"
        );

        vm.startBroadcast(deployerPk);

        // 1. Create our registry via the canonical factory. The deployer takes
        //    admin only because steps 3-5 are `onlyOwner` and the multisig would
        //    otherwise have to sign each of them; step 6 hands it straight on.
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

        // 6. Hand both admin roles over. LAST, because everything above needs them.
        //
        //    `transferFrom`, not `safeTransferFrom`: the safe variant calls
        //    `onERC721Received` on the recipient, which a Safe answers only
        //    through its fallback handler. A multisig deployed without one would
        //    revert here and strand the whole deploy mid-broadcast, with the
        //    registry live and the deployer still holding it — the exact state
        //    this step exists to prevent. The recipient is asserted to be a
        //    contract above and verified by the operator; a Safe can move any
        //    ERC-721 it holds regardless of how it received it.
        bytes32 baseNode = registry.baseNode();
        registry.transferFrom(deployer, registryAdmin, uint256(baseNode));
        registrar.transferOwnership(registryAdmin);

        vm.stopBroadcast();

        // 7. Prove the rotation landed. A deploy that reports success while the
        //    deployer still holds either role is the failure mode with no
        //    external signal — nothing else on chain looks different.
        require(registry.owner() == registryAdmin, "registry admin rotation did not land");
        require(registrar.owner() == registryAdmin, "registrar ownership rotation did not land");

        console.log("Parent name:      ", parentName);
        console.log("L2Registry:       ", registryAddr);
        console.log("WoCoRegistrar:    ", address(registrar));
        console.log("Registry admin:   ", registryAdmin);
        console.log("Registrar owner:  ", registryAdmin);
        console.log("Deployer (no roles retained):", deployer);
        console.log("Authorised sponsor:", sponsor);
        console.log("Platform signer:  ", platformSigner);
    }
}
