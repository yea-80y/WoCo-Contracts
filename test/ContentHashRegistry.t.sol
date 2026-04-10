// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ContentHashRegistry.sol";

contract ContentHashRegistryTest is Test {
    ContentHashRegistry public registry;

    address alice = address(0x1);
    address bob = address(0x2);

    bytes32 hash1 = keccak256("swarm-content-hash-abc123");
    bytes32 hash2 = keccak256("ipfs-cid-xyz789");

    function setUp() public {
        registry = new ContentHashRegistry();
    }

    // ── Register ──

    function test_Register() public {
        vm.prank(alice);
        registry.register(hash1, "WoCo Events", "swarm", "woco.eth", "https://github.com/yea-80y/WoCo-Event-App");

        (
            address owner,
            string memory projectName,
            string memory platform,
            string memory ensName,
            string memory repoUrl,
            uint256 registeredAt,
            bool revoked
        ) = registry.getRegistration(hash1);

        assertEq(owner, alice);
        assertEq(projectName, "WoCo Events");
        assertEq(platform, "swarm");
        assertEq(ensName, "woco.eth");
        assertEq(repoUrl, "https://github.com/yea-80y/WoCo-Event-App");
        assertGt(registeredAt, 0);
        assertFalse(revoked);

        assertTrue(registry.isVerified(hash1));
        assertEq(registry.registrationCount(), 1);
    }

    function test_Register_MinimalMetadata() public {
        vm.prank(alice);
        registry.register(hash1, "My App", "web", "", "");

        assertTrue(registry.isVerified(hash1));

        (, , , string memory ensName, string memory repoUrl, , ) = registry.getRegistration(hash1);
        assertEq(ensName, "");
        assertEq(repoUrl, "");
    }

    function test_Register_RevertIfDuplicate() public {
        vm.prank(alice);
        registry.register(hash1, "App A", "swarm", "", "");

        vm.prank(bob);
        vm.expectRevert("Hash already registered");
        registry.register(hash1, "App B", "ipfs", "", "");
    }

    function test_Register_RevertIfEmptyHash() public {
        vm.prank(alice);
        vm.expectRevert("Empty content hash");
        registry.register(bytes32(0), "App", "swarm", "", "");
    }

    function test_Register_RevertIfEmptyProjectName() public {
        vm.prank(alice);
        vm.expectRevert("Project name required");
        registry.register(hash1, "", "swarm", "", "");
    }

    function test_Register_RevertIfEmptyPlatform() public {
        vm.prank(alice);
        vm.expectRevert("Platform required");
        registry.register(hash1, "App", "", "", "");
    }

    // ── Update ──

    function test_Update() public {
        vm.prank(alice);
        registry.register(hash1, "App v1", "swarm", "", "");

        vm.prank(alice);
        registry.update(hash1, "App v2", "ipfs", "app.eth", "https://github.com/app");

        (, string memory projectName, string memory platform, string memory ensName, string memory repoUrl, , ) =
            registry.getRegistration(hash1);

        assertEq(projectName, "App v2");
        assertEq(platform, "ipfs");
        assertEq(ensName, "app.eth");
        assertEq(repoUrl, "https://github.com/app");
    }

    function test_Update_RevertIfNotOwner() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(bob);
        vm.expectRevert("Not registration owner");
        registry.update(hash1, "Hijacked", "web", "", "");
    }

    function test_Update_RevertIfRevoked() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(alice);
        registry.revoke(hash1);

        vm.prank(alice);
        vm.expectRevert("Hash is revoked");
        registry.update(hash1, "Updated", "swarm", "", "");
    }

    // ── Revoke ──

    function test_Revoke() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(alice);
        registry.revoke(hash1);

        assertFalse(registry.isVerified(hash1));

        (, , , , , , bool revoked) = registry.getRegistration(hash1);
        assertTrue(revoked);
    }

    function test_Revoke_RevertIfNotOwner() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(bob);
        vm.expectRevert("Not registration owner");
        registry.revoke(hash1);
    }

    function test_Revoke_RevertIfAlreadyRevoked() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(alice);
        registry.revoke(hash1);

        vm.prank(alice);
        vm.expectRevert("Already revoked");
        registry.revoke(hash1);
    }

    // ── Re-register after revoke ──

    function test_ReregisterAfterRevoke() public {
        vm.prank(alice);
        registry.register(hash1, "App v1", "swarm", "", "");

        vm.prank(alice);
        registry.revoke(hash1);

        // Bob can re-register a revoked hash
        vm.prank(bob);
        registry.register(hash1, "App v2", "ipfs", "new.eth", "");

        (address owner, string memory projectName, , , , , bool revoked) = registry.getRegistration(hash1);
        assertEq(owner, bob);
        assertEq(projectName, "App v2");
        assertFalse(revoked);
        assertTrue(registry.isVerified(hash1));

        // Registration count should NOT increase (re-registration reuses the slot)
        assertEq(registry.registrationCount(), 1);
    }

    // ── Owner hashes ──

    function test_GetOwnerHashes() public {
        vm.startPrank(alice);
        registry.register(hash1, "App 1", "swarm", "", "");
        registry.register(hash2, "App 2", "ipfs", "", "");
        vm.stopPrank();

        bytes32[] memory hashes = registry.getOwnerHashes(alice);
        assertEq(hashes.length, 2);
        assertEq(hashes[0], hash1);
        assertEq(hashes[1], hash2);

        assertEq(registry.getOwnerHashCount(alice), 2);
    }

    function test_GetOwnerHashes_Empty() public view {
        bytes32[] memory hashes = registry.getOwnerHashes(alice);
        assertEq(hashes.length, 0);
        assertEq(registry.getOwnerHashCount(alice), 0);
    }

    // ── isVerified edge cases ──

    function test_IsVerified_UnregisteredHash() public view {
        assertFalse(registry.isVerified(hash1));
    }

    function test_IsVerified_RevokedHash() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(alice);
        registry.revoke(hash1);

        assertFalse(registry.isVerified(hash1));
    }

    // ── Registration count ──

    function test_RegistrationCount() public {
        assertEq(registry.registrationCount(), 0);

        vm.prank(alice);
        registry.register(hash1, "App 1", "swarm", "", "");
        assertEq(registry.registrationCount(), 1);

        vm.prank(bob);
        registry.register(hash2, "App 2", "ipfs", "", "");
        assertEq(registry.registrationCount(), 2);
    }

    // ── Events ──

    function test_EmitHashRegistered() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit ContentHashRegistry.HashRegistered(hash1, alice, "App", "swarm");
        registry.register(hash1, "App", "swarm", "", "");
    }

    function test_EmitHashUpdated() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(alice);
        vm.expectEmit(true, true, false, false);
        emit ContentHashRegistry.HashUpdated(hash1, alice);
        registry.update(hash1, "App v2", "swarm", "", "");
    }

    function test_EmitHashRevoked() public {
        vm.prank(alice);
        registry.register(hash1, "App", "swarm", "", "");

        vm.prank(alice);
        vm.expectEmit(true, true, false, false);
        emit ContentHashRegistry.HashRevoked(hash1, alice);
        registry.revoke(hash1);
    }
}
