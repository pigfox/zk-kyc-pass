// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {Roles} from "../src/Roles.sol";
import {ZKComplianceRegistry} from "../src/ZKComplianceRegistry.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";

/// @title RolesTest
/// @notice Exercises the shared {Roles} base DIRECTLY, through a concrete
///         {ZKComplianceRegistry}, rather than only as a side effect of the
///         contracts that inherit it.
/// @dev WHY THIS FILE EXISTS. `src/Roles.sol` is byte-identical to
///      rwa-tokenization-demo's `src/Roles.sol` apart from its natspec, and that
///      repo gives the base a dedicated test file. This one did not: its role
///      behaviour was asserted only in passing, inside `KYCToken.t.sol` and
///      `ZKComplianceRegistry.t.sol`. Coverage was 100% either way, so nothing
///      failed — but identical code was proven two different ways in two repos,
///      and only one of them proved the base on its own terms. PF-S134 closes
///      that asymmetry by porting the sibling's shape.
///
///      The per-contract role assertions in `KYCToken.t.sol` and
///      `ZKComplianceRegistry.t.sol` are deliberately LEFT IN PLACE. That is
///      also the sibling's shape: rwa asserts `Roles` errors in every one of its
///      per-contract suites AND in its dedicated `Roles.t.sol`. Each child must
///      keep proving it actually applies the modifiers; this file proves what
///      the modifiers themselves do.
contract RolesTest is Test {
    ZKComplianceRegistry internal registry;
    MockVerifier internal verifier;

    address internal owner = address(this);
    address internal alice = address(0xA11CE);
    address internal carol = address(0xCA401);
    address internal stranger = address(0x57A);

    uint256 internal constant ROOT = uint256(keccak256("root-epoch-1"));

    function setUp() public {
        verifier = new MockVerifier();
        registry = new ZKComplianceRegistry(address(verifier), ROOT, owner);
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsOwnerAndFirstAgent() public {
        ZKComplianceRegistry fresh = new ZKComplianceRegistry(address(verifier), ROOT, owner);
        assertEq(fresh.owner(), owner, "owner");
        assertTrue(fresh.agents(owner), "owner is agent");
    }

    function test_Constructor_RevertsOnZeroOwner() public {
        vm.expectRevert(Roles.ZeroAddress.selector);
        new ZKComplianceRegistry(address(verifier), ROOT, address(0));
    }

    function test_Constructor_EmitsOwnershipAndAgent() public {
        vm.expectEmit(true, true, false, false);
        emit Roles.OwnershipTransferred(address(0), owner);
        vm.expectEmit(true, false, false, true);
        emit Roles.AgentSet(owner, true);
        new ZKComplianceRegistry(address(verifier), ROOT, owner);
    }

    /*//////////////////////////////////////////////////////////////
                           TRANSFER OWNERSHIP
    //////////////////////////////////////////////////////////////*/

    function test_TransferOwnership_Succeeds() public {
        vm.expectEmit(true, true, false, false);
        emit Roles.OwnershipTransferred(owner, alice);
        vm.prank(owner);
        registry.transferOwnership(alice);
        assertEq(registry.owner(), alice, "new owner");
    }

    function test_TransferOwnership_DoesNotGrantAgentRole() public {
        vm.prank(owner);
        registry.transferOwnership(carol);
        assertFalse(registry.agents(carol), "new owner is not auto-agent");
    }

    function test_TransferOwnership_RevertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(Roles.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }

    function test_TransferOwnership_RevertsWhenNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotOwner.selector, stranger));
        registry.transferOwnership(stranger);
    }

    /*//////////////////////////////////////////////////////////////
                                SET AGENT
    //////////////////////////////////////////////////////////////*/

    function test_SetAgent_EnablesAndDisables() public {
        vm.expectEmit(true, false, false, true);
        emit Roles.AgentSet(alice, true);
        vm.prank(owner);
        registry.setAgent(alice, true);
        assertTrue(registry.agents(alice), "enabled");

        vm.prank(owner);
        registry.setAgent(alice, false);
        assertFalse(registry.agents(alice), "disabled");
    }

    function test_SetAgent_RevertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(Roles.ZeroAddress.selector);
        registry.setAgent(address(0), true);
    }

    function test_SetAgent_RevertsWhenNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotOwner.selector, stranger));
        registry.setAgent(stranger, true);
    }

    /*//////////////////////////////////////////////////////////////
                              ONLY AGENT
    //////////////////////////////////////////////////////////////*/

    /// @dev `revoke` is the registry's only agent-gated entry point, and it does
    ///      nothing conditional past the modifier, so it isolates `onlyAgent`
    ///      cleanly — a rejection here can only be the modifier.
    function test_OnlyAgent_RevertsForNonAgent() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotAgent.selector, stranger));
        registry.revoke(carol);
    }

    function test_OnlyAgent_AllowsGrantedAgent() public {
        vm.prank(owner);
        registry.setAgent(alice, true);
        vm.prank(alice);
        registry.revoke(carol); // does not revert
        assertFalse(registry.isVerified(carol), "granted agent can revoke");
    }

    /// @dev The owner is an agent from construction, so the agent path is
    ///      reachable without a grant. Distinct from the case above, which
    ///      proves a LATER grant also works.
    function test_OnlyAgent_AllowsOwnerFromConstruction() public {
        vm.prank(owner);
        registry.revoke(carol); // does not revert
        assertFalse(registry.isVerified(carol), "owner is an agent from construction");
    }
}
