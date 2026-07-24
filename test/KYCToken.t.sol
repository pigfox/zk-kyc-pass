// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {KYCToken} from "../src/KYCToken.sol";
import {Roles} from "../src/Roles.sol";
import {MockRegistry} from "./mocks/MockRegistry.sol";

/// @title KYCTokenTest
/// @notice Unit coverage for the compliance-gated ERC-20 and the shared Roles
///         base it inherits. Verification is driven through a {MockRegistry} so
///         every mint/transfer branch is reachable without a real proof.
contract KYCTokenTest is Test {
    KYCToken internal token;
    MockRegistry internal registry;

    address internal owner = address(this);
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event AgentSet(address indexed account, bool enabled);

    function setUp() public {
        registry = new MockRegistry();
        token = new KYCToken("ACME RWA Share", "ACME", address(registry), owner);
        registry.setVerified(alice, true);
        registry.setVerified(bob, true);
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsMetadataAndRoles() public view {
        assertEq(token.name(), "ACME RWA Share");
        assertEq(token.symbol(), "ACME");
        assertEq(token.decimals(), 18);
        assertEq(address(token.identityRegistry()), address(registry));
        assertEq(token.owner(), owner);
        assertTrue(token.agents(owner));
        assertEq(token.totalSupply(), 0);
    }

    function test_Constructor_RevertsOnZeroRegistry() public {
        vm.expectRevert(Roles.ZeroAddress.selector);
        new KYCToken("n", "s", address(0), owner);
    }

    function test_Constructor_RevertsOnZeroOwner() public {
        vm.expectRevert(Roles.ZeroAddress.selector);
        new KYCToken("n", "s", address(registry), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                                  MINT
    //////////////////////////////////////////////////////////////*/

    function test_Mint_ToVerified() public {
        vm.expectEmit(true, true, false, true);
        emit Transfer(address(0), alice, 5000 ether);
        token.mint(alice, 5000 ether);
        assertEq(token.balanceOf(alice), 5000 ether);
        assertEq(token.totalSupply(), 5000 ether);
    }

    function test_Mint_RevertsForUnverifiedRecipient() public {
        vm.expectRevert(abi.encodeWithSelector(KYCToken.RecipientNotVerified.selector, carol));
        token.mint(carol, 1 ether);
    }

    function test_Mint_RevertsForZeroRecipient() public {
        vm.expectRevert(Roles.ZeroAddress.selector);
        token.mint(address(0), 1 ether);
    }

    function test_Mint_RevertsForNonAgent() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotAgent.selector, alice));
        token.mint(alice, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                                TRANSFER
    //////////////////////////////////////////////////////////////*/

    function test_Transfer_BothVerified() public {
        token.mint(alice, 1000 ether);
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, 400 ether);
        assertTrue(token.transfer(bob, 400 ether));
        assertEq(token.balanceOf(alice), 600 ether);
        assertEq(token.balanceOf(bob), 400 ether);
        assertEq(token.totalSupply(), 1000 ether); // conserved
    }

    function test_Transfer_RevertsWhenSenderNotVerified() public {
        token.mint(alice, 100 ether);
        registry.setVerified(alice, false);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(KYCToken.SenderNotVerified.selector, alice));
        token.transfer(bob, 1 ether);
    }

    function test_Transfer_RevertsWhenRecipientNotVerified() public {
        token.mint(alice, 100 ether);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(KYCToken.RecipientNotVerified.selector, carol));
        token.transfer(carol, 1 ether);
    }

    function test_Transfer_RevertsOnZeroRecipient() public {
        token.mint(alice, 100 ether);
        vm.prank(alice);
        vm.expectRevert(Roles.ZeroAddress.selector);
        token.transfer(address(0), 1 ether);
    }

    function test_Transfer_RevertsOnInsufficientBalance() public {
        token.mint(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(KYCToken.InsufficientBalance.selector, alice, 1 ether, 2 ether)
        );
        token.transfer(bob, 2 ether);
    }

    /*//////////////////////////////////////////////////////////////
                             APPROVE / FROM
    //////////////////////////////////////////////////////////////*/

    function test_Approve_SetsAllowanceAndEmits() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, 50 ether);
        assertTrue(token.approve(bob, 50 ether));
        assertEq(token.allowance(alice, bob), 50 ether);
    }

    function test_Approve_RevertsOnZeroSpender() public {
        vm.prank(alice);
        vm.expectRevert(Roles.ZeroAddress.selector);
        token.approve(address(0), 1 ether);
    }

    function test_TransferFrom_SpendsFiniteAllowance() public {
        token.mint(alice, 100 ether);
        vm.prank(alice);
        token.approve(bob, 40 ether);

        vm.prank(bob);
        assertTrue(token.transferFrom(alice, bob, 30 ether));
        assertEq(token.balanceOf(bob), 30 ether);
        assertEq(token.allowance(alice, bob), 10 ether);
    }

    function test_TransferFrom_InfiniteAllowanceNotDecremented() public {
        token.mint(alice, 100 ether);
        vm.prank(alice);
        token.approve(bob, type(uint256).max);

        vm.prank(bob);
        token.transferFrom(alice, bob, 30 ether);
        assertEq(token.allowance(alice, bob), type(uint256).max);
    }

    function test_TransferFrom_RevertsOnInsufficientAllowance() public {
        token.mint(alice, 100 ether);
        vm.prank(alice);
        token.approve(bob, 5 ether);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(KYCToken.InsufficientAllowance.selector, alice, bob, 5 ether, 6 ether)
        );
        token.transferFrom(alice, bob, 6 ether);
    }

    /*//////////////////////////////////////////////////////////////
                             ROLES (INHERITED)
    //////////////////////////////////////////////////////////////*/

    function test_Roles_TransferOwnership() public {
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, alice);
        token.transferOwnership(alice);
        assertEq(token.owner(), alice);
    }

    function test_Roles_TransferOwnershipRevertsForNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotOwner.selector, alice));
        token.transferOwnership(alice);
    }

    function test_Roles_TransferOwnershipRevertsOnZero() public {
        vm.expectRevert(Roles.ZeroAddress.selector);
        token.transferOwnership(address(0));
    }

    function test_Roles_SetAgent() public {
        vm.expectEmit(true, false, false, true);
        emit AgentSet(alice, true);
        token.setAgent(alice, true);
        assertTrue(token.agents(alice));

        token.setAgent(alice, false);
        assertFalse(token.agents(alice));
    }

    function test_Roles_SetAgentRevertsForNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotOwner.selector, alice));
        token.setAgent(bob, true);
    }

    function test_Roles_SetAgentRevertsOnZero() public {
        vm.expectRevert(Roles.ZeroAddress.selector);
        token.setAgent(address(0), true);
    }

    function test_NewAgentCanMint() public {
        token.setAgent(alice, true);
        vm.prank(alice);
        token.mint(bob, 1 ether);
        assertEq(token.balanceOf(bob), 1 ether);
    }
}
