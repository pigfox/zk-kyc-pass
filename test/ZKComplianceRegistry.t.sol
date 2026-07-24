// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {ZKComplianceRegistry} from "../src/ZKComplianceRegistry.sol";
import {Roles} from "../src/Roles.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";

/// @title ZKComplianceRegistryTest
/// @notice Unit coverage for the compliance registry. The Groth16 proof branch
///         is driven through a {MockVerifier}; the real verifier is exercised
///         end-to-end in test/RealProof.t.sol.
contract ZKComplianceRegistryTest is Test {
    ZKComplianceRegistry internal registry;
    MockVerifier internal verifier;

    address internal owner = address(this);
    uint256 internal constant ROOT = uint256(keccak256("root-epoch-1"));
    uint256 internal constant EXPIRY = 4102444800; // 2100-01-01
    uint256 internal constant NULLIFIER = uint256(keccak256("nullifier-1"));

    address internal holder = address(0xA11CE);

    event RootUpdated(uint256 indexed newRoot);
    event ProofRedeemed(address indexed holder, uint256 nullifier, uint256 expiry);
    event VerificationRevoked(address indexed holder);

    // Dummy proof points; the mock ignores them.
    uint256[2] internal pA;
    uint256[2][2] internal pB;
    uint256[2] internal pC;

    function setUp() public {
        verifier = new MockVerifier();
        registry = new ZKComplianceRegistry(address(verifier), ROOT, owner);
    }

    function _signals(address who, uint256 nullifier, uint256 root, uint256 expiry)
        internal
        pure
        returns (uint256[4] memory s)
    {
        s[0] = nullifier;
        s[1] = root;
        s[2] = uint256(uint160(who));
        s[3] = expiry;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsState() public view {
        assertEq(address(registry.verifier()), address(verifier));
        assertEq(registry.currentRoot(), ROOT);
        assertEq(registry.owner(), owner);
        assertTrue(registry.agents(owner));
    }

    function test_Constructor_RevertsOnZeroVerifier() public {
        vm.expectRevert(Roles.ZeroAddress.selector);
        new ZKComplianceRegistry(address(0), ROOT, owner);
    }

    function test_Constructor_EmitsInitialRoot() public {
        vm.expectEmit(true, false, false, false);
        emit RootUpdated(ROOT);
        new ZKComplianceRegistry(address(verifier), ROOT, owner);
    }

    /*//////////////////////////////////////////////////////////////
                                REDEEM
    //////////////////////////////////////////////////////////////*/

    function test_Redeem_HappyPath() public {
        vm.prank(holder);
        vm.expectEmit(true, false, false, true);
        emit ProofRedeemed(holder, NULLIFIER, EXPIRY);
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, EXPIRY));

        assertTrue(registry.isVerified(holder));
        assertEq(registry.verifiedUntil(holder), EXPIRY);
        assertTrue(registry.spentNullifiers(NULLIFIER));
    }

    function test_Redeem_RevertsOnRootMismatch() public {
        uint256 wrongRoot = ROOT + 1;
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ZKComplianceRegistry.RootMismatch.selector, wrongRoot, ROOT));
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, wrongRoot, EXPIRY));
    }

    function test_Redeem_RevertsOnAddressMismatch() public {
        // Signals bound to `holder`, but a different address calls.
        vm.prank(address(0xBEEF));
        vm.expectRevert(
            abi.encodeWithSelector(ZKComplianceRegistry.AddressMismatch.selector, address(0xBEEF))
        );
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, EXPIRY));
    }

    function test_Redeem_RevertsOnExpired() public {
        vm.warp(1_000_000);
        uint256 pastExpiry = 999_999;
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ZKComplianceRegistry.CredentialExpired.selector, pastExpiry));
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, pastExpiry));
    }

    function test_Redeem_RevertsOnExpiryEqualToNow() public {
        vm.warp(1_000_000);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ZKComplianceRegistry.CredentialExpired.selector, 1_000_000));
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, 1_000_000));
    }

    function test_Redeem_RevertsOnSpentNullifier() public {
        vm.prank(holder);
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, EXPIRY));

        // Same nullifier, second holder — replay must be rejected.
        vm.prank(address(0xB0B));
        vm.expectRevert(
            abi.encodeWithSelector(ZKComplianceRegistry.NullifierAlreadySpent.selector, NULLIFIER)
        );
        registry.redeemProof(pA, pB, pC, _signals(address(0xB0B), NULLIFIER, ROOT, EXPIRY));
    }

    function test_Redeem_RevertsOnInvalidProof() public {
        verifier.setShouldVerify(false);
        vm.prank(holder);
        vm.expectRevert(ZKComplianceRegistry.InvalidProof.selector);
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, EXPIRY));
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_IsVerified_FalseBeforeRedeem() public view {
        assertFalse(registry.isVerified(holder));
    }

    function test_IsVerified_LapsesAtExpiry() public {
        vm.warp(1000);
        uint256 expiry = 2000;
        vm.prank(holder);
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, expiry));
        assertTrue(registry.isVerified(holder));

        vm.warp(2000); // now == expiry => no longer verified
        assertFalse(registry.isVerified(holder));
    }

    /*//////////////////////////////////////////////////////////////
                               GOVERNANCE
    //////////////////////////////////////////////////////////////*/

    function test_SetRoot_UpdatesAndEmits() public {
        uint256 newRoot = uint256(keccak256("root-epoch-2"));
        vm.expectEmit(true, false, false, false);
        emit RootUpdated(newRoot);
        registry.setRoot(newRoot);
        assertEq(registry.currentRoot(), newRoot);
    }

    function test_SetRoot_RevertsForNonOwner() public {
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotOwner.selector, holder));
        registry.setRoot(1);
    }

    function test_SetRoot_RotationInvalidatesOldRootProofs() public {
        registry.setRoot(uint256(keccak256("root-epoch-2")));
        vm.prank(holder);
        vm.expectRevert(); // RootMismatch against the old ROOT
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, EXPIRY));
    }

    function test_Revoke_ClearsVerification() public {
        vm.prank(holder);
        registry.redeemProof(pA, pB, pC, _signals(holder, NULLIFIER, ROOT, EXPIRY));
        assertTrue(registry.isVerified(holder));

        vm.expectEmit(true, false, false, false);
        emit VerificationRevoked(holder);
        registry.revoke(holder);
        assertFalse(registry.isVerified(holder));
        assertEq(registry.verifiedUntil(holder), 0);
    }

    function test_Revoke_RevertsForNonAgent() public {
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(Roles.NotAgent.selector, holder));
        registry.revoke(holder);
    }
}
