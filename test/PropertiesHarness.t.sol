// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {Properties} from "./Properties.sol";

/// @title PropertiesHarnessTest
/// @notice Proves the shared fuzz harness is not vacuous: a property suite that
///         silently never reaches an interesting state reports green forever.
///         These tests drive the harness' entry points deterministically and
///         assert each reachable outcome — and each invariant-defeating attempt —
///         actually happens, so a green Echidna/Medusa/Foundry run means something.
contract PropertiesHarnessTest is Test {
    Properties internal p;

    function setUp() public {
        p = new Properties();
    }

    function test_Harness_RedeemThenMintThenTransfer() public {
        // Actor 0 and actor 1 redeem; actor 0 is minted to and transfers to 1.
        p.redeem(0, 1);
        assertEq(p.ghost_redeems(), 1, "actor 0 redeemed");
        p.redeem(1, 2);
        assertEq(p.ghost_redeems(), 2, "actor 1 redeemed");

        p.mint(0, 1000 ether);
        assertEq(p.ghost_mints(), 1, "actor 0 minted");
        assertEq(p.token().balanceOf(address(p.poolActorAt(0))), _bounded(1000 ether), "balance credited");

        p.transfer(0, 1, 100 ether);
        assertEq(p.ghost_transfers(), 1, "transfer went through");
        _assertAll();
    }

    function test_Harness_ReplayIsRejectedInEpoch() public {
        // nullifierSeed 0 => nullifier 1 (harness bounds seed as 1 + seed % 8).
        p.redeem(0, 0); // nullifier 1 spent by actor 0
        assertEq(p.nullifierRedeemCount(1), 1, "spent once");

        // Actor 1 tries the SAME nullifier under the same root — rejected.
        p.redeem(1, 0);
        assertEq(p.nullifierRedeemCount(1), 1, "still spent exactly once");
        assertFalse(p.nullifierReuseSeen(), "no reuse observed");
        _assertAll();
    }

    function test_Harness_SpentNullifierStaysSpentAcrossRotation() public {
        // spentNullifiers is global: the SAME integer nullifier can never redeem
        // twice, even after a root rotation. (Cross-epoch re-verification happens
        // in reality with a DIFFERENT nullifier the circuit derives per root — a
        // circuit-level property, exercised in test/circuit.)
        p.redeem(0, 0); // nullifier 1
        assertEq(p.nullifierRedeemCount(1), 1, "spent once");

        p.rotateRoot(42); // new epoch — does NOT clear spentNullifiers
        p.redeem(1, 0); // same integer nullifier 1 — still globally spent, rejected
        assertEq(p.nullifierRedeemCount(1), 1, "still spent exactly once");
        assertFalse(p.nullifierReuseSeen(), "no reuse observed");
        _assertAll();
    }

    function test_Harness_BadProofDoesNotRedeem() public {
        p.setVerifierVerdict(false);
        p.redeem(0, 1);
        assertEq(p.ghost_redeems(), 0, "no redemption on a failed proof");
        assertFalse(p.token().identityRegistry().isVerified(address(p.poolActorAt(0))), "not verified");
        _assertAll();
    }

    function test_Harness_UnverifiedCannotBeMinted() public {
        // Actor 2 never redeemed, so it is unverified.
        p.mint(2, 1000 ether);
        assertEq(p.ghost_mints(), 0, "mint to unverified rejected");
        assertFalse(p.unverifiedMovedTokens(), "guard held");
        _assertAll();
    }

    function test_Harness_RevokedHolderCannotTransfer() public {
        p.redeem(0, 1);
        p.redeem(1, 2);
        p.mint(0, 1000 ether);

        p.revoke(0); // actor 0 loses verification while holding tokens
        assertFalse(p.token().identityRegistry().isVerified(address(p.poolActorAt(0))), "revoked");

        p.transfer(0, 1, 10 ether);
        assertEq(p.ghost_transfers(), 0, "revoked holder cannot transfer");
        assertFalse(p.unverifiedMovedTokens(), "guard held");
        _assertAll();
    }

    function test_Harness_TransferToUnverifiedRejected() public {
        p.redeem(0, 1);
        p.mint(0, 1000 ether);
        // Actor 3 is unverified — cannot receive.
        p.transfer(0, 3, 10 ether);
        assertEq(p.ghost_transfers(), 0, "transfer to unverified rejected");
        assertFalse(p.unverifiedMovedTokens(), "guard held");
        _assertAll();
    }

    function test_Harness_SupplyConservedAcrossTransfer() public {
        p.redeem(0, 1);
        p.redeem(1, 2);
        p.mint(0, 500 ether);
        p.mint(1, 300 ether);
        p.transfer(0, 1, 200 ether);
        assertTrue(p.echidna_supply_conserved(), "supply conserved");
        assertEq(p.totalMinted(), _bounded(500 ether) + _bounded(300 ether), "mint total tracked");
        _assertAll();
    }

    function test_Harness_NoOpsWhenNothingRedeemed() public {
        p.mint(0, 1 ether);
        p.transfer(0, 1, 1 ether);
        p.revoke(0);
        p.rotateRoot(1);
        _assertAll();
    }

    /// @dev Replicates the harness amount bound (`_bound(v, 1, 1_000_000 ether)`
    ///      == `1 + v % 1_000_000 ether`) so tests can predict the exact minted
    ///      amount rather than assume the raw seed lands unchanged.
    uint256 internal constant MAX_AMOUNT = 1_000_000 ether;

    function _bounded(uint256 v) internal pure returns (uint256) {
        return 1 + (v % MAX_AMOUNT);
    }

    function _assertAll() internal view {
        assertTrue(p.echidna_nullifier_never_reused(), "nullifier never reused");
        assertTrue(p.echidna_unverified_never_holds_or_moves(), "unverified never moves");
        assertTrue(p.echidna_supply_conserved(), "supply conserved");
        assertTrue(p.echidna_ledger_consistent(), "ledger consistent");
    }
}
