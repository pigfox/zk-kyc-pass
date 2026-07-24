// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {Properties} from "./Properties.sol";

/// @title InvariantsTest
/// @notice Runs the shared {Properties} harness under Foundry's invariant engine,
///         asserting the same predicates Echidna and Medusa check.
contract InvariantsTest is Test {
    Properties internal properties;

    function setUp() public {
        properties = new Properties();
        targetContract(address(properties));

        // Only the fuzz entry points. Foundry weights the selector distribution
        // by REPETITION, so entries are duplicated to shape the walk toward the
        // interesting states: you must redeem before you can be minted to, and be
        // minted to before you can transfer. Verdict flips, root rotation and
        // revocation are in the set so the negative paths (bad proof, stale root,
        // revoked holder) get exercised too.
        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = Properties.redeem.selector;
        selectors[1] = Properties.redeem.selector;
        selectors[2] = Properties.redeem.selector;
        selectors[3] = Properties.mint.selector;
        selectors[4] = Properties.mint.selector;
        selectors[5] = Properties.transfer.selector;
        selectors[6] = Properties.transfer.selector;
        selectors[7] = Properties.setVerifierVerdict.selector;
        selectors[8] = Properties.rotateRoot.selector;
        selectors[9] = Properties.revoke.selector;
        targetSelector(FuzzSelector({addr: address(properties), selectors: selectors}));
    }

    /// @notice INVARIANT (1): a spent nullifier can never redeem again in-epoch.
    function invariant_NullifierNeverReused() public view {
        assertTrue(properties.echidna_nullifier_never_reused(), "a nullifier redeemed twice under one root");
    }

    /// @notice INVARIANT (2): an unverified address never holds-via-mint, sends,
    ///         or receives.
    function invariant_UnverifiedNeverMoves() public view {
        assertTrue(
            properties.echidna_unverified_never_holds_or_moves(),
            "an unverified address moved or received tokens"
        );
    }

    /// @notice INVARIANT (3): total supply is conserved (== sum of balances == mints).
    function invariant_SupplyConserved() public view {
        assertTrue(properties.echidna_supply_conserved(), "supply diverged from balances or mint total");
    }

    /// @notice Harness canary: successes never outrun their opportunities.
    function invariant_LedgerConsistent() public view {
        assertTrue(
            properties.echidna_ledger_consistent(),
            "a success counter advanced without registering an opportunity"
        );
    }

    /// @notice Proves the run was not inert — a property suite that never reaches
    ///         an interesting state reports green forever. Each check is an
    ///         IMPLICATION (success given a registered opportunity), so it holds
    ///         across every `afterInvariant` firing regardless of how the
    ///         selector dice landed.
    function afterInvariant() public view {
        if (properties.ghost_redeemOpportunities() > 0) {
            assertGt(properties.ghost_redeems(), 0, "every redeemable proof failed to redeem");
        }
        if (properties.ghost_mintOpportunities() > 0) {
            assertGt(properties.ghost_mints(), 0, "every mintable recipient failed to be minted to");
        }
        if (properties.ghost_transferOpportunities() > 0) {
            assertGt(properties.ghost_transfers(), 0, "every valid transfer failed");
        }
    }
}
