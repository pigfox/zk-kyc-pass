// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IGroth16Verifier} from "../../src/interfaces/IGroth16Verifier.sol";

/// @title MockVerifier
/// @notice A verifier stand-in for tests that need to drive the registry state
///         machine without generating a real Groth16 proof.
/// @dev The real generated {Groth16Verifier} is exercised separately in
///      test/RealProof.t.sol against a checked-in fixture proof. This mock exists
///      so the rest of the suite does not have to carry a valid proof through
///      every path — only the proof-verification branch of {redeemProof}.
contract MockVerifier is IGroth16Verifier {
    /// @notice What {verifyProof} should return.
    bool public shouldVerify = true;

    /// @notice Flips the verdict the mock hands back.
    function setShouldVerify(bool value) external {
        shouldVerify = value;
    }

    /// @inheritdoc IGroth16Verifier
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[4] calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}
