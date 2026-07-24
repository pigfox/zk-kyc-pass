// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IGroth16Verifier
/// @notice The surface the compliance registry consumes from the snarkjs-exported
///         {Groth16Verifier}. The public-signal array is fixed at length 4 by the
///         circuit: [nullifier, root, holderAddr, expiry].
/// @dev The concrete verifier in src/Verifier.sol is generated verbatim by
///      `snarkjs zkey export solidityverifier` and is never hand-edited. This
///      interface simply names its one entry point so the registry can call it
///      through a typed reference.
interface IGroth16Verifier {
    /// @notice Verify a Groth16 proof against the four public signals.
    /// @param pA Proof point A.
    /// @param pB Proof point B.
    /// @param pC Proof point C.
    /// @param pubSignals [nullifier, root, holderAddr, expiry].
    /// @return True iff the proof is valid for those public signals.
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) external view returns (bool);
}
