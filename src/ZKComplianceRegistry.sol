// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";
import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";
import {IGroth16Verifier} from "./interfaces/IGroth16Verifier.sol";

/// @title ZKComplianceRegistry
/// @notice Privacy-preserving KYC gate for a tokenized RWA. A holder proves, in
///         zero knowledge, that they possess a valid credential from an approved
///         issuer — without revealing which issuer or any identifying data — and
///         becomes verified until their credential's expiry. The token consults
///         {isVerified} on every mint and transfer, exactly as it would a plain
///         whitelist; the difference is that NOTHING identifying is ever written
///         on chain. On-chain state is only: the current Merkle root, the set of
///         spent nullifiers, and per-address expiries. There is no identity list
///         to enumerate.
/// @dev Implements {IIdentityRegistry} so it is a drop-in for the token's gate.
///      The proof shape and public-signal ordering are fixed by kycpass.circom:
///      pubSignals = [nullifier, root, holderAddr, expiry].
contract ZKComplianceRegistry is Roles, IIdentityRegistry {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice The proof's root does not match the currently published root.
    error RootMismatch(uint256 proofRoot, uint256 currentRoot);
    /// @notice The proof's bound address is not the caller (anti-theft binding).
    error AddressMismatch(address caller);
    /// @notice The credential has expired (`expiry <= block.timestamp`).
    error CredentialExpired(uint256 expiry);
    /// @notice This nullifier has already been redeemed against the current root.
    error NullifierAlreadySpent(uint256 nullifier);
    /// @notice The Groth16 proof did not verify.
    error InvalidProof();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the owner publishes a new credential Merkle root.
    /// @param newRoot The root now accepted by `redeemProof`. Proofs against any earlier
    ///        root stop redeeming from this block on, which is what makes rotation the
    ///        revocation lever for the credential SET.
    event RootUpdated(uint256 indexed newRoot);
    /// @notice Emitted when a holder redeems a proof and becomes verified.
    /// @dev Carries NO identifying data — only the caller, the spent nullifier,
    ///      and the expiry. The nullifier is unlinkable to any credential.
    /// @param holder The address that became verified; it is bound into the proof, so a
    ///        third party cannot redeem someone else's credential to their own address.
    /// @param nullifier The spent nullifier, recorded so the same credential cannot be
    ///        redeemed twice. It reveals nothing about which credential produced it.
    /// @param expiry The unix time at which this verification lapses on its own, with no
    ///        revocation call required.
    event ProofRedeemed(address indexed holder, uint256 nullifier, uint256 expiry);
    /// @notice Emitted when an agent revokes an address's verification early.
    /// @param holder The address whose verification was cut short before its expiry.
    event VerificationRevoked(address indexed holder);

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The Groth16 verifier generated from the circuit's final zkey.
    IGroth16Verifier public immutable verifier;
    /// @notice The currently published credential Merkle root. Rotating it is a
    ///         revocation lever: proofs against an old root stop redeeming,
    ///         though verifications already granted persist until their expiry.
    uint256 public currentRoot;
    /// @notice Nullifiers already redeemed. A nullifier is Poseidon(secret, root),
    ///         so replay is impossible within a root epoch.
    mapping(uint256 nullifier => bool spent) public spentNullifiers;
    /// @notice The unix time until which `account` is verified. Zero means never
    ///         verified or revoked.
    mapping(address account => uint256 until) public verifiedUntil;

    /// @notice Binds the registry to its verifier and publishes the first credential root.
    /// @dev `verifier_` is stored as an `immutable`, so this constructor is the ONLY point
    ///      at which the proving key backing this registry can be chosen. Replacing the
    ///      verifier means redeploying this registry, and KYCToken with it.
    /// @param verifier_ The deployed Groth16 verifier (non-zero).
    /// @param initialRoot The first published credential root (may be zero and
    ///        set later via {setRoot}).
    /// @param initialOwner The deployer; owner and first agent.
    constructor(address verifier_, uint256 initialRoot, address initialOwner) Roles(initialOwner) {
        if (verifier_ == address(0)) revert ZeroAddress();
        verifier = IGroth16Verifier(verifier_);
        currentRoot = initialRoot;
        emit RootUpdated(initialRoot);
    }

    /*//////////////////////////////////////////////////////////////
                                REDEMPTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Redeem a credential proof and become verified until its expiry.
    /// @dev Checks, in order: the proof's root is the published one; the proof is
    ///      bound to the caller; the credential is unexpired; the nullifier is
    ///      unspent; and the Groth16 proof verifies. Only then is the nullifier
    ///      burned and the caller's expiry recorded.
    /// @param pA Proof point A.
    /// @param pB Proof point B.
    /// @param pC Proof point C.
    /// @param pubSignals [nullifier, root, holderAddr, expiry].
    function redeemProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) external {
        uint256 nullifier = pubSignals[0];
        uint256 root = pubSignals[1];
        uint256 boundAddr = pubSignals[2];
        uint256 expiry = pubSignals[3];

        if (root != currentRoot) revert RootMismatch(root, currentRoot);
        if (boundAddr != uint256(uint160(msg.sender))) revert AddressMismatch(msg.sender);
        if (expiry <= block.timestamp) revert CredentialExpired(expiry);
        if (spentNullifiers[nullifier]) revert NullifierAlreadySpent(nullifier);
        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) revert InvalidProof();

        spentNullifiers[nullifier] = true;
        verifiedUntil[msg.sender] = expiry;
        emit ProofRedeemed(msg.sender, nullifier, expiry);
    }

    /*//////////////////////////////////////////////////////////////
                               GOVERNANCE
    //////////////////////////////////////////////////////////////*/

    /// @notice Publish a new credential Merkle root (issuer re-issuance / rotation).
    /// @dev Rotation is the revocation lever for the credential SET: proofs
    ///      against the old root no longer redeem. Verifications ALREADY granted
    ///      persist until their expiry — a documented tradeoff (see SECURITY.md).
    /// @param newRoot The credential Merkle root to publish. Not validated against zero:
    ///        publishing zero is a legitimate way to stop all future redemptions while
    ///        leaving existing verifications to lapse naturally.
    function setRoot(uint256 newRoot) external onlyOwner {
        currentRoot = newRoot;
        emit RootUpdated(newRoot);
    }

    /// @notice Revoke an address's verification immediately.
    /// @dev The per-address emergency lever, complementing root rotation. Sets
    ///      the expiry to zero so {isVerified} returns false at once.
    /// @param account The address to de-verify. Its spent nullifier is NOT released, so a
    ///        revoked holder cannot re-redeem the same credential to undo this.
    function revoke(address account) external onlyAgent {
        verifiedUntil[account] = 0;
        emit VerificationRevoked(account);
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice True while `account` holds a live, unexpired verification.
    /// @dev Verification lapses automatically at expiry — a deliberate feature:
    ///      a stale credential silently stops working with no revocation call.
    /// @param account The address to test.
    /// @return True while the address holds an unexpired verification. Strict `>` against
    ///         `block.timestamp`, so a credential expiring exactly now reads as expired —
    ///         the conservative direction.
    function isVerified(address account) external view override returns (bool) {
        return verifiedUntil[account] > block.timestamp;
    }
}
