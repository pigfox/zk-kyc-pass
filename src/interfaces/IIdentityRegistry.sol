// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IIdentityRegistry
/// @notice The single method the token needs from the compliance registry: a
///         yes/no verification check on an address. Defined fresh and minimal
///         here — the ZK registry proves verification a different way, but the
///         token only ever consults this one view (mint checks the recipient,
///         transfer checks both parties).
interface IIdentityRegistry {
    /// @notice True when `account` currently holds a live, unexpired KYC
    ///         verification and may hold and transact the token.
    /// @param account The address to test.
    /// @return True while the verification is live. Answered fresh on every call rather
    ///         than cached by the token, so a lapse or a revocation takes effect on the
    ///         very next transfer with no action needed from the token.
    function isVerified(address account) external view returns (bool);
}
