// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IIdentityRegistry} from "../../src/interfaces/IIdentityRegistry.sol";

/// @title MockRegistry
/// @notice A compliance-registry stand-in for the token unit tests: verification
///         is a plain settable set, so KYCToken's mint/transfer gating can be
///         driven through every branch without redeeming real proofs.
/// @dev The real {ZKComplianceRegistry} is exercised in its own suite and, wired
///      to the token, in the invariant harness. The token only ever consults
///      {isVerified}, so this is a faithful substitute for the token's view of
///      the world.
contract MockRegistry is IIdentityRegistry {
    mapping(address account => bool verified) private _verified;

    /// @notice Set or clear `account`'s verification.
    function setVerified(address account, bool value) external {
        _verified[account] = value;
    }

    /// @inheritdoc IIdentityRegistry
    function isVerified(address account) external view override returns (bool) {
        return _verified[account];
    }
}
