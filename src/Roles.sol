// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Roles
/// @notice Minimal two-tier access control shared by the zk-kyc-pass contracts:
///         a single `owner` (governance) and a set of `agents` (operational
///         actors). This mirrors the owner/agent split of ERC-3643 (T-REX)
///         without vendoring the full suite — the same house style as the RWA
///         tokenization demo it composes with.
/// @dev The deployer is set as BOTH owner and the first agent in the
///      constructor, so a freshly deployed contract is immediately operable by
///      the deployer alone — which is exactly how this demo is wired: every
///      privileged role resolves to the single deployer address.
abstract contract Roles {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice The caller is not the owner.
    error NotOwner(address caller);
    /// @notice The caller does not hold the agent role.
    error NotAgent(address caller);
    /// @notice A zero address was supplied where a real account is required.
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when ownership moves from `previousOwner` to `newOwner`.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    /// @notice Emitted when `account` is granted (`enabled=true`) or revoked the agent role.
    event AgentSet(address indexed account, bool enabled);

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The governance account. May transfer ownership and manage agents.
    address public owner;
    /// @notice Operational actors permitted to take agent-gated actions.
    mapping(address account => bool isAgent) public agents;

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    modifier onlyAgent() {
        if (!agents[msg.sender]) revert NotAgent(msg.sender);
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param initialOwner The account that becomes owner and the first agent.
    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        owner = initialOwner;
        agents[initialOwner] = true;
        emit OwnershipTransferred(address(0), initialOwner);
        emit AgentSet(initialOwner, true);
    }

    /*//////////////////////////////////////////////////////////////
                               GOVERNANCE
    //////////////////////////////////////////////////////////////*/

    /// @notice Transfer ownership to `newOwner`.
    /// @dev The new owner is NOT granted an agent role automatically; manage
    ///      that separately with {setAgent} if the new owner should also operate.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Grant (`enabled=true`) or revoke the agent role for `account`.
    function setAgent(address account, bool enabled) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        agents[account] = enabled;
        emit AgentSet(account, enabled);
    }
}
