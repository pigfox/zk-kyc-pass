// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Roles} from "./Roles.sol";
import {IIdentityRegistry} from "./interfaces/IIdentityRegistry.sol";

/// @title KYCToken
/// @notice A fractional ERC-20 representing shares of a real-world asset, with
///         ERC-3643-style compliance hooks: every acquisition of tokens is gated
///         on KYC verification. Minting requires the recipient to be verified;
///         transfers require BOTH parties to be verified. Here the verification
///         source is a {ZKComplianceRegistry} — the token neither knows nor cares
///         that verification is proven in zero knowledge; it consults the same
///         {IIdentityRegistry.isVerified} view it would for a plain whitelist.
/// @dev Hand-rolled minimal ERC-20 (no external token library vendored). The
///      compliance checks live in {mint} and {_transfer}. There is no burn or
///      redemption path — the story is the compliance gate, so total supply only
///      ever grows via {mint} and is conserved across transfers.
contract KYCToken is Roles {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice The sender of a transfer is not KYC-verified.
    error SenderNotVerified(address account);
    /// @notice The recipient of a mint or transfer is not KYC-verified.
    error RecipientNotVerified(address account);
    /// @notice `account` holds fewer tokens than the operation requires.
    error InsufficientBalance(address account, uint256 balance, uint256 needed);
    /// @notice `spender` has less allowance from `owner` than the operation requires.
    error InsufficientAllowance(address owner, address spender, uint256 allowance, uint256 needed);

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-20 transfer event (mint = from zero).
    event Transfer(address indexed from, address indexed to, uint256 value);
    /// @notice ERC-20 approval event.
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    /// @notice ERC-20 token name.
    string public name;
    /// @notice ERC-20 token symbol.
    string public symbol;
    /// @notice ERC-20 decimals. Fixed at 18 for fractional shares.
    uint8 public constant decimals = 18;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Total tokens in existence. Equals the sum of all balances.
    uint256 public totalSupply;
    mapping(address account => uint256 balance) private _balances;
    mapping(address owner => mapping(address spender => uint256 amount)) private _allowances;

    /// @notice The compliance registry consulted on every mint and transfer.
    IIdentityRegistry public immutable identityRegistry;

    /// @param name_ ERC-20 name.
    /// @param symbol_ ERC-20 symbol.
    /// @param identityRegistry_ The compliance registry address (non-zero).
    /// @param initialOwner The deployer; owner and first (mint) agent.
    constructor(string memory name_, string memory symbol_, address identityRegistry_, address initialOwner)
        Roles(initialOwner)
    {
        if (identityRegistry_ == address(0)) revert ZeroAddress();
        name = name_;
        symbol = symbol_;
        identityRegistry = IIdentityRegistry(identityRegistry_);
    }

    /*//////////////////////////////////////////////////////////////
                                  VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice The token balance of `account`.
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    /// @notice The remaining tokens `spender` may pull from `holder`.
    function allowance(address holder, address spender) external view returns (uint256) {
        return _allowances[holder][spender];
    }

    /*//////////////////////////////////////////////////////////////
                             MINT (COMPLIANT)
    //////////////////////////////////////////////////////////////*/

    /// @notice Mint `amount` tokens to `to`. The recipient must be KYC-verified.
    function mint(address to, uint256 amount) external onlyAgent {
        if (to == address(0)) revert ZeroAddress();
        if (!identityRegistry.isVerified(to)) revert RecipientNotVerified(to);
        totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    /*//////////////////////////////////////////////////////////////
                               ERC-20 WRITES
    //////////////////////////////////////////////////////////////*/

    /// @notice Approve `spender` to pull up to `amount` of the caller's tokens.
    function approve(address spender, uint256 amount) external returns (bool) {
        if (spender == address(0)) revert ZeroAddress();
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /// @notice Transfer `amount` tokens to `to`. Both parties must be verified.
    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    /// @notice Transfer `amount` from `from` to `to` using the caller's allowance.
    ///         Both `from` and `to` must be verified.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, amount);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNALS
    //////////////////////////////////////////////////////////////*/

    /// @dev Shared transfer path enforcing the both-parties-verified hook.
    function _transfer(address from, address to, uint256 amount) internal {
        if (to == address(0)) revert ZeroAddress();
        if (!identityRegistry.isVerified(from)) revert SenderNotVerified(from);
        if (!identityRegistry.isVerified(to)) revert RecipientNotVerified(to);
        uint256 bal = _balances[from];
        if (bal < amount) revert InsufficientBalance(from, bal, amount);
        unchecked {
            _balances[from] = bal - amount;
            _balances[to] += amount;
        }
        emit Transfer(from, to, amount);
    }

    /// @dev Deduct `amount` from the (`holder`,`spender`) allowance. An allowance
    ///      of `type(uint256).max` is treated as infinite and never decremented.
    function _spendAllowance(address holder, address spender, uint256 amount) internal {
        uint256 current = _allowances[holder][spender];
        if (current != type(uint256).max) {
            if (current < amount) revert InsufficientAllowance(holder, spender, current, amount);
            unchecked {
                _allowances[holder][spender] = current - amount;
            }
        }
    }
}
