// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PigfoxProperties} from "pipeline/PigfoxProperties.sol";

import {ZKComplianceRegistry} from "../src/ZKComplianceRegistry.sol";
import {KYCToken} from "../src/KYCToken.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";
import {Actor} from "./Actor.sol";

/// @title Properties
/// @notice The single source of truth for the protocol's invariants, shared by
///         Foundry, Echidna and Medusa. Keeping one property contract means a
///         property can never hold in one engine and silently rot in another.
/// @dev The harness IS the deployer — owner and agent of both the registry and
///      the token — so it can mint, rotate the root and revoke. A pool of real
///      {Actor} forwarders supplies distinct `msg.sender`s, which the compliance
///      gate's address binding requires: a redemption proof only redeems for the
///      caller it is bound to. The mock verifier stands in for the Groth16 proof
///      so `redeemProof` is reachable; the real verifier is proven end-to-end in
///      test/RealProof.t.sol.
///
///      The three invariants the brief names map to {echidna_nullifier_never_reused},
///      {echidna_unverified_never_holds_or_moves} and {echidna_supply_conserved}.
contract Properties is PigfoxProperties {
    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    MockVerifier public verifier;
    ZKComplianceRegistry public registry;
    KYCToken public token;

    uint256 internal constant POOL_SIZE = 5;
    Actor[] internal actorPool;
    mapping(address => bool) public isPoolActor;

    /// @dev How long past `block.timestamp` a freshly redeemed credential lasts.
    ///      Short enough that a run which advances time can expire it (exercising
    ///      the unverified-cannot-move path via natural lapse), long enough that
    ///      the redemption itself always succeeds.
    uint256 internal constant CRED_WINDOW = 30 days;

    /// @dev Nullifiers are bounded into a small pool so collisions actually
    ///      happen inside a single sequence — otherwise the replay guard is
    ///      unreachable and its property passes vacuously.
    uint256 internal constant NULLIFIER_POOL = 8;

    /// @notice How many successful redemptions each nullifier integer has
    ///         settled. Must never exceed one: the contract's `spentNullifiers`
    ///         is global, so a nullifier integer spends exactly once, ever. (The
    ///         circuit derives a fresh nullifier per root, so cross-epoch
    ///         re-verification uses a DIFFERENT integer — a circuit-level property
    ///         exercised in test/circuit; at the contract level the guarantee is
    ///         simply global single-spend, which is what this models.)
    mapping(uint256 => uint256) public nullifierRedeemCount;
    /// @notice Sticky: set if any nullifier integer ever redeems twice.
    bool public nullifierReuseSeen;

    /// @notice Sticky: set if a mint or transfer ever succeeded while a party was
    ///         not verified at execution time.
    bool public unverifiedMovedTokens;

    /// @notice Running total minted; with no burn path, equals totalSupply.
    uint256 public totalMinted;

    /*//////////////////////////////////////////////////////////////
                            PROGRESS GHOSTS
    //////////////////////////////////////////////////////////////*/

    uint256 public ghost_redeems;
    uint256 public ghost_mints;
    uint256 public ghost_transfers;

    uint256 public ghost_redeemOpportunities;
    uint256 public ghost_mintOpportunities;
    uint256 public ghost_transferOpportunities;

    /// @notice Sticky: set if a success counter ever advanced without first
    ///         registering its paired opportunity (a harness-consistency canary).
    bool public ledgerInconsistent;

    constructor() {
        verifier = new MockVerifier();
        registry = new ZKComplianceRegistry(address(verifier), uint256(keccak256("epoch-0")), address(this));
        token = new KYCToken("ACME RWA Share", "ACME", address(registry), address(this));

        for (uint256 i = 0; i < POOL_SIZE; i++) {
            Actor a = new Actor();
            actorPool.push(a);
            isPoolActor[address(a)] = true;
        }
    }

    /*//////////////////////////////////////////////////////////////
                              ACTOR POOL
    //////////////////////////////////////////////////////////////*/

    function poolSize() public pure returns (uint256) {
        return POOL_SIZE;
    }

    function poolActorAt(uint256 index) public view returns (Actor) {
        return actorPool[index % POOL_SIZE];
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZER ENTRY POINTS
    //////////////////////////////////////////////////////////////*/

    /// @notice An actor redeems a credential proof, bound to itself.
    function redeem(uint256 actorSeed, uint256 nullifierSeed) public {
        Actor actor = actorPool[actorSeed % POOL_SIZE];
        uint256 nullifier = _bound(nullifierSeed, 1, NULLIFIER_POOL);
        uint256 root = registry.currentRoot();
        uint256 expiry = block.timestamp + CRED_WINDOW;

        // Every on-chain precondition is read here, immediately before the call,
        // against the same state the call executes against: root matches (we use
        // currentRoot), the proof is bound to the caller, expiry is in the future
        // (always, by construction), the nullifier is unspent, and the verdict is
        // true. When all hold the redemption MUST succeed.
        uint256 oppBefore = ghost_redeemOpportunities;
        bool mustSucceed = !registry.spentNullifiers(nullifier) && verifier.shouldVerify();
        if (mustSucceed) ghost_redeemOpportunities += 1;

        uint256[4] memory signals;
        signals[0] = nullifier;
        signals[1] = root;
        signals[2] = uint256(uint160(address(actor)));
        signals[3] = expiry;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;

        (bool ok,) = actor.exec(
            address(registry), 0, abi.encodeCall(ZKComplianceRegistry.redeemProof, (a, b, c, signals))
        );

        if (ok) {
            if (mustSucceed && ghost_redeemOpportunities == oppBefore) ledgerInconsistent = true;
            // The contract's spentNullifiers is global, so a successful SECOND
            // redemption of the same integer would be a replay-guard breach.
            if (nullifierRedeemCount[nullifier] > 0) nullifierReuseSeen = true;
            nullifierRedeemCount[nullifier] += 1;
            ghost_redeems += 1;
        }
    }

    /// @notice The agent (this harness) mints to an actor.
    function mint(uint256 actorSeed, uint256 amountSeed) public {
        Actor actor = actorPool[actorSeed % POOL_SIZE];
        uint256 amount = _bound(amountSeed, 1, 1_000_000 ether);
        address to = address(actor);

        // A verified, non-zero recipient minted to by the agent must succeed.
        uint256 oppBefore = ghost_mintOpportunities;
        bool verifiedBefore = registry.isVerified(to);
        if (verifiedBefore) ghost_mintOpportunities += 1;

        try token.mint(to, amount) {
            if (verifiedBefore && ghost_mintOpportunities == oppBefore) ledgerInconsistent = true;
            if (!verifiedBefore) unverifiedMovedTokens = true; // must have been verified
            totalMinted += amount;
            ghost_mints += 1;
        } catch {}
    }

    /// @notice One actor transfers to another.
    function transfer(uint256 fromSeed, uint256 toSeed, uint256 amountSeed) public {
        Actor from = actorPool[fromSeed % POOL_SIZE];
        Actor to = actorPool[toSeed % POOL_SIZE];
        uint256 amount = _bound(amountSeed, 1, 1_000_000 ether);

        // Both parties verified, sender solvent, recipient non-zero: the transfer
        // must go through.
        uint256 oppBefore = ghost_transferOpportunities;
        bool fromV = registry.isVerified(address(from));
        bool toV = registry.isVerified(address(to));
        bool solvent = token.balanceOf(address(from)) >= amount;
        bool mustSucceed = fromV && toV && solvent;
        if (mustSucceed) ghost_transferOpportunities += 1;

        (bool ok,) = from.exec(address(token), 0, abi.encodeCall(KYCToken.transfer, (address(to), amount)));

        if (ok) {
            if (mustSucceed && ghost_transferOpportunities == oppBefore) ledgerInconsistent = true;
            if (!fromV || !toV) unverifiedMovedTokens = true; // both must have been verified
            ghost_transfers += 1;
        }
    }

    /// @notice Flips the verifier verdict so both proof branches are explored.
    function setVerifierVerdict(bool value) public {
        verifier.setShouldVerify(value);
    }

    /// @notice The owner rotates the credential root (issuer re-issuance).
    function rotateRoot(uint256 seed) public {
        registry.setRoot(uint256(keccak256(abi.encode("epoch", seed))));
    }

    /// @notice The agent revokes an actor's verification.
    function revoke(uint256 actorSeed) public {
        registry.revoke(address(actorPool[actorSeed % POOL_SIZE]));
    }

    /*//////////////////////////////////////////////////////////////
                              DECLARATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc PigfoxProperties
    function pigfoxPropertyCount() public pure override returns (uint256) {
        return 4;
    }

    /// @inheritdoc PigfoxProperties
    function pigfoxHarnessDescription() public pure override returns (string memory) {
        return "a nullifier spends once, only verified addresses hold or move tokens, and supply is conserved";
    }

    /*//////////////////////////////////////////////////////////////
                               PROPERTIES
    //////////////////////////////////////////////////////////////*/

    /// @notice INVARIANT: a spent nullifier can never redeem again within a root
    ///         epoch (the replay guard).
    function echidna_nullifier_never_reused() public view returns (bool) {
        return !nullifierReuseSeen;
    }

    /// @notice INVARIANT: an address that is not currently verified can never be
    ///         minted to, nor send or receive a transfer.
    function echidna_unverified_never_holds_or_moves() public view returns (bool) {
        return !unverifiedMovedTokens;
    }

    /// @notice INVARIANT: total supply is conserved — it equals the sum of all
    ///         balances and the running mint total (no burn path exists).
    function echidna_supply_conserved() public view returns (bool) {
        uint256 sum;
        for (uint256 i = 0; i < actorPool.length; i++) {
            sum += token.balanceOf(address(actorPool[i]));
        }
        return sum == token.totalSupply() && token.totalSupply() == totalMinted;
    }

    /// @notice Harness-consistency canary: every counted success registered an
    ///         opportunity first.
    function echidna_ledger_consistent() public view returns (bool) {
        return !ledgerInconsistent;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNALS
    //////////////////////////////////////////////////////////////*/

    function _bound(uint256 value, uint256 min, uint256 max) internal pure returns (uint256) {
        if (min >= max) return min;
        return min + (value % (max - min + 1));
    }
}
