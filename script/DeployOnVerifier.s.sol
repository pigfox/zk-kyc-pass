// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {ZKComplianceRegistry} from "../src/ZKComplianceRegistry.sol";
import {KYCToken} from "../src/KYCToken.sol";

/// @title DeployOnVerifier
/// @notice Deploys the registry and the token against an ALREADY-DEPLOYED Groth16
///         verifier, instead of deploying a fresh one.
/// @dev WHY THIS EXISTS, alongside Deploy.s.sol rather than replacing it.
///
///      `src/Verifier.sol` is generated verbatim by snarkjs and PF-S123 ruled it
///      stays generated-and-UNMODIFIED, so its source still matches the bytecode
///      verified on Basescan and it does not need redeploying. The registry and
///      the token DID change (natspec), so they do. Deploy.s.sol deploys all
///      three and would therefore mint a redundant second verifier, orphaning a
///      perfectly good verified contract for no reason.
///
///      The registry stores the verifier as an `immutable`, so this is the only
///      point at which the two can be bound. Pointing a new registry at the
///      existing verifier is exactly what "no cascade into either registry" means
///      in practice.
///
///      Deploy.s.sol remains the correct script for a from-scratch deployment,
///      where there is no verifier to reuse. This one is for a redeploy that must
///      preserve one.
///
/// @dev Env:
///        DEMO_DEPLOYER_PK   — the broadcasting signer (becomes owner AND agent).
///        KYC_INITIAL_ROOT   — credential Merkle root to publish, decimal.
///        KYC_VERIFIER_ADDR  — the existing verifier to bind to.
///
///      DIRECT-CHAIN ONLY: chain 84532 is required below, and this script accepts
///      no alternate endpoint of any kind.
contract DeployOnVerifier is Script {
    string internal constant TOKEN_NAME = "ACME RWA Share";
    string internal constant TOKEN_SYMBOL = "ACME";

    function run() external {
        require(block.chainid == 84532, "DeployOnVerifier: not Base Sepolia (84532)");

        uint256 pk = vm.envUint("DEMO_DEPLOYER_PK");
        uint256 initialRoot = vm.envUint("KYC_INITIAL_ROOT");
        address verifier = vm.envAddress("KYC_VERIFIER_ADDR");
        address deployer = vm.addr(pk);

        // A verifier address with no code would produce a registry that reverts on
        // every redemption, and it would do so only at redemption time — long
        // after the deploy looked successful.
        require(verifier.code.length > 0, "DeployOnVerifier: no code at KYC_VERIFIER_ADDR");

        vm.startBroadcast(pk);
        ZKComplianceRegistry registry = new ZKComplianceRegistry(verifier, initialRoot, deployer);
        KYCToken token = new KYCToken(TOKEN_NAME, TOKEN_SYMBOL, address(registry), deployer);
        vm.stopBroadcast();

        console2.log("DEPLOYER", deployer);
        console2.log("VERIFIER", verifier);
        console2.log("REGISTRY", address(registry));
        console2.log("TOKEN", address(token));
        console2.log("INITIAL_ROOT");
        console2.logBytes32(bytes32(initialRoot));
    }
}
