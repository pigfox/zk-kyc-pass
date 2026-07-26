// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {Groth16Verifier} from "../src/Verifier.sol";
import {ZKComplianceRegistry} from "../src/ZKComplianceRegistry.sol";
import {KYCToken} from "../src/KYCToken.sol";

/// @title Deploy
/// @notice Deploys the zk-kyc-pass stack to Base Sepolia: the generated Groth16
///         verifier, the compliance registry (seeded with the issuer's published
///         root), and the compliance-gated token. The broadcasting deployer
///         becomes owner AND agent of both the registry and the token (the Roles
///         constructor grants both), so a single key can publish roots, mint, and
///         revoke — which is how this demo is wired.
/// @dev Env:
///        DEPLOYER_PRIVATE_KEY — the broadcasting signer (owner + agent).
///        KYC_INITIAL_ROOT     — the credential Merkle root to publish at deploy,
///                               as a decimal field element (from `kycctl root`).
contract Deploy is Script {
    string internal constant TOKEN_NAME = "ACME RWA Share";
    string internal constant TOKEN_SYMBOL = "ACME";

    function run() external {
        // DEMO_DEPLOYER_PK is the unified role key shared by all three demo repos
        // (see pigfox2-repos/KEYS.md for the addresses and what each role may do).
        uint256 pk = vm.envUint("DEMO_DEPLOYER_PK");
        uint256 initialRoot = vm.envUint("KYC_INITIAL_ROOT");
        address deployer = vm.addr(pk);

        vm.startBroadcast(pk);
        Groth16Verifier verifier = new Groth16Verifier();
        ZKComplianceRegistry registry = new ZKComplianceRegistry(address(verifier), initialRoot, deployer);
        KYCToken token = new KYCToken(TOKEN_NAME, TOKEN_SYMBOL, address(registry), deployer);
        vm.stopBroadcast();

        console2.log("DEPLOYER", deployer);
        console2.log("VERIFIER", address(verifier));
        console2.log("REGISTRY", address(registry));
        console2.log("TOKEN", address(token));
        console2.log("INITIAL_ROOT");
        console2.logBytes32(bytes32(initialRoot));
    }
}
