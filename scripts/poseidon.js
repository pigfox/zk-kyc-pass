#!/usr/bin/env node
//
// Poseidon hashing oracle — the single source of truth for the hash the circuit
// uses, shared by the JS circuit tests and the Go issuer/prover CLI (which shells
// out to this script so its tree hashing stays byte-identical to kycpass.circom).
//
// Usage:
//   node scripts/poseidon.js <in0> <in1> [in2 ...]
//
// Each input is a decimal field element. Prints a JSON object:
//   { "hash": "<decimal>", "hashHex": "0x<64-hex>" }
//
// This is deliberately circuit-AGNOSTIC: it computes Poseidon(inputs) for any
// arity circomlib supports (1..16). The circuit's leaf is Poseidon(secret,
// expiry, issuerId); its nullifier is Poseidon(secret, root); a Merkle parent is
// Poseidon(left, right). All three are just this call with different arguments.
"use strict";

const {buildPoseidon} = require("circomlibjs");

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    process.stderr.write("usage: node scripts/poseidon.js <in0> [in1 ...]\n");
    process.exit(2);
  }

  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const inputs = args.map((a) => {
    if (!/^[0-9]+$/.test(a)) {
      process.stderr.write(`error: input "${a}" is not a decimal field element\n`);
      process.exit(2);
    }
    return BigInt(a);
  });

  const h = poseidon(inputs);
  const dec = F.toObject(h).toString();
  const hex = "0x" + BigInt(dec).toString(16).padStart(64, "0");

  process.stdout.write(JSON.stringify({hash: dec, hashHex: hex}) + "\n");
}

main().catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + "\n");
  process.exit(1);
});
