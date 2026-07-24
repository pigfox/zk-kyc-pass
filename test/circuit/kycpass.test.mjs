// Circuit tests for kycpass.circom, driven through snarkjs against the checked-in
// artifacts (circuits/build/kycpass_final.zkey + verification_key.json + wasm).
//
// Run: node --test test/circuit/
//
// Covers the security-relevant behaviours from the brief:
//   1. a well-formed credential proof verifies;
//   2. a wrong holderSecret cannot even witness (leaf leaves the tree);
//   3. a wrong root cannot witness (inclusion === root fails);
//   4. a tampered nullifier public signal fails verification;
//   5. a proof bound to address A is rejected when presented as address B.
import {test, after} from "node:test";
import assert from "node:assert/strict";
import {fileURLToPath} from "node:url";
import path from "node:path";
import * as snarkjs from "snarkjs";
import {newPoseidon, MerkleTree, DEPTH} from "./tree.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUILD = path.resolve(HERE, "../../circuits/build");
const WASM = path.join(BUILD, "kycpass_js", "kycpass.wasm");
const ZKEY = path.join(BUILD, "kycpass_final.zkey");
const VKEY_PATH = path.join(BUILD, "verification_key.json");

// A representative holder. addrA/addrB are 20-byte addresses as field elements.
const HOLDER_SECRET = 111222333444555n;
const EXPIRY = 4102444800n; // 2100-01-01, comfortably in the future
const ISSUER_ID = 7n;
const ADDR_A = BigInt("0x00000000000000000000000000000000000000aa");
const ADDR_B = BigInt("0x00000000000000000000000000000000000000bb");
const LEAF_INDEX = 3;

async function fixtures() {
  const {H} = await newPoseidon();
  const tree = new MerkleTree(H, DEPTH);
  // A couple of decoy leaves so the path is not a degenerate all-zero one.
  tree.insert(0, H([1n, 2n, 3n]));
  tree.insert(1, H([4n, 5n, 6n]));
  const leaf = H([HOLDER_SECRET, EXPIRY, ISSUER_ID]);
  tree.insert(LEAF_INDEX, leaf);
  const {pathElements, pathIndices, root} = tree.proof(LEAF_INDEX);
  const nullifier = H([HOLDER_SECRET, root]);
  return {H, tree, leaf, pathElements, pathIndices, root, nullifier};
}

function baseInput(f, overrides = {}) {
  return {
    holderSecret: HOLDER_SECRET.toString(),
    issuerId: ISSUER_ID.toString(),
    pathElements: f.pathElements.map((x) => x.toString()),
    pathIndices: f.pathIndices.map((x) => x.toString()),
    root: f.root.toString(),
    holderAddr: ADDR_A.toString(),
    expiry: EXPIRY.toString(),
    ...overrides,
  };
}

async function loadVkey() {
  const {readFile} = await import("node:fs/promises");
  return JSON.parse(await readFile(VKEY_PATH, "utf8"));
}

// snarkjs' bn128 curve spins up a persistent ffjavascript worker-thread pool
// (cached on globalThis.curve_bn128). Node 20.11 has no --test-force-exit, so
// without terminating it the process lingers for minutes after the tests pass.
// Tearing it down here lets `node --test` exit promptly with the right code.
after(async () => {
  const curve = globalThis.curve_bn128;
  if (curve && typeof curve.terminate === "function") {
    await curve.terminate();
  }
});

test("valid credential proof verifies; public signals are [nullifier, root, addr, expiry]", async () => {
  const f = await fixtures();
  const {proof, publicSignals} = await snarkjs.groth16.fullProve(baseInput(f), WASM, ZKEY);
  const vkey = await loadVkey();
  assert.equal(await snarkjs.groth16.verify(vkey, publicSignals, proof), true);

  // circom ordering: outputs first (nullifier), then public inputs in declared
  // order (root, holderAddr, expiry).
  assert.equal(publicSignals.length, 4);
  assert.equal(BigInt(publicSignals[0]), f.nullifier);
  assert.equal(BigInt(publicSignals[1]), f.root);
  assert.equal(BigInt(publicSignals[2]), ADDR_A);
  assert.equal(BigInt(publicSignals[3]), EXPIRY);
});

test("wrong holderSecret cannot witness (leaf leaves the tree)", async () => {
  const f = await fixtures();
  await assert.rejects(
    snarkjs.groth16.fullProve(baseInput(f, {holderSecret: (HOLDER_SECRET + 1n).toString()}), WASM, ZKEY),
  );
});

test("wrong root cannot witness (inclusion === root fails)", async () => {
  const f = await fixtures();
  await assert.rejects(
    snarkjs.groth16.fullProve(baseInput(f, {root: (f.root + 1n).toString()}), WASM, ZKEY),
  );
});

test("tampered nullifier public signal fails verification", async () => {
  const f = await fixtures();
  const {proof, publicSignals} = await snarkjs.groth16.fullProve(baseInput(f), WASM, ZKEY);
  const tampered = [...publicSignals];
  tampered[0] = (BigInt(tampered[0]) + 1n).toString(); // flip the nullifier
  const vkey = await loadVkey();
  assert.equal(await snarkjs.groth16.verify(vkey, tampered, proof), false);
});

test("proof bound to address A is rejected when presented as address B", async () => {
  const f = await fixtures();
  const {proof, publicSignals} = await snarkjs.groth16.fullProve(baseInput(f), WASM, ZKEY);
  const swapped = [...publicSignals];
  assert.equal(BigInt(swapped[2]), ADDR_A);
  swapped[2] = ADDR_B.toString(); // present the same proof as a different address
  const vkey = await loadVkey();
  assert.equal(await snarkjs.groth16.verify(vkey, swapped, proof), false);
});
