// Generates test/fixtures/kycpass-proof.json — a real Groth16 proof, in the
// calldata shape the on-chain Groth16Verifier consumes, for the Solidity
// integration test (test/RealProof.t.sol). Run: node test/circuit/gen-fixture.mjs
//
// The holder address, expiry and issuer are fixed so the fixture is
// deterministic and the Solidity test can prank the bound address.
import * as snarkjs from "snarkjs";
import {writeFile, mkdir} from "node:fs/promises";
import {fileURLToPath} from "node:url";
import path from "node:path";
import {newPoseidon, MerkleTree, DEPTH} from "./tree.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUILD = path.resolve(HERE, "../../circuits/build");
const WASM = path.join(BUILD, "kycpass_js", "kycpass.wasm");
const ZKEY = path.join(BUILD, "kycpass_final.zkey");
const OUT = path.resolve(HERE, "../fixtures/kycpass-proof.json");

// The bound holder — must match what test/RealProof.t.sol pranks.
const HOLDER = BigInt("0x00000000000000000000000000000000000000AA");
const HOLDER_SECRET = 987654321098765n;
const EXPIRY = 4102444800n; // 2100-01-01
const ISSUER_ID = 42n;
const LEAF_INDEX = 5;

const {H} = await newPoseidon();
const tree = new MerkleTree(H, DEPTH);
// A couple of decoy leaves so the path is not degenerate.
tree.insert(0, H([1n, 2n, 3n]));
tree.insert(1, H([4n, 5n, 6n]));
const leaf = H([HOLDER_SECRET, EXPIRY, ISSUER_ID]);
tree.insert(LEAF_INDEX, leaf);
const {pathElements, pathIndices, root} = tree.proof(LEAF_INDEX);

const input = {
  holderSecret: HOLDER_SECRET.toString(),
  issuerId: ISSUER_ID.toString(),
  pathElements: pathElements.map(String),
  pathIndices: pathIndices.map(String),
  root: root.toString(),
  holderAddr: HOLDER.toString(),
  expiry: EXPIRY.toString(),
};

const {proof, publicSignals} = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

// exportSolidityCallData returns: [pA],[[pB]],[pC],[pubSignals] as a string.
const raw = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
const [pA, pB, pC, pub] = JSON.parse("[" + raw + "]");

const fixture = {
  _comment: "Real Groth16 proof for kycpass.circom. Regenerate: node test/circuit/gen-fixture.mjs",
  holder: "0x" + HOLDER.toString(16).padStart(40, "0"),
  expiryDecimal: EXPIRY.toString(),
  nullifier: pub[0],
  root: pub[1],
  pA,
  pB0: pB[0],
  pB1: pB[1],
  pC,
  pubSignals: pub,
};

await mkdir(path.dirname(OUT), {recursive: true});
await writeFile(OUT, JSON.stringify(fixture, null, 2) + "\n");
console.log("wrote", OUT);
console.log("  holder   ", fixture.holder);
console.log("  root     ", fixture.root);
console.log("  nullifier", fixture.nullifier);
console.log("  addr sig ", pub[2]);

const curve = globalThis.curve_bn128;
if (curve && typeof curve.terminate === "function") await curve.terminate();
process.exit(0);
