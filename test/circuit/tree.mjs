// Fixed-depth Poseidon Merkle tree, zero-subtree optimized — the JS mirror of
// the tree the circuit's MerkleInclusion template walks and the Go CLI manages.
//
// Only populated subtrees are hashed; an empty subtree at level k collapses to a
// precomputed zeros[k], so building a proof costs O(leaves * depth) Poseidon
// calls rather than O(2^depth). The leaf/parent hashing here is identical to
// scripts/poseidon.js and to kycpass.circom (Poseidon(left, right) per level,
// leaf = Poseidon(holderSecret, expiry, issuerId)).
import {buildPoseidon} from "circomlibjs";

export const DEPTH = 16;

export async function newPoseidon() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const H = (arr) => BigInt(F.toObject(poseidon(arr)).toString());
  return {H, F};
}

export class MerkleTree {
  constructor(H, depth = DEPTH) {
    this.H = H;
    this.depth = depth;
    this.leaves = new Map(); // index -> bigint
    this.maxIndex = -1;
    // zeros[k] is the root of an all-empty subtree of height k.
    this.zeros = [0n];
    for (let k = 1; k <= depth; k++) {
      this.zeros[k] = H([this.zeros[k - 1], this.zeros[k - 1]]);
    }
  }

  insert(index, leaf) {
    this.leaves.set(index, BigInt(leaf));
    if (index > this.maxIndex) this.maxIndex = index;
  }

  // node(level, index): the hash rooting the subtree at (level, index). Empty
  // subtrees short-circuit to zeros[level].
  node(level, index) {
    if (level === 0) {
      return this.leaves.has(index) ? this.leaves.get(index) : this.zeros[0];
    }
    const span = 1 << level;
    const start = index * span;
    if (this.maxIndex < start || !this._hasLeafIn(start, start + span)) {
      return this.zeros[level];
    }
    return this.H([this.node(level - 1, 2 * index), this.node(level - 1, 2 * index + 1)]);
  }

  _hasLeafIn(lo, hi) {
    for (const idx of this.leaves.keys()) {
      if (idx >= lo && idx < hi) return true;
    }
    return false;
  }

  root() {
    return this.node(this.depth, 0);
  }

  // proof(index): { pathElements[depth], pathIndices[depth], root } for the leaf
  // at `index`, in the order the circuit consumes them (level 0 = leaf level).
  proof(index) {
    const pathElements = [];
    const pathIndices = [];
    let idx = index;
    for (let level = 0; level < this.depth; level++) {
      const sib = idx ^ 1;
      pathElements.push(this.node(level, sib));
      pathIndices.push(idx & 1);
      idx = idx >> 1;
    }
    return {pathElements, pathIndices, root: this.root()};
  }
}
