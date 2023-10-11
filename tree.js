import crypto from 'node:crypto';

const algo = 'sha3-256';

export class Node {
  constructor(hash, left, right) {
    this.left = left;
    this.right = right;
    this.hash = hash;
  }

  toHex() {
    return this.hash.toString('hex');
  }

  toTreeStruct(indent, last = false) {
    let result = indent + '+- ' + this.toHex();
    
    indent += (last ? "   " : "|  ");

    result += '\n' + this.left.toTreeStruct(indent, false);
    result += '\n' + this.right.toTreeStruct(indent, true);
    return result;
  }

  static compareByHash(a, b) {
    return Buffer.compare(a.hash, b.hash);
  }

  static createLeaf(data) {
    return new Leaf(hashData(data));
  }

  static fromNodePair(pair) {
    const [left, right] = pair.toSorted(Node.compareByHash);
    const hash = hashData(left.hash, right.hash);

    return new Node(hash, left, right);
  }
}

class Leaf extends Node {
  constructor(hash) {
    super(hash, null, null);
  }

  toTreeStruct(indent) {
    return indent + '+- ' + this.toHex();
  }
}

class ProofGenerator {
  constructor(root, hash) {
    this.root = root;
    this.hash = hash;
  }

  static create(root, value) { 
    return new ProofGenerator(root, hashData(value));
  }

  checkHashesAreEqual(node) { 
    return Buffer.compare(node.hash, this.hash) === 0;
  }

  search(node, proof) {
    if (node instanceof Leaf) {
      if (this.checkHashesAreEqual(node)) {
        return proof;
      }
      return false;
    }

    return this.search(node.left, [node.right.hash, ...proof]) || this.search(node.right, [node.left.hash, ...proof]);
  }

  run() {
    return this.search(this.root, []);
  }
}

export class MerlkleTree {
  constructor(root) {
    this.root = root;
  }

  getProof(value){
    const proofSearch = ProofGenerator.create(this.root, value);
    return proofSearch.run();
  }

  verify(proof, value) {
    const resultHash = proof.reduce((acc, hash) => {
      const hashBuf = Buffer.from(hash);
      const pair = [acc, hashBuf].toSorted(Buffer.compare);
      
      return hashData(...pair);
    }, hashData(value));
    return Buffer.compare(this.root.hash, resultHash) === 0;
  }

  toString() {
    return this.root.toTreeStruct('', true)
  }

  static #traverse(nodes) {
    if (nodes.length < 2) {
      return nodes[0];
    }

    const pairsIter = splitIntoPairs(nodes);
    const pairs = Array.from(pairsIter);
    const reducedNodes = pairs.map((pair) => Node.fromNodePair(pair));

    return MerlkleTree.#traverse(reducedNodes);
  }

  static fromArray(input) {
    const hashedLeaves = input.map((item) => Node.createLeaf(item));

    const root = MerlkleTree.#traverse(hashedLeaves);

    return new MerlkleTree(root);
  }
}

export function hashData(...items) {
  const hash = crypto.createHash(algo);
  for (let item of items) {
    hash.update(item);
  }
  return hash.digest();
}

function * splitIntoPairs(arr) {
  for (let i = 0; i < arr.length; i += 2) {
    const output = arr.slice(i, i + 2);
    if (output.length < 2) {
      yield output.flatMap((item) => [item, item]);
    } else {
      yield output;
    }
  }
}