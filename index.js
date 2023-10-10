import keccak256 from 'keccak256';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { it } from 'node:test';

const algo = 'sha3-256';

function example1() {
  const message = "secret message";

  const hash = crypto.createHash(algo);
  hash.update(message);
  const hashed = hash.digest('hex'); // d4d114983edca57516ef87b114b3c7ce86643778b1a636806103323384e07012
  console.log({ hashed: hashed });
}

function example2() {
  const foo = "foo";
  const bar = "bar";

  {
    const hash = crypto.createHash(algo);
    hash.update(foo + bar);
    const hashed = hash.digest('hex');
    console.log({ hashed });
  }

  {
    const hash = crypto.createHash(algo);
    hash.update(foo);
    hash.update(bar);
    const hashed = hash.digest('hex');
    console.log({ hashed });
  }
}

class Node {
  constructor(hash, left, right, parent) {
    this.left = left;
    this.right = right;
    this.hash = hash;
    if (parent) {
      this.parent = new WeakRef(parent);
    }
  }

  setParent(node) {
    this.parent = new WeakRef(node);
  }

  toHex() {
    return this.hash.toString('hex');
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

    const node = new Node(hash, left, right);
    left.setParent(node);
    right.setParent(node);
    
    return node;
  }
}

class Leaf extends Node {
  constructor(hash, parent) {
    super(hash, null, null, parent);
  }
}

class ProofSearchStep {
  constructor(root, hash) {
    this.root = root;
    this.hash = hash;
  }

  static create(root, value) { 
    return new ProofSearchStep(root, hashData(value));
  }

  checkHashesAreEqual(node) { 
    return Buffer.compare(node.hash, this.hash) === 0;
  }

  search() {
    const stack = [this.root];
   
    let found;

    while (stack.length) {
      const node = stack.pop();
      if (!(node instanceof Leaf)) {
        stack.push(node.left);
        stack.push(node.right);
        continue;
      }

      if (this.checkHashesAreEqual(node)) {
        found = node;
        break;
      }
    }

    return new ProofBubblingStep(found);
  }
}

class ProofBubblingStep {
  constructor(found) {
    this.found = found;
  }

  collect() {
    const result = [];
    let found = this.found;
    let parent;

    while (parent = found?.parent?.deref()) {
      if (parent.left === found) {
        result.push(parent.right.hash);
      } else {
        result.push(parent.left.hash);
      }

      found = parent;
    }

    return result
  }
}

class MerlkleTree {
  constructor(root) {
    this.root = root;
  }

  getProof(value){
    const proofSearch = ProofSearchStep.create(this.root, value);
    const proofBubbling = proofSearch.search();
    return proofBubbling.collect();
  }

  verify(proof, value) {
    const resultHash = proof.reduce((acc, hash) => {
      const hashBuf = Buffer.from(hash);
      const pair = [acc, hashBuf].toSorted(Buffer.compare);
      
      return hashData(...pair);
    }, hashData(value));
    return Buffer.compare(this.root.hash, resultHash) === 0;
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

function hashData(...items) {
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

const whitelistAddresses = [
  "0X5B38DA6A701C568545DCFCB03FCB875F56BEDDC4", // 0 iter; i = 0
  "0X5A641E5FB72A2FD9137312E7694D42996D689D99",
  "0XDCAB482177A592E424D1C8318A464FC922E8DE40", // 1 iter; i = 2
  "0X6E21D37E07A6F7E53C7ACE372CEC63D4AE4B6BD0",
  "0X09BAAB19FC77C19898140DADD30C4685C597620B", // 2 iter; i = 4
  "0XCC4C29997177253376528C05D3DF91CF2D69061A",
  "0xdD870fA1b7C4700F2BD7f44238821C26f7392148", // 3 iter; i = 6
];


it.skip('should create sorted node', () => {
  const data1 = 'b';
  const node1 = Node.createLeaf(data1);
  assert.equal(Buffer.compare(node1.hash, hashData(data1)), 0);
  
  const data2 = 'a';
  const node2 = Node.createLeaf(data2);

  const node3 = Node.fromNodePair([node1, node2])
  // assert.equal(node3.left no);
});

it.skip('should create tree', () => {
  const input = whitelistAddresses.slice(0, 2);
  const tree = MerlkleTree.fromArray(input);
  console.log(input.length);
  
  const expectedRootHash = hashData(...input.map((addr) => hashData(addr)));
  assert.equal(Buffer.compare(tree.root.hash, expectedRootHash), 0);
  
  const expectedProof = [hashData(input[1])];
  const proof = tree.getProof(input[0]);
  assert.deepEqual(proof, expectedProof);

  assert.ok(tree.verify(proof, input[0]));
});

it('should verify', () => {
  const input = [...whitelistAddresses];
  const tree = MerlkleTree.fromArray(input);
  
  const randomIndex = Math.floor(Math.random() * input.length);
  const addressFromTheList = input.at(randomIndex);

  const proof = tree.getProof(addressFromTheList);

  assert.ok(tree.verify(proof, addressFromTheList));

  assert.ok(!tree.verify(proof, 'random string'));
});

it.skip('should hash data', () => {
  const hashedAddresses = [...whitelistAddresses].map((addr) => hashData(addr) );

  function calcRoot(input) {
    if (input.length < 2) {
      return input;
    }

    const pairsIter = splitIntoPairs(input);
    const pairs = Array.from(pairsIter);
    const reducedLeaves = pairs.map(hashData);
    return calcRoot(reducedLeaves);
  }

  const root = calcRoot(hashedAddresses);
  console.log({ root });
})

it.skip('should create correct merlkle tree', () =>{

  const pairsIter = splitIntoPairs(whitelistAddresses);
  const pairs = Array.from(pairsIter);
  // for (let pair of pairs) {
    
    // }
    
  console.log(pairs);
  console.log(hashData(pairs.at(0)));
  // console.log([...splitIntoPairs(whitelistAddresses)]);
});
