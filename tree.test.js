import assert from 'node:assert';
import { it } from 'node:test';
import { Node, MerlkleTree, hashData } from './tree.js';


const whitelistAddresses = [
  "0X5B38DA6A701C568545DCFCB03FCB875F56BEDDC4", // 0 iter; i = 0
  "0X5A641E5FB72A2FD9137312E7694D42996D689D99",
  "0XDCAB482177A592E424D1C8318A464FC922E8DE40", // 1 iter; i = 2
  "0X6E21D37E07A6F7E53C7ACE372CEC63D4AE4B6BD0",
  "0X09BAAB19FC77C19898140DADD30C4685C597620B", // 2 iter; i = 4
  "0XCC4C29997177253376528C05D3DF91CF2D69061A",
  "0xdD870fA1b7C4700F2BD7f44238821C26f7392148", // 3 iter; i = 6
];

it('should create sorted node', () => {
  const data1 = new Uint8Array([0]);
  const node1 = Node.createLeaf(data1);
  assert.equal(Buffer.compare(node1.hash, hashData(data1)), 0);
  
  const data2 = new Uint8Array([1]);
  const node2 = Node.createLeaf(data2);

  const node3 = Node.fromNodePair([node1, node2]);

  assert.equal(node3.left, node2);
  assert.equal(node3.right, node1);
});

it('should create tree', () => {
  const input = whitelistAddresses.slice(0, 2);
  const tree = MerlkleTree.fromArray(input);
  
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

  {
    const proof = tree.getProof(addressFromTheList);
    assert.ok(tree.verify(proof, addressFromTheList));
  }

  {
    const proof = tree.getProof('random string');
    assert.ok(!proof);
  }
});