pragma circom 2.2.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// Semaphore-style statement (BN254 only: circomlib's Poseidon constants are
// defined for the BN254 scalar field):
//   commitment = Poseidon(secret, salt)          public output
//   nullifier  = Poseidon(secret, externalTopic) public output
//   externalTopic                                public input
// The nullifier is what a consumer should de-duplicate on.
template Nullifier() {
    signal input secret;
    signal input salt;
    signal input externalTopic;
    signal output commitment;
    signal output nullifier;

    component c = Poseidon(2);
    c.inputs[0] <== secret;
    c.inputs[1] <== salt;
    commitment <== c.out;

    component n = Poseidon(2);
    n.inputs[0] <== secret;
    n.inputs[1] <== externalTopic;
    nullifier <== n.out;
}

component main {public [externalTopic]} = Nullifier();
