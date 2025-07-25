pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/*
 * Voter Eligibility Circuit
 * 
 * This circuit proves that:
 * 1. The voter knows their private key corresponding to their public DID
 * 2. The voter's public DID is in the list of eligible voters (Merkle tree)
 * 3. The voter has not voted before (nullifier uniqueness)
 * 4. The vote choice is valid (0 or 1 for each candidate)
 * 
 * WITHOUT REVEALING:
 * - The voter's identity
 * - The voter's vote choice
 * - The voter's private key
 */

template VoterEligibility(nLevels, nCandidates) {
    // Private inputs (known only to voter)
    signal private input voterPrivateKey;
    signal private input voterId;  // Position in eligible voter list
    signal private input voteChoices[nCandidates];  // 0 or 1 for each candidate
    signal private input merklePathElements[nLevels];
    signal private input merklePathIndices[nLevels];
    signal private input nullifierSecret;
    
    // Public inputs (verifiable by anyone)
    signal input merkleRoot;  // Root of eligible voter Merkle tree
    signal input electionId;
    signal input nullifierHash;  // Prevents double voting
    signal input voteCommitment;  // Commitment to vote choices
    
    // Outputs (public)
    signal output validProof;
    
    // Component declarations
    component hasher = Poseidon(2);
    component merkleProof = MerkleTreeChecker(nLevels);
    component nullifierHasher = Poseidon(3);
    component voteCommitmentHasher = Poseidon(nCandidates + 1);
    component voteValidators[nCandidates];
    component sumCheck = LessThan(8);  // Max 2^8 = 256 candidates
    
    // 1. Verify voter's public key from private key
    component pubKeyHasher = Poseidon(1);
    pubKeyHasher.inputs[0] <== voterPrivateKey;
    signal voterPublicKey;
    voterPublicKey <== pubKeyHasher.out;
    
    // 2. Verify voter is in eligible list via Merkle proof
    merkleProof.leaf <== voterPublicKey;
    merkleProof.root <== merkleRoot;
    for (var i = 0; i < nLevels; i++) {
        merkleProof.pathElements[i] <== merklePathElements[i];
        merkleProof.pathIndices[i] <== merklePathIndices[i];
    }
    
    // 3. Verify nullifier to prevent double voting
    nullifierHasher.inputs[0] <== voterPrivateKey;
    nullifierHasher.inputs[1] <== electionId;
    nullifierHasher.inputs[2] <== nullifierSecret;
    nullifierHasher.out === nullifierHash;
    
    // 4. Validate vote choices (each must be 0 or 1)
    signal voteSum;
    voteSum <== 0;
    for (var i = 0; i < nCandidates; i++) {
        voteValidators[i] = IsEqual();
        voteValidators[i].in[0] <== voteChoices[i] * (voteChoices[i] - 1);
        voteValidators[i].in[1] <== 0;
        voteValidators[i].out === 1;  // Must be true for valid vote
        
        voteSum <== voteSum + voteChoices[i];
    }
    
    // 5. Ensure exactly one vote is cast (sum must equal 1)
    component oneVoteCheck = IsEqual();
    oneVoteCheck.in[0] <== voteSum;
    oneVoteCheck.in[1] <== 1;
    oneVoteCheck.out === 1;
    
    // 6. Verify vote commitment
    voteCommitmentHasher.inputs[0] <== nullifierSecret;
    for (var i = 0; i < nCandidates; i++) {
        voteCommitmentHasher.inputs[i + 1] <== voteChoices[i];
    }
    voteCommitmentHasher.out === voteCommitment;
    
    // All checks must pass
    validProof <== merkleProof.root * oneVoteCheck.out * voteValidators[0].out;
}

// Helper template for Merkle tree verification
template MerkleTreeChecker(nLevels) {
    signal input leaf;
    signal input root;
    signal input pathElements[nLevels];
    signal input pathIndices[nLevels];
    
    component hashers[nLevels];
    component mux[nLevels];
    
    signal levelHashes[nLevels + 1];
    levelHashes[0] <== leaf;
    
    for (var i = 0; i < nLevels; i++) {
        hashers[i] = Poseidon(2);
        mux[i] = MultiMux1(2);
        
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        
        mux[i].s <== pathIndices[i];
        
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        
        levelHashes[i + 1] <== hashers[i].out;
    }
    
    root === levelHashes[nLevels];
}

// Component for the main circuit
component main = VoterEligibility(20, 5);  // Support 2^20 voters, 5 candidates
