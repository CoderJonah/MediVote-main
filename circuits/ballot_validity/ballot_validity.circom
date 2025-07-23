pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/*
 * Ballot Validity Circuit
 * 
 * This circuit proves that a ballot is properly formatted:
 * 1. Each vote choice is either 0 or 1 (binary choice)
 * 2. Exactly one candidate is selected (sum of choices equals 1)
 * 3. The ballot is committed using a proper nullifier
 * 4. The ballot timestamp is within the election period
 * 
 * WITHOUT REVEALING:
 * - Which candidate was selected
 * - The voter's identity
 * - The random nullifier value
 */

template BallotValidity(nCandidates) {
    // Private inputs (known only to voter)
    signal private input voteChoices[nCandidates];  // 0 or 1 for each candidate
    signal private input nullifierSecret;
    signal private input timestamp;
    signal private input randomNonce;
    
    // Public inputs (verifiable by anyone)
    signal input electionId;
    signal input ballotCommitment;  // Commitment to this ballot
    signal input electionStartTime;
    signal input electionEndTime;
    
    // Outputs (public)
    signal output validBallot;
    
    // Component declarations
    component voteValidators[nCandidates];
    component sumValidator = IsEqual();
    component timeRangeStart = GreaterEqThan(64);
    component timeRangeEnd = LessEqThan(64);
    component commitmentHasher = Poseidon(nCandidates + 3);
    component commitmentValidator = IsEqual();
    
    // 1. Validate each vote choice is binary (0 or 1)
    signal voteSum;
    voteSum <== 0;
    
    for (var i = 0; i < nCandidates; i++) {
        // Check that voteChoice[i] * (voteChoice[i] - 1) == 0
        // This is only true when voteChoice[i] is 0 or 1
        voteValidators[i] = IsEqual();
        voteValidators[i].in[0] <== voteChoices[i] * (voteChoices[i] - 1);
        voteValidators[i].in[1] <== 0;
        
        // Add to sum for later validation
        voteSum <== voteSum + voteChoices[i];
    }
    
    // 2. Validate exactly one vote is cast (sum equals 1)
    sumValidator.in[0] <== voteSum;
    sumValidator.in[1] <== 1;
    
    // 3. Validate timestamp is within election period
    timeRangeStart.in[0] <== timestamp;
    timeRangeStart.in[1] <== electionStartTime;
    
    timeRangeEnd.in[0] <== timestamp;
    timeRangeEnd.in[1] <== electionEndTime;
    
    // 4. Validate ballot commitment
    // The commitment should be hash(electionId, nullifierSecret, randomNonce, voteChoices...)
    commitmentHasher.inputs[0] <== electionId;
    commitmentHasher.inputs[1] <== nullifierSecret;
    commitmentHasher.inputs[2] <== randomNonce;
    
    for (var i = 0; i < nCandidates; i++) {
        commitmentHasher.inputs[i + 3] <== voteChoices[i];
    }
    
    commitmentValidator.in[0] <== commitmentHasher.out;
    commitmentValidator.in[1] <== ballotCommitment;
    
    // 5. Combine all validations - ALL must pass for valid ballot
    signal allVotesValid;
    allVotesValid <== 1;
    
    // Each vote choice must be valid
    for (var i = 0; i < nCandidates; i++) {
        allVotesValid <== allVotesValid * voteValidators[i].out;
    }
    
    // Final validation: all conditions must be met
    validBallot <== allVotesValid * sumValidator.out * timeRangeStart.out * timeRangeEnd.out * commitmentValidator.out;
}

/*
 * Ballot Encryption Circuit
 * 
 * This circuit proves that an encrypted vote corresponds to a valid ballot
 * without revealing the vote contents
 */
template BallotEncryption(nCandidates) {
    // Private inputs
    signal private input voteChoices[nCandidates];
    signal private input encryptionKey;
    signal private input randomness[nCandidates];
    
    // Public inputs
    signal input encryptedVotes[nCandidates];  // Encrypted vote for each candidate
    signal input publicKey;  // Election public key
    
    // Output
    signal output validEncryption;
    
    // Component declarations
    component encryptors[nCandidates];
    component encryptionValidators[nCandidates];
    
    // Verify each encrypted vote
    for (var i = 0; i < nCandidates; i++) {
        // Simulate encryption: encryptedVote = hash(publicKey, voteChoice, randomness)
        encryptors[i] = Poseidon(3);
        encryptors[i].inputs[0] <== publicKey;
        encryptors[i].inputs[1] <== voteChoices[i];
        encryptors[i].inputs[2] <== randomness[i];
        
        // Verify the encryption matches
        encryptionValidators[i] = IsEqual();
        encryptionValidators[i].in[0] <== encryptors[i].out;
        encryptionValidators[i].in[1] <== encryptedVotes[i];
    }
    
    // All encryptions must be valid
    signal allEncryptionsValid;
    allEncryptionsValid <== 1;
    for (var i = 0; i < nCandidates; i++) {
        allEncryptionsValid <== allEncryptionsValid * encryptionValidators[i].out;
    }
    
    validEncryption <== allEncryptionsValid;
}

// Main components
component main = BallotValidity(5);  // Support 5 candidates
