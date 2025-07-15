pragma circom 2.0.0;

template BallotValidity() {
    signal input vote_sum;
    signal input max_votes;
    signal output valid;
    
    // Check that sum of votes equals max allowed votes
    component eq = IsEqual();
    eq.in[0] <== vote_sum;
    eq.in[1] <== max_votes;
    valid <== eq.out;
}

template IsEqual() {
    signal input in[2];
    signal output out;
    
    component eq = IsZero();
    eq.in <== in[0] - in[1];
    out <== eq.out;
}

template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in!=0 ? 1/in : 0;
    out <== -in*inv +1;
    in*out === 0;
}

component main = BallotValidity();
