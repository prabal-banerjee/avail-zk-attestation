pragma circom 2.0.0;

include "poseidon.circom";          // For using Poseidon hash function
include "eddsaposeidon.circom";     // For signature verification

// Template to verify a new data root 
// Idea: Check if 2/3+1 has signed data root.
// Validator Set format: (validator public key x coord, validator public key y coord, weight)
template VerifyAttestation(validatorSetSize){
    // Old Validator set -> (pk_x, pk_y, weight) * (size of val set)
    signal input validatorSet[validatorSetSize * 3];
    signal input dataRoot;

    // Verify signature on the message by validator set
    component ValidatorSigCheck[validatorSetSize];

    signal input validatorsR8x[validatorSetSize];
    signal input validatorsR8y[validatorSetSize];
    signal input validatorsS[validatorSetSize];
    signal input validatorsIsSigned[validatorSetSize];

    // TODO: Should we check if weight_total is >=x? 
    var weight_total = 0;
    var weight_signed = 0;

    for (var i = 0; i < validatorSetSize; i++){
        ValidatorSigCheck[i] = EdDSAPoseidonVerifier();
        assert(validatorsIsSigned[i] * (validatorsIsSigned[i]-1) == 0 );
        ValidatorSigCheck[i].enabled <== validatorsIsSigned[i];
        weight_signed += validatorSet[i*3 + 2] * validatorsIsSigned[i];
        weight_total += validatorSet[i*3 + 2];
        ValidatorSigCheck[i].Ax <== validatorSet[i*3];
        ValidatorSigCheck[i].Ay <== validatorSet[i*3 + 1];
        ValidatorSigCheck[i].R8x <== validatorsR8x[i];
        ValidatorSigCheck[i].R8y <== validatorsR8y[i];
        ValidatorSigCheck[i].S <== validatorsS[i];
        ValidatorSigCheck[i].M <== dataRoot;
    }
    
    // Check 2/3+1 of weight has signed checkpoint
    // TODO: Can there be problem due to rounding off of weights? 
    assert((weight_total * 2)/3 + 1 <= weight_signed);

}

component main = VerifyAttestation(5);
