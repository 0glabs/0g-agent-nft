// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// TODO: Add proof type:
// 1. TEE proof
// 2. ZKP proof
struct PreimageProofOutput {
    bytes32 dataHash;
    bool isValid;
}

struct TransferValidityProofOutput {
    bytes32 oldDataHash;
    bytes32 newDataHash;
    bytes pubKey;
    bytes16 sealedKey;
    bool isValid;
}

interface IERC7857DataVerifier {
    /// @notice Verify preimage of data, the _proofs prove:
    ///         for public data, the proof is knowing the pre-image of dataHashes
    ///         for private data, the proof is knowing the pre-image of dataHashes and the plaintext of the pre-image
    ///         if preimage proof is not required, the proof is the data itself
    /// @param _proofs Proof generated by TEE/ZKP
    function verifyPreimage(
        bytes[] calldata _proofs
    ) external view returns (PreimageProofOutput[] memory);

    /// @notice Verify data transfer validity, the _proofs prove:
    ///         1. The pre-image of oldDataHashes
    ///         2. The oldKey can decrypt the pre-image and the new key re-encrypt the plaintexts to new ciphertexts
    ///         3. The newKey is encrypted using the receiver's pubKey
    ///         4. The hashes of new ciphertexts is newDataHashes
    ///         5. The newDataHashes identified ciphertexts are available in the storage: need the signature from the receiver signing oldDataHashes and newDataHashes
    /// @param _proofs Proof generated by TEE/ZKP
    function verifyTransferValidity(
        bytes[] calldata _proofs
    ) external view returns (TransferValidityProofOutput[] memory);
}
