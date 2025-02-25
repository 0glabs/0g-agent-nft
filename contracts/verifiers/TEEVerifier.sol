// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./base/BaseVerifier.sol";

contract TEEVerifier is BaseVerifier {
    address public immutable attestationContract;

    constructor(address _attestationContract) {
        attestationContract = _attestationContract;
    }

    /// @notice Verify preimage of data, the _proof prove:
    ///         for public data, the proof is knowing the pre-image of dataHashes
    ///         for private data, the proof is knowing the pre-image of dataHashes and the plaintext of the pre-image
    ///         if preimage proof is not required, the proof is the data itself ✅
    /// @param proofs Proof generated by TEE
    function verifyPreimage(
        bytes[] calldata proofs
    ) external pure override returns (PreimageProofOutput[] memory) {
        PreimageProofOutput[] memory outputs = new PreimageProofOutput[](
            proofs.length
        );
        for (uint256 i = 0; i < proofs.length; i++) {
            require(proofs[i].length == 32, "Invalid data hash length");
            bytes32 dataHash = bytes32(proofs[i]);

            bool isValid = true;

            outputs[i] = PreimageProofOutput(dataHash, isValid);
        }
        return outputs;
    }

    /// @notice Verify data transfer validity, the _proof prove:
    ///         1. The pre-image of oldDataHashes
    ///         2. The oldKey can decrypt the pre-image and the new key re-encrypt the plaintexts to new ciphertexts
    ///         3. The newKey is encrypted with the receiver's pubKey to get the sealedKey
    ///         4. The hashes of new ciphertexts is newDataHashes (key to note: TEE could support a private key of the receiver)
    ///         5. The newDataHashes identified ciphertexts are available in the storage: need the signature from the receiver signing oldDataHashes and newDataHashes
    /// @param proofs Proof generated by TEE
    function verifyTransferValidity(
        bytes[] calldata proofs
    ) external view override returns (TransferValidityProofOutput[] memory) {
        TransferValidityProofOutput[]
            memory outputs = new TransferValidityProofOutput[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            // 144 bytes for oldDataHashes, newDataHashes, pubKey, sealedKey, TODO: proofs payload
            require(proofs[i].length == 144, "Invalid proof length");

            bytes32 oldHash = bytes32(proofs[i][0:32]);
            bytes32 newHash = bytes32(proofs[i][32:64]);
            bytes memory pubKey = proofs[i][64:128];
            bytes16 sealedKey = bytes16(proofs[i][128:144]);

            // TODO: verify the proofs
            // 1. verify TEE signature
            // 2. verify receiver's signature

            outputs[i] = TransferValidityProofOutput(
                oldHash,
                newHash,
                pubKey,
                sealedKey,
                true
            );
        }

        return outputs;
    }
}
