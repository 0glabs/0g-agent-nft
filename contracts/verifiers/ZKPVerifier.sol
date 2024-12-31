// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./base/BaseVerifier.sol";

contract ZKPVerifier is BaseVerifier {
    address public immutable attestationContract;
    
    constructor(address _attestationContract) {
        attestationContract = _attestationContract;
    }

    /// @notice Verify ownership of data, the _proof prove: 
    ///         1. The pre-image of dataHashes
    /// @param proof Proof generated by ZKP
    function verifyOwnership(
        bytes calldata proof
    ) external view override returns (OwnershipProofOutput memory) {
        // TODO: Implement actual verification logic
        return OwnershipProofOutput(new bytes32[](0), true);
    }

    /// @notice Verify data transfer validity, the _proof prove: 
    ///         1. The pre-image of oldDataHashes
    ///         2. The oldKey can decrypt the pre-image and the new key re-encrypt the plaintexts to new ciphertexts
    ///         3. The newKey is encrypted using the receiver's pubKey
    ///         4. The hashes of new ciphertexts is newDataHashes (key to note: ZKP does not support private key of the receiver, the new key is visible for sender)
    ///         5. The newDataHashes identified ciphertexts are available in the storage: need the signature from the receiver signing oldDataHashes and newDataHashes
    /// @param proof Proof generated by ZKP
    function verifyTransferValidity(
        bytes calldata proof
    ) external view override returns (TransferValidityProofOutput memory) {
        // TODO: Implement actual verification logic
        return TransferValidityProofOutput(new bytes32[](0), new bytes32[](0), bytes("null"), bytes("null"), true);
    }
}