// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IERC7857DataVerifier.sol";

abstract contract BaseVerifier is IERC7857DataVerifier {
    // prevent replay attack
    mapping(bytes32 => bool) internal usedProofs;

    // prevent replay attack
    mapping(bytes32 => uint256) internal proofTimestamps;

    function _checkAndMarkProof(bytes32 proofNonce) internal {
        require(!usedProofs[proofNonce], "Proof already used");
        usedProofs[proofNonce] = true;
        proofTimestamps[proofNonce] = block.timestamp;
    }

    /// @notice Get the maximum proof age from implementation
    /// @return The maximum proof age in seconds
    function _getMaxProofAge() internal view virtual returns (uint256);

    // clean expired proof records (save gas)
    function cleanExpiredProofs(bytes32[] calldata proofNonces) external {
        uint256 maxAge = _getMaxProofAge();
        for (uint256 i = 0; i < proofNonces.length; i++) {
            bytes32 nonce = proofNonces[i];
            if (usedProofs[nonce] && block.timestamp > proofTimestamps[nonce] + maxAge) {
                delete usedProofs[nonce];
                delete proofTimestamps[nonce];
            }
        }
    }

    uint256[50] private __gap;
}
