// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IERC7844DataVerifier.sol";

abstract contract BaseVerifier is IERC7844DataVerifier {
    // prevent replay attack
    mapping(bytes32 => bool) internal usedProofs;
    
    // check and mark proof used
    function _checkAndMarkProof(bytes32 proofHash) internal {
        require(!usedProofs[proofHash], "Proof already used");
        usedProofs[proofHash] = true;
    }
}