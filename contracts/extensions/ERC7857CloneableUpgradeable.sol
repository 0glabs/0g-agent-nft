// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC7857Upgradeable} from "../ERC7857Upgradeable.sol";
import {IERC7857Cloneable} from "../interfaces/IERC7857Cloneable.sol";
import {IntelligentData} from "../interfaces/IERC7857Metadata.sol";
import {
    IERC7857DataVerifier,
    TransferValidityProof,
    TransferValidityProofOutput
} from "../interfaces/IERC7857DataVerifier.sol";

contract ERC7857CloneableUpgradeable is IERC7857Cloneable, ERC7857Upgradeable {
    /// @custom:storage-location erc7857:0g.storage.ERC7857Cloneable
    struct ERC7857CloneableStorage {
        uint nextTokenId;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC7857Cloneable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC7857CloneableStorageLocation =
        0x03de6cf14ecf4575e0ed0cc2fdb9b7ee13500cb3c0c403254fc893bf6e0c8000;

    function _getERC7857CloneableStorage() private pure returns (ERC7857CloneableStorage storage $) {
        assembly {
            $.slot := ERC7857CloneableStorageLocation
        }
    }

    function _incrementTokenId() internal returns (uint nextTokenId) {
        ERC7857CloneableStorage storage $ = _getERC7857CloneableStorage();
        nextTokenId = $.nextTokenId;
        $.nextTokenId++;
    }

    function _clone(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) internal returns (uint256) {
        bytes[] memory sealedKeys = _proofCheck(from, to, tokenId, proofs);

        uint256 newTokenId = _incrementTokenId();
        _safeMint(to, newTokenId);
        IntelligentData[] memory datas = _intelligentDatasOf(tokenId);
        _updateData(newTokenId, datas, sealedKeys);

        emit Cloned(tokenId, newTokenId, from, to);

        return newTokenId;
    }

    function iCloneFrom(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) public virtual returns (uint256) {
        // check owner and authority
        if (_ownerOf(tokenId) != from) {
            revert ERC721InvalidSender(from);
        }
        _checkAuthorized(from, msg.sender, tokenId);
        return _clone(from, to, tokenId, proofs);
    }
}
