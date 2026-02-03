// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ERC7857Upgradeable} from "../ERC7857Upgradeable.sol";
import {IntelligentData} from "../interfaces/IERC7857Metadata.sol";
import {
    IERC7857DataVerifier,
    TransferValidityProof,
    TransferValidityProofOutput
} from "../interfaces/IERC7857DataVerifier.sol";

contract ERC7857IDataStorageUpgradeable is ERC7857Upgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @custom:storage-location erc7857:0g.storage.ERC7857IDataStorage
    struct ERC7857IDataStorageStorage {
        mapping(uint tokenId => IntelligentData[]) iDatas;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC7857IDataStorage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC7857IDataStorageStorageLocation =
        0xcee27158032fdbe7e1246476ff878669b520bc82ee1a949d22135b88cc5f5b00;

    function _getERC7857IDataStorageStorage() private pure returns (ERC7857IDataStorageStorage storage $) {
        assembly {
            $.slot := ERC7857IDataStorageStorageLocation
        }
    }

    function _intelligentDatasOf(uint tokenId) internal view virtual override returns (IntelligentData[] memory) {
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();
        return $.iDatas[tokenId];
    }

    function _intelligentDatasLengthOf(uint tokenId) internal view virtual override returns (uint) {
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();
        return $.iDatas[tokenId].length;
    }

    function _updateData(
        uint256 tokenId,
        IntelligentData[] memory newDatas,
        bytes[] memory sealedKeys
    ) internal virtual override {
        ERC7857IDataStorageStorage storage $ = _getERC7857IDataStorageStorage();

        IntelligentData[] memory oldDatas = new IntelligentData[]($.iDatas[tokenId].length);
        for (uint i = 0; i < $.iDatas[tokenId].length; i++) {
            oldDatas[i] = $.iDatas[tokenId][i];
        }

        delete $.iDatas[tokenId];
        for (uint i = 0; i < newDatas.length; i++) {
            $.iDatas[tokenId].push(newDatas[i]);
        }
        address owner = _ownerOf(tokenId);
        emit Updated(tokenId, oldDatas, newDatas);
        emit PublishedSealedKey(owner, tokenId, sealedKeys);
    }
}
