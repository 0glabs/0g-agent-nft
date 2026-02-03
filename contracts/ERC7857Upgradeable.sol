// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721Upgradeable, IERC721} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";

import {IERC7857} from "./interfaces/IERC7857.sol";
import {IntelligentData} from "./interfaces/IERC7857Metadata.sol";
import {
    IERC7857DataVerifier,
    TransferValidityProof,
    TransferValidityProofOutput
} from "./interfaces/IERC7857DataVerifier.sol";

import "./Utils.sol";

contract ERC7857Upgradeable is IERC7857, ERC721Upgradeable {
    /// @custom:storage-location erc7857:0g.storage.ERC7857
    struct ERC7857Storage {
        mapping(address owner => address) accessAssistants;
        IERC7857DataVerifier verifier;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.ERC7857")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC7857StorageLocation =
        0xa2b40c657abdbf180a6038c081d3a0af6206dcea36f4558f991bf8c787ef3c00;

    function _getERC7857Storage() private pure returns (ERC7857Storage storage $) {
        assembly {
            $.slot := ERC7857StorageLocation
        }
    }

    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    function __ERC7857_init(string memory name_, string memory symbol_, address verifier_) internal onlyInitializing {
        __ERC721_init(name_, symbol_);
        __ERC7857_init_unchained(verifier_);
    }

    function __ERC7857_init_unchained(address verifier_) internal onlyInitializing {
        _setVerifier(verifier_);
    }

    function _setVerifier(address verifier_) internal {
        ERC7857Storage storage $ = _getERC7857Storage();
        $.verifier = IERC7857DataVerifier(verifier_);
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC721Upgradeable, IERC165) returns (bool) {
        return interfaceId == type(IERC7857).interfaceId || super.supportsInterface(interfaceId);
    }

    function delegateAccess(address assistant) public virtual {
        // Allow setting to zero address to revoke delegation
        ERC7857Storage storage $ = _getERC7857Storage();
        $.accessAssistants[msg.sender] = assistant;

        emit DelegateAccess(msg.sender, assistant);
    }

    function getDelegateAccess(address user) public view virtual returns (address) {
        ERC7857Storage storage $ = _getERC7857Storage();
        return $.accessAssistants[user];
    }

    function _proofCheck(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) internal returns (bytes[] memory sealedKeys) {
        ERC7857Storage storage $ = _getERC7857Storage();
        if (to == address(0)) {
            revert ERC721InvalidReceiver(to);
        }
        if (_ownerOf(tokenId) != from) {
            revert ERC721InvalidSender(from);
        }
        if (proofs.length == 0) {
            revert ERC7857EmptyProof();
        }

        TransferValidityProofOutput[] memory proofOutput = $.verifier.verifyTransferValidity(proofs);

        IntelligentData[] memory datas = _intelligentDatasOf(tokenId);

        if (proofOutput.length != datas.length) {
            revert ERC7857ProofCountMismatch();
        }

        sealedKeys = new bytes[](proofOutput.length);

        for (uint i = 0; i < proofOutput.length; i++) {
            // require the token's data hash is the same as the data hash in the proof
            if (proofOutput[i].dataHash != datas[i].dataHash) {
                revert ERC7857DataHashMismatch();
            }

            // only the receiver itself or the access assistant can sign the access proof
            if (proofOutput[i].accessAssistant != $.accessAssistants[to] && proofOutput[i].accessAssistant != to) {
                revert ERC7857AccessAssistantMismatch();
            }

            bytes memory wantedKey = proofOutput[i].wantedKey;
            bytes memory targetPubkey = proofOutput[i].targetPubkey;
            if (wantedKey.length == 0) {
                // if the wanted key is empty, the default wanted receiver is receiver itself
                address defaultWantedReceiver = Utils.pubKeyToAddress(targetPubkey);
                if (defaultWantedReceiver != to) {
                    revert ERC7857WantedReceiverMismatch();
                }
            } else {
                // if the wanted key is not empty, the data is private
                if (!Utils.bytesEqual(targetPubkey, wantedKey)) {
                    revert ERC7857TargetPubkeyMismatch();
                }
            }

            sealedKeys[i] = proofOutput[i].sealedKey;
        }
    }

    function _transfer(address from, address to, uint256 tokenId, TransferValidityProof[] calldata proofs) internal {
        bytes[] memory sealedKeys = _proofCheck(from, to, tokenId, proofs);

        safeTransferFrom(from, to, tokenId);

        emit PublishedSealedKey(to, tokenId, sealedKeys);
    }

    function iTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        TransferValidityProof[] calldata proofs
    ) public virtual {
        // owner and authority will be checked in _proofCheck()
        _transfer(from, to, tokenId, proofs);
    }

    /**
     * @notice Empty by default, can be overridden in child contracts.
     */
    function _intelligentDatasOf(
        uint //tokenId
    ) internal view virtual returns (IntelligentData[] memory) {
        return new IntelligentData[](0);
    }

    /**
     * @notice Empty by default, can be overridden in child contracts.
     */
    function _intelligentDatasLengthOf(
        uint //tokenId
    ) internal view virtual returns (uint) {
        return 0;
    }

    /**
     * @notice Empty by default, can be overridden in child contracts.
     */
    function _updateData(
        uint256 tokenId,
        IntelligentData[] memory newDatas,
        bytes[] memory sealedKeys
    ) internal virtual {}

    function intelligentDatasOf(uint256 tokenId) public view virtual returns (IntelligentData[] memory) {
        if (_ownerOf(tokenId) == address(0)) {
            revert ERC721NonexistentToken(tokenId);
        }
        return _intelligentDatasOf(tokenId);
    }

    function verifier() public view virtual returns (IERC7857DataVerifier) {
        ERC7857Storage storage $ = _getERC7857Storage();
        return $.verifier;
    }
}
