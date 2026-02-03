// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./base/BaseVerifier.sol";
import "../interfaces/IERC7857DataVerifier.sol";
import "../TeeVerifier.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

struct AttestationConfig {
    OracleType oracleType;
    address contractAddress;
}

contract Verifier is
    BaseVerifier,
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    event AttestationContractUpdated(AttestationConfig[] attestationConfigs);

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    string public constant VERSION = "1.0.0";

    /// @custom:storage-location erc7201:0g.storage.Verifier
    struct VerifierStorage {
        address admin;
        mapping(OracleType => address) attestationContract;
        uint256 maxProofAge;
    }

    // keccak256(abi.encode(uint256(keccak256("0g.storage.Verifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VERIFIER_STORAGE_LOCATION =
        0xbecdd708b48a40f3aa8e2248844b430477e64ef60f94c9d0bf26b790ba82a300;

    function _getVerifierStorage() private pure returns (VerifierStorage storage $) {
        assembly {
            $.slot := VERIFIER_STORAGE_LOCATION
        }
    }

    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(AttestationConfig[] calldata _attestationConfigs, address _admin) external initializer {
        require(_admin != address(0), "Invalid admin address");

        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        VerifierStorage storage $ = _getVerifierStorage();
        for (uint256 i = 0; i < _attestationConfigs.length; i++) {
            $.attestationContract[_attestationConfigs[i].oracleType] = _attestationConfigs[i].contractAddress;
        }
        $.maxProofAge = 7 days;

        // Set admin state variable
        $.admin = _admin;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        emit AttestationContractUpdated(_attestationConfigs);
    }

    function setAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newAdmin != address(0), "Invalid admin address");
        VerifierStorage storage $ = _getVerifierStorage();
        address oldAdmin = $.admin;

        if (oldAdmin != newAdmin) {
            $.admin = newAdmin;

            _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
            _grantRole(ADMIN_ROLE, newAdmin);
            _grantRole(OPERATOR_ROLE, newAdmin);

            // Only revoke if oldAdmin is not address(0)
            if (oldAdmin != address(0)) {
                _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
                _revokeRole(ADMIN_ROLE, oldAdmin);
                _revokeRole(OPERATOR_ROLE, oldAdmin);
            }

            emit AdminChanged(oldAdmin, newAdmin);
        }
    }

    function updateAttestationContract(AttestationConfig[] calldata _attestationConfigs) external onlyRole(ADMIN_ROLE) {
        VerifierStorage storage $ = _getVerifierStorage();
        for (uint256 i = 0; i < _attestationConfigs.length; i++) {
            $.attestationContract[_attestationConfigs[i].oracleType] = _attestationConfigs[i].contractAddress;
        }

        emit AttestationContractUpdated(_attestationConfigs);
    }

    function updateMaxProofAge(uint256 _maxProofAge) external onlyRole(ADMIN_ROLE) {
        VerifierStorage storage $ = _getVerifierStorage();
        $.maxProofAge = _maxProofAge;
    }

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    function hashNonce(bytes memory nonce) private view returns (bytes32) {
        return keccak256(abi.encode(nonce, msg.sender));
    }

    function teeOracleVerify(bytes32 messageHash, bytes memory signature) internal view returns (bool) {
        VerifierStorage storage $ = _getVerifierStorage();
        return TEEVerifier($.attestationContract[OracleType.TEE]).verifyTEESignature(messageHash, signature);
    }

    /// @notice Extract and verify signature from the access proof
    /// @param accessProof The access proof
    /// @return The recovered access assistant address
    function verifyAccessibility(AccessProof memory accessProof) private pure returns (address) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n66",
                Strings.toHexString(
                    uint256(
                        keccak256(abi.encodePacked(accessProof.dataHash, accessProof.targetPubkey, accessProof.nonce))
                    ),
                    32
                )
            )
        );

        address accessAssistant = messageHash.recover(accessProof.proof);
        require(accessAssistant != address(0), "Invalid access assistant");
        return accessAssistant;
    }

    function verifyOwnershipProof(OwnershipProof memory ownershipProof) private view returns (bool) {
        if (ownershipProof.oracleType == OracleType.TEE) {
            bytes32 messageHash = keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n66",
                    Strings.toHexString(
                        uint256(
                            keccak256(
                                abi.encodePacked(
                                    ownershipProof.dataHash,
                                    ownershipProof.sealedKey,
                                    ownershipProof.targetPubkey,
                                    ownershipProof.nonce
                                )
                            )
                        ),
                        32
                    )
                )
            );

            return teeOracleVerify(messageHash, ownershipProof.proof);
        }
        // TODO: add ZKP verification
        else {
            return false;
        }
    }

    /// @notice Process a single transfer validity proof
    /// @param proof The proof data
    /// @return output The processed proof data as a struct
    function processTransferProof(
        TransferValidityProof calldata proof
    ) private view returns (TransferValidityProofOutput memory output) {
        // compare the proof data in access proof and ownership proof
        require(proof.accessProof.dataHash == proof.ownershipProof.dataHash, "Invalid dataHash");
        output.dataHash = proof.accessProof.dataHash;

        output.wantedKey = proof.accessProof.targetPubkey;
        output.accessProofNonce = proof.accessProof.nonce;
        output.targetPubkey = proof.ownershipProof.targetPubkey;
        output.sealedKey = proof.ownershipProof.sealedKey;
        output.ownershipProofNonce = proof.ownershipProof.nonce;

        // verify the access assistant
        output.accessAssistant = verifyAccessibility(proof.accessProof);

        bool isValid = verifyOwnershipProof(proof.ownershipProof);

        require(isValid, "Invalid ownership proof");

        return output;
    }

    /// @notice Verify data transfer validity, the proofs prove:
    ///         1. The dataHash identified data is available to the target receiver
    ///         2. The dataHash identified data is owned by the sender
    ///         3. The dataHash identified data is decrypted by the data key, and the decrypted plaintext is good
    ///         4. The data key which is used to encrypt the dataHash identified data is delivered to the target receiver
    /// @param proofs Proof generated by TEE/ZKP
    function verifyTransferValidity(
        TransferValidityProof[] calldata proofs
    ) public virtual override whenNotPaused returns (TransferValidityProofOutput[] memory) {
        TransferValidityProofOutput[] memory outputs = new TransferValidityProofOutput[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            TransferValidityProofOutput memory output = processTransferProof(proofs[i]);

            outputs[i] = output;

            bytes32 accessProofNonce = hashNonce(output.accessProofNonce);
            _checkAndMarkProof(accessProofNonce);

            bytes32 ownershipProofNonce = hashNonce(output.ownershipProofNonce);
            _checkAndMarkProof(ownershipProofNonce);
        }

        return outputs;
    }

    function admin() public view returns (address) {
        return _getVerifierStorage().admin;
    }

    function attestationContract(OracleType oracleType) public view returns (address) {
        return _getVerifierStorage().attestationContract[oracleType];
    }

    function maxProofAge() public view returns (uint256) {
        return _getVerifierStorage().maxProofAge;
    }

    /// @notice Internal implementation of _getMaxProofAge for BaseVerifier
    /// @return The maximum proof age in seconds
    function _getMaxProofAge() internal view override returns (uint256) {
        return _getVerifierStorage().maxProofAge;
    }
}
