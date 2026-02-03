// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import "./extensions/ERC7857CloneableUpgradeable.sol";
import "./extensions/ERC7857AuthorizeUpgradeable.sol";
import "./extensions/ERC7857IDataStorageUpgradeable.sol";
import "./interfaces/IERC7857DataVerifier.sol";
import "./Utils.sol";

contract AgentNFT is
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    ERC7857CloneableUpgradeable,
    ERC7857AuthorizeUpgradeable,
    ERC7857IDataStorageUpgradeable
{
    /// @notice The event emitted when the admin is changed
    /// @param _oldAdmin The old admin
    /// @param _newAdmin The new admin
    event AdminChanged(address indexed _oldAdmin, address indexed _newAdmin);

    /// @notice The event emitted when a creator is set for a token
    /// @param tokenId The token ID
    /// @param creator The creator address
    event CreatorSet(uint256 indexed tokenId, address indexed creator);

    /// @notice The event emitted when the base URI is updated
    /// @param oldBaseURI The old base URI
    /// @param newBaseURI The new base URI
    event BaseURIUpdated(string oldBaseURI, string newBaseURI);

    /// @notice The event emitted when a token URI is updated
    /// @param tokenId The token ID
    /// @param newURI The new token URI
    event TokenURIUpdated(uint256 indexed tokenId, string newURI);

    /// @notice The event emitted when the verifier is updated
    /// @param oldVerifier The old verifier address
    /// @param newVerifier The new verifier address
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @custom:storage-location erc7201:agent.storage.AgentNFT
    struct AgentNFTStorage {
        // Contract metadata
        string storageInfo;
        // Core components
        address admin;
        // Mint fee
        uint256 mintFee;
        // Standard NFT metadata support
        string baseURI;
        mapping(uint256 => string) customURIs;
        // Creator/Partner tracking for fee distribution
        mapping(uint256 => address) creators;
    }

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    string public constant VERSION = "1.0.0";

    // keccak256(abi.encode(uint(keccak256("agent.storage.AgentNFT")) - 1)) & ~bytes32(uint(0xff))
    bytes32 private constant AGENT_NFT_STORAGE_LOCATION =
        0x4aa80aaafbe0e5fe3fe1aa97f3c1f8c65d61f96ef1aab2b448154f4e07594600;

    function _getAgentStorage() private pure returns (AgentNFTStorage storage $) {
        assembly {
            $.slot := AGENT_NFT_STORAGE_LOCATION
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory name_,
        string memory symbol_,
        string memory storageInfo_,
        address verifierAddr,
        address admin_
    ) public virtual initializer {
        require(verifierAddr != address(0), "Zero address");
        require(admin_ != address(0), "Invalid admin address");

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __ERC7857_init(name_, symbol_, verifierAddr);

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(ADMIN_ROLE, admin_);
        _grantRole(OPERATOR_ROLE, admin_);
        _grantRole(MINTER_ROLE, admin_);

        AgentNFTStorage storage $ = _getAgentStorage();
        $.storageInfo = storageInfo_;
        $.admin = admin_;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(AccessControlUpgradeable, ERC7857Upgradeable, IERC165) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function setAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newAdmin != address(0), "Invalid admin address");
        address oldAdmin = _getAgentStorage().admin;

        if (oldAdmin != newAdmin) {
            _getAgentStorage().admin = newAdmin;

            _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
            _grantRole(ADMIN_ROLE, newAdmin);

            _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
            _revokeRole(ADMIN_ROLE, oldAdmin);

            emit AdminChanged(oldAdmin, newAdmin);
        }
    }

    // Basic getters
    function admin() public view virtual returns (address) {
        return _getAgentStorage().admin;
    }

    /// @notice Grant MINTER_ROLE to a trusted contract (e.g., AgentMarket)
    function grantMinterRole(address minter) external onlyRole(ADMIN_ROLE) {
        require(minter != address(0), "Invalid minter address");
        _grantRole(MINTER_ROLE, minter);
    }

    /// @notice Revoke MINTER_ROLE from an address
    function revokeMinterRole(address minter) external onlyRole(ADMIN_ROLE) {
        _revokeRole(MINTER_ROLE, minter);
    }

    // Operator functions
    function updateVerifier(address newVerifier) public virtual onlyRole(OPERATOR_ROLE) {
        require(newVerifier != address(0), "Zero address");
        address oldVerifier = address(verifier());
        _setVerifier(newVerifier);
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    function update(
        uint256 tokenId,
        IntelligentData[] calldata newDatas,
        bytes[] memory sealedKeys
    ) public virtual whenNotPaused {
        require(_ownerOf(tokenId) == msg.sender, "Not owner");
        require(newDatas.length > 0, "Empty data array");

        _updateData(tokenId, newDatas, sealedKeys);
    }

    function mint(
        IntelligentData[] calldata iDatas,
        address to,
        bytes[] memory sealedKeys
    ) public payable virtual whenNotPaused returns (uint256 tokenId) {
        require(to != address(0), "Zero address");
        require(iDatas.length > 0, "Empty data array");

        AgentNFTStorage storage $ = _getAgentStorage();
        require(msg.value >= $.mintFee, "Insufficient mint fee");

        tokenId = _incrementTokenId();
        _safeMint(to, tokenId);
        _updateData(tokenId, iDatas, sealedKeys);
    }

    /// @notice Mint iNFT with MINTER_ROLE (for AgentMarket contract)
    /// @dev No fee required - used by trusted contracts like AgentMarket
    function mintWithRole(
        IntelligentData[] calldata iDatas,
        address to,
        bytes[] memory sealedKeys
    ) public virtual onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        require(to != address(0), "Zero address");
        require(iDatas.length > 0, "Empty data array");

        tokenId = _incrementTokenId();
        _safeMint(to, tokenId);
        _updateData(tokenId, iDatas, sealedKeys);
    }

    /// @notice Mint standard NFT with MINTER_ROLE (for AgentMarket contract)
    /// @dev No fee required - used by trusted contracts like AgentMarket
    function mintWithRole(address to) public virtual onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        return mintWithRole(to, "");
    }

    /// @notice Mint standard NFT with custom URI and MINTER_ROLE (for AgentMarket contract)
    /// @dev No fee required - used by trusted contracts like AgentMarket
    function mintWithRole(
        address to,
        string memory uri
    ) public virtual onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        require(to != address(0), "Zero address");

        tokenId = _incrementTokenId();
        _safeMint(to, tokenId);

        if (bytes(uri).length > 0) {
            AgentNFTStorage storage $ = _getAgentStorage();
            $.customURIs[tokenId] = uri;
        }
    }

    /// @notice Mint iNFT with creator tracking (for fee distribution)
    /// @dev No fee required - used by AgentMarket for partner NFTs
    function mintWithRole(
        IntelligentData[] calldata iDatas,
        address to,
        address creator,
        bytes[] memory sealedKeys
    ) public virtual onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        require(to != address(0), "Zero address");
        require(iDatas.length > 0, "Empty data array");

        tokenId = _incrementTokenId();
        _safeMint(to, tokenId);
        _updateData(tokenId, iDatas, sealedKeys);

        if (creator != address(0)) {
            AgentNFTStorage storage $ = _getAgentStorage();
            $.creators[tokenId] = creator;
            emit CreatorSet(tokenId, creator);
        }
    }

    /// @notice Mint standard NFT with creator tracking (for fee distribution)
    /// @dev No fee required - used by AgentMarket for partner NFTs
    function mintWithRole(
        address to,
        string memory uri,
        address creator
    ) public virtual onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        require(to != address(0), "Zero address");

        tokenId = _incrementTokenId();
        _safeMint(to, tokenId);

        AgentNFTStorage storage $ = _getAgentStorage();
        if (bytes(uri).length > 0) {
            $.customURIs[tokenId] = uri;
        }
        if (creator != address(0)) {
            $.creators[tokenId] = creator;
            emit CreatorSet(tokenId, creator);
        }
    }

    /// @notice Mint a standard NFT (for migration compatibility)
    function mint(address to) public payable virtual whenNotPaused returns (uint256 tokenId) {
        return mint(to, "");
    }

    /// @notice Mint a standard NFT with custom URI (for migration compatibility)
    function mint(address to, string memory uri) public payable virtual whenNotPaused returns (uint256 tokenId) {
        require(to != address(0), "Zero address");

        AgentNFTStorage storage $ = _getAgentStorage();
        require(msg.value >= $.mintFee, "Insufficient mint fee");

        tokenId = _incrementTokenId();
        _safeMint(to, tokenId);

        if (bytes(uri).length > 0) {
            $.customURIs[tokenId] = uri;
        }

        // Refund excess payment
        _refundExcess($.mintFee);
    }

    function storageInfo() public view virtual returns (string memory) {
        return _getAgentStorage().storageInfo;
    }

    function batchAuthorizeUsage(uint256 tokenId, address[] calldata users) public virtual {
        require(users.length > 0, "Empty users array");
        require(_ownerOf(tokenId) == msg.sender, "Not owner");

        for (uint i = 0; i < users.length; i++) {
            require(users[i] != address(0), "Zero address in users");
            _authorizeUsage(tokenId, users[i]);
        }
    }

    function clearAuthorizedUsers(uint256 tokenId) public virtual {
        require(_ownerOf(tokenId) == msg.sender, "Not owner");

        _clearAuthorized(tokenId);
        emit AuthorizedUsersCleared(msg.sender, tokenId);
    }

    event AuthorizedUsersCleared(address indexed owner, uint256 indexed tokenId);

    /// @notice Internal helper to refund excess payment
    /// @param requiredAmount The required payment amount
    function _refundExcess(uint256 requiredAmount) internal {
        if (msg.value > requiredAmount) {
            uint256 excess = msg.value - requiredAmount;
            (bool success, ) = payable(msg.sender).call{value: excess}("");
            require(success, "Refund failed");
        }
    }

    // Mint fee management
    event MintFeeUpdated(uint256 oldFee, uint256 newFee);

    function setMintFee(uint256 newMintFee) external onlyRole(OPERATOR_ROLE) {
        AgentNFTStorage storage $ = _getAgentStorage();
        uint256 oldFee = $.mintFee;
        $.mintFee = newMintFee;
        emit MintFeeUpdated(oldFee, newMintFee);
    }

    function getMintFee() external view returns (uint256) {
        return _getAgentStorage().mintFee;
    }

    function withdrawFees() external onlyRole(ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        require(balance > 0, "No fees to withdraw");

        address adminAddr = _getAgentStorage().admin;
        (bool success, ) = payable(adminAddr).call{value: balance}("");
        require(success, "Transfer failed");
    }

    // Standard NFT metadata support (ERC721Metadata)
    function tokenURI(
        uint256 tokenId
    ) public view virtual override(ERC721Upgradeable, IERC721Metadata) returns (string memory) {
        _requireOwned(tokenId);

        AgentNFTStorage storage $ = _getAgentStorage();

        // Priority 1: Custom URI
        string memory customURI = $.customURIs[tokenId];
        if (bytes(customURI).length > 0) {
            return customURI;
        }

        // Priority 2: baseURI + tokenId
        string memory base = $.baseURI;
        if (bytes(base).length > 0) {
            return string(abi.encodePacked(base, Strings.toString(tokenId)));
        }

        // Priority 3: Return first dataDescription if it looks like a URI
        IntelligentData[] memory datas = _intelligentDatasOf(tokenId);
        if (datas.length > 0 && bytes(datas[0].dataDescription).length > 0) {
            return datas[0].dataDescription;
        }

        return "";
    }

    function setBaseURI(string memory newBaseURI) external onlyRole(OPERATOR_ROLE) {
        AgentNFTStorage storage $ = _getAgentStorage();
        string memory oldBaseURI = $.baseURI;
        $.baseURI = newBaseURI;
        emit BaseURIUpdated(oldBaseURI, newBaseURI);
    }

    function setTokenURI(uint256 tokenId, string memory newURI) external {
        require(_ownerOf(tokenId) == msg.sender, "Not owner");
        _getAgentStorage().customURIs[tokenId] = newURI;
        emit TokenURIUpdated(tokenId, newURI);
    }

    /// @notice Get the creator of a token
    /// @param tokenId The token ID
    /// @return The creator address
    function creatorOf(uint256 tokenId) public view virtual returns (address) {
        return _getAgentStorage().creators[tokenId];
    }

    /// @notice Set the creator of a token (only OPERATOR_ROLE)
    /// @param tokenId The token ID
    /// @param creator The creator address
    function setCreator(uint256 tokenId, address creator) external onlyRole(OPERATOR_ROLE) {
        require(_ownerOf(tokenId) != address(0), "Token does not exist");
        _getAgentStorage().creators[tokenId] = creator;
        emit CreatorSet(tokenId, creator);
    }

    // Pausable functions
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*=== override ===*/
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override(ERC721Upgradeable, ERC7857AuthorizeUpgradeable) returns (address) {
        address from = super._update(to, tokenId, auth);

        return from;
    }

    function _updateData(
        uint256 tokenId,
        IntelligentData[] memory newDatas,
        bytes[] memory sealedKeys
    ) internal override(ERC7857IDataStorageUpgradeable, ERC7857Upgradeable) {
        ERC7857IDataStorageUpgradeable._updateData(tokenId, newDatas, sealedKeys);
    }

    function _intelligentDatasOf(
        uint tokenId
    )
        internal
        view
        virtual
        override(ERC7857IDataStorageUpgradeable, ERC7857Upgradeable)
        returns (IntelligentData[] memory)
    {
        return ERC7857IDataStorageUpgradeable._intelligentDatasOf(tokenId);
    }

    function _intelligentDatasLengthOf(
        uint tokenId
    ) internal view virtual override(ERC7857IDataStorageUpgradeable, ERC7857Upgradeable) returns (uint) {
        return ERC7857IDataStorageUpgradeable._intelligentDatasLengthOf(tokenId);
    }
}
