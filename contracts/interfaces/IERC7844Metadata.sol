// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC7844Metadata {
    /// @dev This emits when data is updated
    event Updated(
        uint256 indexed _tokenId,
        bytes32[] _oldDataHashes,
        bytes32[] _newDataHashes
    );

    /// @notice Get the name of the NFT collection
    function name() external view returns (string memory);

    /// @notice Get the symbol of the NFT collection
    function symbol() external view returns (string memory);

    /// @notice Get the config metadata for the NFT collection
    /// @return storageURL The base storage URL for the functional data
    function config() external view returns (
        string memory storageURL
    );

    /// @notice Set the config metadata (only owner)
    function setConfig(
        string memory storageURL
    ) external;

    /// @notice Get the metadata URI for a specific token
    function tokenURI(uint256 tokenId) external view returns (string memory);

    /// @notice Update data
    /// @param _tokenId The token to update
    /// @param _proof Proof of updated data ownership
    function update(
        uint256 _tokenId,
        bytes calldata _proof
    ) external;

    /// @notice Get the data hash of a token
    /// @param _tokenId The token identifier
    /// @return The current data hash of the token
    function dataHashesOf(uint256 _tokenId) external view returns (bytes32[] memory);
}
