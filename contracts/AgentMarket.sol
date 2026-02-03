// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IAgentMarket.sol";
import "./interfaces/IERC7857.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./AgentNFT.sol";
import "./Utils.sol";

contract AgentMarket is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    IAgentMarket
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using SafeERC20 for IERC20;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    uint256 public constant MAX_FEE_RATE = 1000;
    string public constant VERSION = "1.0.0";

    /// @custom:storage-location erc7201:agent.storage.AgentMarket
    struct AgentMarketStorage {
        address admin;
        uint256 feeRate;
        uint256 mintFee;
        uint256 discountMintFee;
        address agentNFT;
        mapping(address => uint256) feeBalances;
        mapping(address => uint256) balances;
        mapping(uint256 => bool) usedOrders;
        mapping(uint256 => bool) usedOffers;
        // Partner fee distribution
        mapping(address => uint256) partnerFeeRates; // partner address => fee share rate (in basis points, max 10000)
        mapping(address => mapping(address => uint256)) partnerFeeBalances; // partner => currency => balance
        // Supported NFT contracts whitelist
        mapping(address => bool) supportedNFTs; // NFT contract address => supported status
    }

    // keccak256(abi.encode(uint256(keccak256("agent.storage.AgentMarket")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AGENT_MARKET_STORAGE_LOCATION =
        0xdf1beedbd3d3bce86b126f6986f1edd5f2fcd885f76d774cda1ccb33ea72b400;

    function _getMarketStorage() private pure returns (AgentMarketStorage storage $) {
        assembly {
            $.slot := AGENT_MARKET_STORAGE_LOCATION
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _agentNFT,
        uint256 _initialFeeRate,
        address _admin,
        uint256 _initialMintFee,
        uint256 _initialDiscountMintFee
    ) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        require(_admin != address(0), "Invalid admin address");
        require(_agentNFT != address(0), "Invalid AgentNFT address");
        require(_initialFeeRate <= MAX_FEE_RATE, "Fee rate too high");

        AgentMarketStorage storage $ = _getMarketStorage();
        $.admin = _admin;
        $.agentNFT = _agentNFT;
        $.feeRate = _initialFeeRate;
        $.mintFee = _initialMintFee;
        $.discountMintFee = _initialDiscountMintFee;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(MINTER_ROLE, _admin);
    }

    function admin() external view override returns (address) {
        return _getMarketStorage().admin;
    }

    function setAdmin(address newAdmin) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newAdmin != address(0), "Invalid admin address");
        address oldAdmin = _getMarketStorage().admin;

        if (oldAdmin != newAdmin) {
            _getMarketStorage().admin = newAdmin;

            _grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
            _grantRole(ADMIN_ROLE, newAdmin);

            _revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
            _revokeRole(ADMIN_ROLE, oldAdmin);
            emit AdminChanged(oldAdmin, newAdmin);
        }
    }

    function setFeeRate(uint256 newFeeRate) external override onlyRole(ADMIN_ROLE) {
        require(newFeeRate <= MAX_FEE_RATE, "Fee rate too high");
        uint256 oldFeeRate = _getMarketStorage().feeRate;
        _getMarketStorage().feeRate = newFeeRate;
        emit FeeRateUpdated(oldFeeRate, newFeeRate);
    }

    event AgentNFTUpdated(address oldAgentNFT, address newAgentNFT);
    event PartnerFeeRateUpdated(address indexed partner, uint256 oldRate, uint256 newRate);
    event PartnerFeesWithdrawn(address indexed partner, address currency, uint256 amount);
    event NFTSupportAdded(address indexed nftContract);
    event NFTSupportRemoved(address indexed nftContract);

    function setAgentNFT(address newAgentNFT) external onlyRole(ADMIN_ROLE) {
        require(newAgentNFT != address(0), "Invalid AgentNFT address");
        address oldAgentNFT = _getMarketStorage().agentNFT;
        _getMarketStorage().agentNFT = newAgentNFT;
        emit AgentNFTUpdated(oldAgentNFT, newAgentNFT);
    }

    /// @notice Add an external NFT contract to the whitelist
    /// @param nftContract The NFT contract address to support
    function addSupportedNFT(address nftContract) external onlyRole(ADMIN_ROLE) {
        require(nftContract != address(0), "Invalid NFT contract address");
        AgentMarketStorage storage $ = _getMarketStorage();
        require(!$.supportedNFTs[nftContract], "NFT already supported");
        $.supportedNFTs[nftContract] = true;
        emit NFTSupportAdded(nftContract);
    }

    /// @notice Remove an external NFT contract from the whitelist
    /// @param nftContract The NFT contract address to remove
    function removeSupportedNFT(address nftContract) external onlyRole(ADMIN_ROLE) {
        require(nftContract != address(0), "Invalid NFT contract address");
        AgentMarketStorage storage $ = _getMarketStorage();
        require(nftContract != $.agentNFT, "Cannot remove internal agentNFT");
        require($.supportedNFTs[nftContract], "NFT not supported");
        $.supportedNFTs[nftContract] = false;
        emit NFTSupportRemoved(nftContract);
    }

    /// @notice Check if an NFT contract is supported
    /// @param nftContract The NFT contract address to check
    /// @return True if supported (either internal agentNFT or whitelisted)
    function isSupportedNFT(address nftContract) external view returns (bool) {
        AgentMarketStorage storage $ = _getMarketStorage();
        // Internal agentNFT is always supported
        if (nftContract == $.agentNFT) {
            return true;
        }
        // Check whitelist for external contracts
        return $.supportedNFTs[nftContract];
    }

    function withdrawFees(address currency) external override onlyRole(ADMIN_ROLE) {
        AgentMarketStorage storage $ = _getMarketStorage();
        uint256 amount = $.feeBalances[currency];
        require(amount > 0, "No fees to withdraw");

        // Update state before external calls (CEI pattern)
        $.feeBalances[currency] = 0;

        if (currency == address(0)) {
            // withdraw 0G
            _safeTransferNative($.admin, amount);
        } else {
            // withdraw ERC20
            IERC20(currency).safeTransfer($.admin, amount);
        }

        emit FeesWithdrawn($.admin, currency, amount);
    }

    /// @notice Set the partner's share of transaction fees (in basis points, 10000 = 100%)
    /// @dev The partner receives this percentage of the TOTAL TRANSACTION FEE, not the transaction amount
    /// @dev Example: feeRate=250 (2.5%), partnerFeeRate=4000 (40%)
    ///      Transaction 100 -> Fee 2.5 -> Partner gets 1.0, Platform gets 1.5
    /// @param partner The partner address (creator/collaborator)
    /// @param feeShareRate The partner's share of fees (0-10000, where 10000 = 100% of fees go to partner)
    function setPartnerFeeRate(address partner, uint256 feeShareRate) external onlyRole(ADMIN_ROLE) {
        require(partner != address(0), "Invalid partner address");
        require(feeShareRate <= 10000, "Fee share rate too high");

        AgentMarketStorage storage $ = _getMarketStorage();
        uint256 oldRate = $.partnerFeeRates[partner];
        $.partnerFeeRates[partner] = feeShareRate;

        emit PartnerFeeRateUpdated(partner, oldRate, feeShareRate);
    }

    /// @notice Get the partner's fee share rate
    /// @param partner The partner address
    /// @return The fee share rate in basis points (of the total transaction fee)
    function getPartnerFeeRate(address partner) external view returns (uint256) {
        return _getMarketStorage().partnerFeeRates[partner];
    }

    /// @notice Get the partner's accumulated fee balance for a specific currency
    /// @param partner The partner address
    /// @param currency The currency address (address(0) for native token)
    /// @return The partner's fee balance
    function getPartnerFeeBalance(address partner, address currency) external view returns (uint256) {
        return _getMarketStorage().partnerFeeBalances[partner][currency];
    }

    /// @notice Withdraw partner fees
    /// @dev Partners can withdraw their own fees
    /// @param currency The currency to withdraw (address(0) for native token)
    function withdrawPartnerFees(address currency) external nonReentrant whenNotPaused {
        AgentMarketStorage storage $ = _getMarketStorage();
        uint256 amount = $.partnerFeeBalances[msg.sender][currency];
        require(amount > 0, "No fees to withdraw");

        // Update state before external calls (CEI pattern)
        $.partnerFeeBalances[msg.sender][currency] = 0;

        if (currency == address(0)) {
            // withdraw native token
            _safeTransferNative(msg.sender, amount);
        } else {
            // withdraw ERC20
            IERC20(currency).safeTransfer(msg.sender, amount);
        }

        emit PartnerFeesWithdrawn(msg.sender, currency, amount);
    }

    // core transaction function
    function fulfillOrder(
        Order calldata order,
        Offer calldata offer,
        TransferValidityProof[] calldata proofs
    ) external payable override nonReentrant whenNotPaused {
        // Prevent ETH from being stuck in zero-price orders
        if (offer.offerPrice == 0) {
            require(msg.value == 0, "ETH not accepted for free orders");
        }
        // 1. resolve and validate NFT contract
        address nftContract = _resolveAndValidateNFT(order.nftContract);
        require(nftContract == _resolveAndValidateNFT(offer.nftContract), "NFT contract mismatch");

        // 2. verify order and offer:
        // 2.1 verify signature
        // 2.2 verify expiration
        // 2.3 verify nonce is not used
        // 2.4 verify NFT owner is seller
        // 2.5 verify offerPrice >= expectedPrice
        address seller = _validateOrder(order, nftContract);
        address buyer = _validateOffer(offer, order);

        AgentMarketStorage storage $ = _getMarketStorage();

        // 3. transfer iNFT
        if (offer.needProof) {
            AgentNFT(nftContract).iTransferFrom(seller, buyer, order.tokenId, proofs);
        } else {
            // Standard transferFrom (IERC721)
            IERC721(nftContract).safeTransferFrom(seller, buyer, order.tokenId);
        }

        // 4. transfer erc20 token or 0G
        if (offer.offerPrice > 0) {
            _handlePayment(offer.offerPrice, order.currency, buyer, seller, order.tokenId, nftContract);
        }

        // 5. mark order and offer as used
        $.usedOrders[uint256(order.nonce)] = true;
        $.usedOffers[uint256(offer.nonce)] = true;

        emit OrderFulfilled(seller, buyer, order.tokenId, offer.offerPrice, order.currency);
    }

    function deposit(address account) external payable {
        require(msg.value > 0, "Must send ETH");
        require(account != address(0), "Invalid address");
        require(!paused(), "Contract is paused");
        AgentMarketStorage storage $ = _getMarketStorage();
        $.balances[account] += msg.value;
        emit Deposit(account, $.balances[account]);
    }

    function withdraw(address account, uint256 amount) external {
        AgentMarketStorage storage $ = _getMarketStorage();
        require(msg.sender == account || msg.sender == $.admin, "Only the account or admin can withdraw");
        require($.balances[account] >= amount, "Insufficient balance");
        require(account != address(0), "Invalid address");
        require(!paused(), "Contract is paused");
        $.balances[account] -= amount;
        _safeTransferNative(account, amount);
        emit Withdraw(account, amount);
    }

    function getBalance(address account) external view returns (uint256) {
        return _getMarketStorage().balances[account];
    }

    /// @notice Resolve and validate NFT contract address
    /// @param nftContract The NFT contract address (address(0) means default agentNFT)
    /// @return The resolved NFT contract address
    function _resolveAndValidateNFT(address nftContract) internal view returns (address) {
        AgentMarketStorage storage $ = _getMarketStorage();

        // address(0) or agentNFT -> return agentNFT (internal contract, always allowed)
        if (nftContract == address(0) || nftContract == $.agentNFT) {
            return $.agentNFT;
        }

        // External contracts: check whitelist
        require($.supportedNFTs[nftContract], "NFT contract not supported");
        return nftContract;
    }

    function _validateOrder(Order calldata order, address nftContract) internal view returns (address) {
        // 1.1 verify expiration
        require(block.timestamp <= order.expireTime, "Order expired");
        // 1.2 verify price
        require(order.expectedPrice >= 0, "Invalid price");
        // 1.3 verify order nonce is not used
        address seller = _verifyOrderSignature(order);
        AgentMarketStorage storage $ = _getMarketStorage();
        require(!$.usedOrders[uint256(order.nonce)], "Order already used");
        // 1.4 verify NFT owner is seller
        address tokenOwner = IERC721(nftContract).ownerOf(order.tokenId);
        require(tokenOwner == seller, "NFT owner mismatch");

        return seller;
    }

    function _validateOffer(Offer calldata offer, Order calldata order) internal view returns (address) {
        require(block.timestamp <= offer.expireTime, "Offer expired");
        require(offer.offerPrice >= order.expectedPrice, "Price too low");
        require(offer.tokenId == order.tokenId, "TokenId mismatch");

        address buyer = _verifyOfferSignature(offer);
        AgentMarketStorage storage $ = _getMarketStorage();
        require(!$.usedOffers[uint256(offer.nonce)], "Offer already used");

        if (order.receiver != address(0)) {
            require(buyer == order.receiver, "Receiver mismatch");
        }

        return buyer;
    }

    function _verifyOrderSignature(Order calldata order) internal view returns (address) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Order(uint256 tokenId,uint256 expectedPrice,address currency,uint256 expireTime,bytes32 nonce,address receiver,address nftContract,uint256 chainId,address verifyingContract)"
                ),
                order.tokenId,
                order.expectedPrice,
                order.currency,
                order.expireTime,
                order.nonce,
                order.receiver,
                order.nftContract,
                block.chainid,
                address(this)
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));

        return digest.recover(order.signature);
    }

    function _verifyOfferSignature(Offer calldata offer) internal view returns (address) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "Offer(uint256 tokenId,uint256 offeredPrice,uint256 expireTime,bool needProof,bytes32 nonce,address nftContract,uint256 chainId,address verifyingContract)"
                ),
                offer.tokenId,
                offer.offerPrice,
                offer.expireTime,
                offer.needProof,
                offer.nonce,
                offer.nftContract,
                block.chainid,
                address(this)
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));

        return digest.recover(offer.signature);
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes("AgentMarket")),
                    keccak256(bytes(VERSION)),
                    block.chainid,
                    address(this)
                )
            );
    }

    /// @notice Safely get the creator of a token from NFT contract
    /// @param nftContract The NFT contract address
    /// @param tokenId The token ID
    /// @return The creator address (or address(0) if not supported)
    function _getCreator(address nftContract, uint256 tokenId) internal view returns (address) {
        // Try to call creatorOf() if the contract supports it
        try AgentNFT(nftContract).creatorOf(tokenId) returns (address creator) {
            return creator;
        } catch {
            // If creatorOf() is not supported or reverts, return address(0)
            return address(0);
        }
    }

    function _handlePayment(
        uint256 offerPrice,
        address currency,
        address buyer,
        address seller,
        uint256 tokenId,
        address nftContract
    ) internal {
        AgentMarketStorage storage $ = _getMarketStorage();
        uint256 totalAmount = offerPrice;
        uint256 totalFee = (totalAmount * $.feeRate) / 10000;
        uint256 sellerAmount = totalAmount - totalFee;

        // Check if this NFT has a creator/partner for fee distribution
        address creator = _getCreator(nftContract, tokenId);
        uint256 partnerFee = 0;
        uint256 platformFee = totalFee;

        if (creator != address(0)) {
            uint256 partnerFeeRate = $.partnerFeeRates[creator];
            if (partnerFeeRate > 0) {
                // Split the fee between partner and platform
                partnerFee = (totalFee * partnerFeeRate) / 10000;
                platformFee = totalFee - partnerFee;
            }
        }

        // native token
        if (currency == address(0)) {
            if (msg.value > 0) {
                // Payment method 1: Direct payment via msg.value (for regular users)
                require(msg.value >= totalAmount, "Insufficient payment");
                $.feeBalances[currency] += platformFee;
                if (partnerFee > 0) {
                    $.partnerFeeBalances[creator][currency] += partnerFee;
                }
                _safeTransferNative(seller, sellerAmount);
                // Refund excess payment
                _refundExcess(totalAmount);
            } else {
                // Payment method 2: Balance payment via deposit system (for intermediaries)
                require($.balances[buyer] >= totalAmount, "Insufficient balance");
                $.balances[buyer] -= totalAmount;
                $.feeBalances[currency] += platformFee;
                if (partnerFee > 0) {
                    $.partnerFeeBalances[creator][currency] += partnerFee;
                }
                _safeTransferNative(seller, sellerAmount);
            }
        } else {
            // ERC20 token
            require(msg.value == 0, "ETH not accepted for ERC20 payments");
            IERC20 token = IERC20(currency);
            token.safeTransferFrom(buyer, seller, sellerAmount);
            token.safeTransferFrom(buyer, address(this), totalFee);
            $.feeBalances[currency] += platformFee;
            if (partnerFee > 0) {
                $.partnerFeeBalances[creator][currency] += partnerFee;
            }
        }
    }

    function getFeeRate() external view override returns (uint256) {
        return _getMarketStorage().feeRate;
    }

    function getFeeBalance(address currency) external view override returns (uint256) {
        return _getMarketStorage().feeBalances[currency];
    }

    function _safeTransferNative(address to, uint256 amount) internal {
        require(to != address(0), "Invalid recipient");
        require(amount > 0, "Invalid amount");

        (bool success, ) = payable(to).call{value: amount}("");
        require(success, "Native token transfer failed");
    }

    /// @notice Internal helper to refund excess payment
    /// @param requiredAmount The required payment amount
    function _refundExcess(uint256 requiredAmount) internal {
        if (msg.value > requiredAmount) {
            uint256 excess = msg.value - requiredAmount;
            (bool success, ) = payable(msg.sender).call{value: excess}("");
            require(success, "Refund failed");
        }
    }

    event MintFeeUpdated(uint256 mintFee);

    function setMintFee(uint256 newMintFee) external onlyRole(OPERATOR_ROLE) {
        _getMarketStorage().mintFee = newMintFee;
        emit MintFeeUpdated(_getMarketStorage().mintFee);
    }

    event DiscountMintFeeUpdated(uint256 discountMintFee);

    function setDiscountMintFee(uint256 newDiscountMintFee) external onlyRole(OPERATOR_ROLE) {
        _getMarketStorage().discountMintFee = newDiscountMintFee;
        emit DiscountMintFeeUpdated(_getMarketStorage().discountMintFee);
    }

    function getMintFee() external view returns (uint256) {
        return _getMarketStorage().mintFee;
    }

    function getDiscountMintFee() external view returns (uint256) {
        return _getMarketStorage().discountMintFee;
    }

    event PaidMinted(uint256 indexed tokenId, address indexed from, address indexed to, uint256 mintFee);

    function paidMint(
        IntelligentData[] calldata iDatas,
        address to,
        bool isDiscount,
        bytes[] memory sealedKeys
    ) external onlyRole(MINTER_ROLE) {
        AgentMarketStorage storage $ = _getMarketStorage();
        uint256 requiredFee = isDiscount ? $.discountMintFee : $.mintFee;
        require($.balances[to] >= requiredFee, "Insufficient balance for mint fee");
        require(to != address(0), "Invalid recipient");
        require(!paused(), "Contract is paused");
        $.balances[to] -= requiredFee;
        $.feeBalances[address(0)] += requiredFee;
        uint256 tokenId = AgentNFT($.agentNFT).mintWithRole(iDatas, to, sealedKeys);
        emit PaidMinted(tokenId, msg.sender, to, requiredFee);
    }

    function batchPaidMint(
        IntelligentData[][] calldata iDatasArray,
        address[] calldata tos,
        bool[] calldata isDiscounts,
        bytes[][] memory sealedKeysArray
    ) external onlyRole(MINTER_ROLE) {
        require(iDatasArray.length == tos.length, "Length mismatch: iDatas and tos");
        require(iDatasArray.length == isDiscounts.length, "Length mismatch: iDatas and isDiscounts");
        require(iDatasArray.length == sealedKeysArray.length, "Length mismatch: iDatas and sealedKeys");
        require(iDatasArray.length > 0, "Empty arrays");
        require(!paused(), "Contract is paused");

        AgentMarketStorage storage $ = _getMarketStorage();

        for (uint256 i = 0; i < tos.length; i++) {
            uint256 requiredFee = isDiscounts[i] ? $.discountMintFee : $.mintFee;
            require($.balances[tos[i]] >= requiredFee, "Insufficient balance for mint fee");
            require(tos[i] != address(0), "Invalid recipient");

            $.balances[tos[i]] -= requiredFee;
            $.feeBalances[address(0)] += requiredFee;
            uint256 tokenId = AgentNFT($.agentNFT).mintWithRole(iDatasArray[i], tos[i], sealedKeysArray[i]);
            emit PaidMinted(tokenId, msg.sender, tos[i], requiredFee);
        }
    }

    function paidMint(address to, string memory uri, address creator, bool isDiscount) external onlyRole(MINTER_ROLE) {
        AgentMarketStorage storage $ = _getMarketStorage();
        uint256 requiredFee = isDiscount ? $.discountMintFee : $.mintFee;
        require($.balances[to] >= requiredFee, "Insufficient balance for mint fee");
        require(to != address(0), "Invalid recipient");
        require(!paused(), "Contract is paused");
        $.balances[to] -= requiredFee;
        $.feeBalances[address(0)] += requiredFee;
        uint256 tokenId = AgentNFT($.agentNFT).mintWithRole(to, uri, creator);
        emit PaidMinted(tokenId, creator, to, requiredFee);
    }

    function paidMint(
        IntelligentData[] calldata iDatas,
        address to,
        address creator,
        bool isDiscount,
        bytes[] memory sealedKeys
    ) external onlyRole(MINTER_ROLE) {
        AgentMarketStorage storage $ = _getMarketStorage();
        uint256 requiredFee = isDiscount ? $.discountMintFee : $.mintFee;
        require($.balances[to] >= requiredFee, "Insufficient balance for mint fee");
        require(to != address(0), "Invalid recipient");
        require(!paused(), "Contract is paused");
        $.balances[to] -= requiredFee;
        $.feeBalances[address(0)] += requiredFee;
        uint256 tokenId = AgentNFT($.agentNFT).mintWithRole(iDatas, to, creator, sealedKeys);
        emit PaidMinted(tokenId, creator, to, requiredFee);
    }

    function pause() external override onlyRole(OPERATOR_ROLE) {
        _pause();
        emit ContractPaused(msg.sender);
    }

    function unpause() external override onlyRole(OPERATOR_ROLE) {
        _unpause();
        emit ContractUnpaused(msg.sender);
    }

    function isPaused() external view override returns (bool) {
        return paused();
    }
}
