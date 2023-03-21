// SPDX-License-Identifier:
// Sources flattened with hardhat v2.8.0 https://hardhat.org

// File contracts/shared/interfaces/IAdminProjectRouter.sol

pragma solidity >=0.7.0;

interface IAdminProjectRouter {
    function isSuperAdmin(
        address _addr,
        string calldata _project
    ) external view returns (bool);

    function isAdmin(
        address _addr,
        string calldata _project
    ) external view returns (bool);
}

// File contracts/shared/abstracts/Authorization.sol

pragma solidity >=0.7.0;

abstract contract Authorization {
    IAdminProjectRouter public adminProjectRouter;
    string public constant PROJECT = "bitkub-oracle";

    event AdminProjectRouterSet(
        address indexed oldAdmin,
        address indexed newAdmin,
        address indexed caller
    );

    modifier onlySuperAdmin() {
        require(
            adminProjectRouter.isSuperAdmin(msg.sender, PROJECT),
            "Authorization: restricted only super admin"
        );
        _;
    }

    modifier onlyAdmin() {
        require(
            adminProjectRouter.isAdmin(msg.sender, PROJECT),
            "Authorization: restricted only admin"
        );
        _;
    }

    modifier onlySuperAdminOrAdmin() {
        require(
            adminProjectRouter.isSuperAdmin(msg.sender, PROJECT) ||
                adminProjectRouter.isAdmin(msg.sender, PROJECT),
            "Authorization: restricted only super admin or admin"
        );
        _;
    }

    function setAdminProjectRouter(
        address _adminProjectRouter
    ) public virtual onlySuperAdmin {
        require(
            _adminProjectRouter != address(0),
            "Authorization: new admin project router is the zero address"
        );
        emit AdminProjectRouterSet(
            address(adminProjectRouter),
            _adminProjectRouter,
            msg.sender
        );
        adminProjectRouter = IAdminProjectRouter(_adminProjectRouter);
    }
}

// File contracts/shared/abstracts/Committee.sol

pragma solidity >=0.7.0;

abstract contract Committee {
    address public committee;

    event CommitteeSet(
        address indexed oldCommittee,
        address indexed newCommittee,
        address indexed caller
    );

    modifier onlyCommittee() {
        require(
            msg.sender == committee,
            "Committee: restricted only committee"
        );
        _;
    }

    function setCommittee(address _committee) public virtual onlyCommittee {
        emit CommitteeSet(committee, _committee, msg.sender);
        committee = _committee;
    }
}

// File contracts/shared/abstracts/CommitteeControlledAuthorization.sol

pragma solidity >=0.7.0;

abstract contract CommitteeControlledAuthorization is Authorization, Committee {
    function setAdminProjectRouter(
        address _adminProjectRouter
    ) public virtual override onlyCommittee {
        require(
            _adminProjectRouter != address(0),
            "Authorization: new admin project router is the zero address"
        );
        emit AdminProjectRouterSet(
            address(adminProjectRouter),
            _adminProjectRouter,
            msg.sender
        );
        adminProjectRouter = IAdminProjectRouter(_adminProjectRouter);
    }
}

// File contracts/shared/interfaces/IKYCBitkubChain.sol

pragma solidity >=0.6.0 <0.9.0;

interface IKYCBitkubChain {
    function kycsLevel(address _addr) external view returns (uint256);
}

// File contracts/shared/abstracts/KYCHandler.sol

pragma solidity 0.8.0;

abstract contract KYCHandler {
    IKYCBitkubChain public kyc;

    uint256 public acceptedKYCLevel;
    bool public isActivatedOnlyKYCAddress;

    function _activateOnlyKYCAddress() internal virtual {
        isActivatedOnlyKYCAddress = true;
    }

    function _setKYC(address _kyc) internal virtual {
        kyc = IKYCBitkubChain(_kyc);
    }

    function _setAcceptedKYCLevel(uint256 _kycLevel) internal virtual {
        acceptedKYCLevel = _kycLevel;
    }

    function setKYC(address _kyc) public virtual;

    function setAcceptedKYCLevel(uint256 _kycLevel) public virtual;
}

// File contracts/shared/abstracts/Context.sol

pragma solidity ^0.8.0;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// File contracts/shared/abstracts/Pausable.sol

pragma solidity ^0.8.0;

abstract contract Pausable is Context {
    event Paused(address account);

    event Unpaused(address account);

    bool private _paused;

    constructor() {
        _paused = false;
    }

    function paused() public view virtual returns (bool) {
        return _paused;
    }

    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(paused(), "Pausable: not paused");
        _;
    }

    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}

// File contracts/shared/abstracts/ReentrancyGuard.sol

// OpenZeppelin Contracts v4.4.1 (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}

// File contracts/shared/structs/DataFeedSubscriptionStructs.sol

pragma solidity ^0.8.0;

// details of a package
struct PackageDetails {
    string name; // name of this package
    uint256 price; // price for initial subscription and renewal (unit is wei)
    uint64 subscriptionPeriod; // the amount of seconds a user will get if they subscribe (unit is second()
    uint32 quotaLeft; // the amount of times this package can be subscribed
    uint16 renewalCount; // the amount of times a user can renew their subscription after initial subscription
    uint16 readerCount; // the amount of contracts a user can allow to read the data feeds
    uint16 dataFeedType; // the type of data feeds this package allows to read
    bool disabled; // true if this package is disabled. if disabled, new users can not subscribe this package anymore
}

// details of a subscription part 1.
// this part will be used when renewing a subscription
// or when allowing contracts to read the data feeds.
struct SubscriptionRenewalAndMiscDetails {
    string name; // subscription name
    uint256 price; // price for renewal of this subscription (unit is wei)
    uint64 subscriptionPeriod; // the amount of seconds a user will get if they renew (unit is second()
    uint16 renewalCount; // the amount of times a user can renew their subscription after initial subscription, will be decreased by one if renew
}

// details of a subscription part 2
// this part will be used when PermissionManager contract
// checks whether a tokenID has to right to read the data feeds
// this struct uses 1 word
struct SubscriptionPermissionDetails {
    uint128 endDate; // the time in unixtimestamp this subscription last has the right to read the data feeds (unit is second)
    uint16 readerCount; // the amount of contracts a user can allow to read the data feeds
    uint16 dataFeedType; // the type of data feeds this subscription allows to read
    bool disabled; // true if this subscription is disabled. if disabled, this subscription no longer has the right to read the data feeds
}

// SubscriptionRenewalAndMiscDetails U SubscriptionPermissionDetails
struct SubscriptionDetails {
    string name;
    uint256 price;
    uint128 endDate;
    uint64 subscriptionPeriod;
    uint16 renewalCount;
    uint16 readerCount;
    uint16 dataFeedType;
    bool disabled;
}

// File contracts/shared/interfaces/BitkubDataFeedInterface/DataFeedSubscriptionInterface.sol

pragma solidity ^0.8.0;

interface DataFeedSubscriptionInterface {
    // the total number of packages
    function packageCount() external view returns (uint256);

    // returns all packages ([package with ID 1, package with ID 2, package with ID 3, ...])
    function packageDetails() external view returns (PackageDetails[] memory);

    function packageDetails(
        uint256 _packageID
    ) external view returns (PackageDetails memory);

    // returns packages by input IDs
    // packageID must be more than 0 (1, 2, 3, ...)
    function packageDetailsByIDs(
        uint256[] calldata _packageIDs
    ) external view returns (PackageDetails[] memory);

    ////////////////////////////////////////////////////////////////////////////////////////

    function subscriptionRenewalAndMiscDetails(
        uint256 _tokenID
    ) external view returns (SubscriptionRenewalAndMiscDetails memory);

    function subscriptionRenewalAndMiscDetailsByIDs(
        uint256[] memory _tokenIDs
    ) external view returns (SubscriptionRenewalAndMiscDetails[] memory);

    function subscriptionPermissionDetails(
        uint256 _tokenID
    ) external view returns (SubscriptionPermissionDetails memory);

    function subscriptionPermissionDetailsByIDs(
        uint256[] memory _tokenIDs
    ) external view returns (SubscriptionPermissionDetails[] memory);

    function subscriptionDetails(
        uint256 _tokenID
    ) external view returns (SubscriptionDetails memory);

    function subscriptionDetailsByIDs(
        uint256[] memory _tokenIs
    ) external view returns (SubscriptionDetails[] memory);

    ////////////////////////////////////////////////////////////////////////////////////////

    event NewSubscription(
        uint256 indexed packageID,
        uint256 indexed tokenID,
        address indexed caller,
        PackageDetails packageDetails
    );

    // metamask
    function subscribe(uint256 _packageID) external;

    // bitkubNext only
    function subscribe(uint256 _packageID, address _bitkubNext) external;

    event SubscriptionRenewed(
        uint256 indexed tokenID,
        address indexed caller,
        SubscriptionDetails oldSubscriptionDetails,
        SubscriptionDetails newSubscriptionDetails
    );

    // metamask
    function renew(uint256 _tokenID) external;

    // bitkubNext only
    function renew(uint256 _tokenID, address _bitkubNext) external;

    ////////////////////////////////////////////////////////////////////////////////////////

    function isSubscribed(
        uint256 _tokenID,
        address _dataFeedAddr
    ) external view returns (bool);

    // returns SubscriptionPermissionDetails.readerCount
    function getMaximumReaderCount(
        uint256 _tokenID
    ) external view returns (uint256);
}

// File contracts/shared/interfaces/BitkubDataFeedInterface/DataFeedSubscriptionAdminInterface.sol

pragma solidity ^0.8.0;

interface DataFeedSubscriptionAdminInterface {
    event PackageAdded(
        uint256 indexed packageID,
        address indexed caller,
        PackageDetails packageDetails
    );

    event PackageUpdated(
        uint256 indexed packageID,
        address indexed caller,
        PackageDetails oldPackageDetails,
        PackageDetails newPackageDetails
    );

    event SubscriptionEdited(
        uint256 indexed tokenID,
        address indexed caller,
        SubscriptionDetails oldSubscriptionDetails,
        SubscriptionDetails newSubscriptionDetails
    );

    // super admin
    function addPackage(PackageDetails calldata _packageDetails) external;

    // super admin
    function updatePackage(
        uint256 _packageID,
        PackageDetails calldata _packageDetails
    ) external;

    // super admin
    function disablePackage(uint256 _packageID, bool _disabled) external;

    // committee
    function editSubscription(
        uint256 _tokenID,
        SubscriptionDetails calldata _subscriptionDetails
    ) external;

    // committee
    function disableSubscription(uint256 _tokenID, bool _disabled) external;
}

// File contracts/shared/interfaces/IKAP20.sol

pragma solidity >=0.6.0 <0.9.0;

interface IKAP20 {
    function totalSupply() external view returns (uint256);

    function decimals() external view returns (uint8);

    function symbol() external view returns (string memory);

    function name() external view returns (string memory);

    function balanceOf(address account) external view returns (uint256);

    function transfer(
        address recipient,
        uint256 amount
    ) external returns (bool);

    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    function adminTransfer(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}

// File contracts/shared/interfaces/IAdminKAP20Router.sol

pragma solidity >=0.6.0 <0.9.0;

interface IAdminKAP20Router {
    function externalTransferKKUB(
        address _feeToken,
        address _from,
        address _to,
        uint256 _value,
        uint256 _feeValue
    ) external returns (bool);
}

// File contracts/shared/interfaces/IKAP165.sol

pragma solidity >=0.6.0 <0.9.0;

interface IKAP165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// File contracts/shared/interfaces/IKAP721/IKAP721.sol

pragma solidity >=0.6.0 <0.9.0;

interface IKAP721 is IKAP165 {
    event Transfer(
        address indexed from,
        address indexed to,
        uint256 indexed tokenId
    );
    event Approval(
        address indexed owner,
        address indexed approved,
        uint256 indexed tokenId
    );
    event ApprovalForAll(
        address indexed owner,
        address indexed operator,
        bool approved
    );

    function balanceOf(address owner) external view returns (uint256 balance);

    function ownerOf(uint256 tokenId) external view returns (address owner);

    function tokenOfOwnerAll(
        address _owner
    ) external view returns (uint256[] memory);

    function tokenOfOwnerByPage(
        address _owner,
        uint256 _page,
        uint256 _limit
    ) external view returns (uint256[] memory);

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    function transferFrom(address from, address to, uint256 tokenId) external;

    function adminTransfer(
        address _from,
        address _to,
        uint256 _tokenId
    ) external;

    function internalTransfer(
        address sender,
        address recipient,
        uint256 tokenId
    ) external returns (bool);

    function externalTransfer(
        address sender,
        address recipient,
        uint256 tokenId
    ) external returns (bool);

    function approve(address to, uint256 tokenId) external;

    function adminApprove(address to, uint256 tokenId) external;

    function getApproved(
        uint256 tokenId
    ) external view returns (address operator);

    function setApprovalForAll(address operator, bool _approved) external;

    function adminSetApprovalForAll(
        address owner,
        address operator,
        bool approved
    ) external;

    function isApprovedForAll(
        address owner,
        address operator
    ) external view returns (bool);

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}

// File contracts/shared/interfaces/IKAP721/IKAP721Metadata.sol

pragma solidity >=0.6.0 <0.9.0;

interface IKAP721Metadata {
    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function tokenURI(uint256 tokenId) external view returns (string memory);
}

// File contracts/shared/interfaces/IKAP721/IKAP721Enumerable.sol

pragma solidity >=0.6.0 <0.9.0;

interface IKAP721Enumerable {
    function totalSupply() external view returns (uint256);

    function tokenOfOwnerByIndex(
        address owner,
        uint256 index
    ) external view returns (uint256 tokenId);

    function tokenByIndex(uint256 index) external view returns (uint256);
}

// File contracts/shared/interfaces/BitkubDataFeedInterface/BitkubDataFeedNFTInterface.sol

pragma solidity >=0.6.0 <0.9.0;

interface BitkubDataFeedNFTInterface is
    IKAP721,
    IKAP721Metadata,
    IKAP721Enumerable
{
    event AllowedAddressAdded(
        address indexed allowedAddr,
        address indexed caller
    );
    event AllowedAddressRemoved(
        address indexed allowedAddr,
        address indexed caller
    );

    function exists(uint256 _tokenId) external view returns (bool);

    function allowedAddrLength() external view returns (uint256);

    function allowedAddr() external view returns (address[] memory);

    function allowedAddr(
        uint256 _page,
        uint256 _limit
    ) external view returns (address[] memory);

    function tokenOfOwnerByTokenInfoByPage(
        address _owner,
        address _infoAddr,
        uint256 _page,
        uint256 _limit
    ) external view returns (uint256[] memory);

    function tokenOfOwnerByTokenInfo(
        address _owner,
        address _infoAddr
    ) external view returns (uint256[] memory);

    function balanceOfByTokenInfo(
        address _owner,
        address _infoAddr
    ) external view returns (uint256);

    function getTokenInfoAddress(
        uint256 _tokenId
    ) external view returns (address);

    function addAddress(address _addr) external;

    function removeAddress(address _addr) external;

    function setTokenURI(uint256 _tokenId, string calldata _tokenURI) external;

    function setBaseURI(string calldata _baseURI) external;

    function pause() external;

    function unpause() external;

    function mint(address _to) external returns (uint256 tokenId);

    function burn(uint256 _tokenId) external;
}

// File contracts/shared/interfaces/BitkubDataFeedInterface/DataFeedTypeInterface.sol

pragma solidity ^0.8.0;

interface DataFeedTypeInterface {
    event AddressAdded(
        uint256 indexed dataFeedType,
        address indexed addedAddress,
        address indexed caller
    );

    event AddressRemoved(
        uint256 indexed dataFeedType,
        address indexed removedAddress,
        address indexed caller
    );

    function setAddresses(
        uint256 _dataFeedType,
        address[] memory _dataFeedAddrs
    ) external;

    function addAddresses(
        uint256 _dataFeedType,
        address[] memory _dataFeedAddrs
    ) external;

    function removeAddresses(
        uint256 _dataFeedType,
        address[] memory _dataFeedAddrs
    ) external;

    function setDataFeedDescription(
        uint256 _dataFeedType,
        string memory _description
    ) external;

    function inDataFeedType(
        uint256 _dataFeedType,
        address _dataFeedAddr
    ) external view returns (bool);

    function activeDataFeedTypesCount() external view returns (uint256);

    function activeDataFeedTypes()
        external
        view
        returns (uint256[] memory dataFeedTypes);

    function activeDataFeedTypesByPage(
        uint256 _page,
        uint256 _limit
    ) external view returns (uint256[] memory dataFeedTypes);

    function dataFeedTypeDescription(
        uint256 _dataFeedType
    ) external view returns (string memory);

    function addressesCountByDataFeedType(
        uint256 _dataFeedType
    ) external view returns (uint256);

    // right now _dataFeedType = 1 shoud do...
    // returns all addresses of this dataFeedType
    function addressesByDataFeedType(
        uint256 _dataFeedType
    ) external view returns (address[] memory);

    function addressesByDataFeedTypeByPage(
        uint256 _dataFeedType,
        uint256 _page,
        uint256 _limit
    ) external view returns (address[] memory);
}

// File contracts/shared/interfaces/AccessControllerInterface.sol

pragma solidity >=0.7.0;

interface AccessControllerInterface {
    function hasAccess(
        address user,
        bytes calldata data
    ) external view returns (bool);
}

// File contracts/shared/interfaces/IPermissionManager.sol

pragma solidity ^0.8.0;

interface IPermissionManager is AccessControllerInterface {
    event AddressAdded(
        uint256 indexed tokenID,
        address indexed addedAddress,
        address indexed caller
    );

    event AddressRemoved(
        uint256 indexed tokenID,
        address indexed removedAddress,
        address indexed caller
    );

    // returns the tokenID that grants the right to read the data feeds to _addr
    // tokenID 0 means no access
    function currentTokenID(
        address _addr
    ) external view returns (uint256 tokenID);

    function allowedAddressesCount(
        uint256 _tokenID
    ) external view returns (uint256);

    // returns all addresses that this tokenID grants the right to read the data feeds
    function allowedAddresses(
        uint256 _tokenID
    ) external view returns (address[] memory);

    // same as allowedAddresses(uint256 _tokenID), but with page and limit (page and limit must be more than 0)
    function allowedAddressesByPage(
        uint256 _tokenID,
        uint256 _page,
        uint256 _limit
    ) external view returns (address[] memory);

    function ownerFunctionSignatures() external view returns (bytes4[] memory);

    function ownerFunctionNames() external view returns (string[] memory);

    function setCheckOwnerSignatures(string[] memory _ownerFunctions) external;

    // revoke the right to read the data feeds of all addresses that were granted the right
    // and grant all addresses of _addrs the right to read the data feeds
    function setAddresses(uint256 _tokenID, address[] calldata _addrs) external;

    // same as function setAddresses(uint256 _tokenID, address[] calldata _addrs), but for bitkubNext
    function setAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _bitkubNext
    ) external;

    // grant all addresses of _addrs the right to read the data feeds
    function addAddresses(uint256 _tokenID, address[] calldata _addrs) external;

    // same as function addAddresses(uint256 _tokenID, address[] calldata _addrs), but for bitkubNext
    function addAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _bitkubNext
    ) external;

    // revoke the right to read the data feeds of the addresses in _addrs
    function removeAddresses(
        uint256 _tokenID,
        address[] calldata _addrs
    ) external;

    // same as removeAddresses(uint256 _tokenID, address[] calldata _addrs), but for bitkubNext
    function removeAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _bitkubNext
    ) external;
}

// File contracts/shared/libraries/EnumerableSetAddress.sol

pragma solidity >=0.6.0;

library EnumerableSetAddress {
    struct AddressSet {
        address[] _values;
        mapping(address => uint256) _indexes;
    }

    function add(
        AddressSet storage set,
        address value
    ) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    function remove(
        AddressSet storage set,
        address value
    ) internal returns (bool) {
        uint256 valueIndex = set._indexes[value];
        if (valueIndex != 0) {
            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;
            address lastvalue = set._values[lastIndex];
            set._values[toDeleteIndex] = lastvalue;
            set._indexes[lastvalue] = toDeleteIndex + 1;
            set._values.pop();
            delete set._indexes[value];
            return true;
        } else {
            return false;
        }
    }

    function contains(
        AddressSet storage set,
        address value
    ) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(AddressSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(
        AddressSet storage set,
        uint256 index
    ) internal view returns (address) {
        require(
            set._values.length > index,
            "EnumerableSet: index out of bounds"
        );
        return set._values[index];
    }

    function getAll(
        AddressSet storage set
    ) internal view returns (address[] memory) {
        return set._values;
    }

    function get(
        AddressSet storage set,
        uint256 _page,
        uint256 _limit
    ) internal view returns (address[] memory) {
        require(_page > 0 && _limit > 0);
        uint256 tempLength = _limit;
        uint256 cursor = (_page - 1) * _limit;
        uint256 _addressLength = length(set);
        if (cursor >= _addressLength) {
            return new address[](0);
        }
        if (tempLength > _addressLength - cursor) {
            tempLength = _addressLength - cursor;
        }
        address[] memory addresses = new address[](tempLength);
        for (uint256 i = 0; i < tempLength; i++) {
            addresses[i] = at(set, cursor + i);
        }
        return addresses;
    }
}

// File contracts/shared/libraries/EnumerableSetUint.sol

pragma solidity >=0.6.0;

library EnumerableSetUint {
    struct UintSet {
        uint256[] _values;
        mapping(uint256 => uint256) _indexes;
    }

    function add(UintSet storage set, uint256 value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    function remove(
        UintSet storage set,
        uint256 value
    ) internal returns (bool) {
        uint256 valueIndex = set._indexes[value];
        if (valueIndex != 0) {
            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;
            uint256 lastvalue = set._values[lastIndex];
            set._values[toDeleteIndex] = lastvalue;
            set._indexes[lastvalue] = toDeleteIndex + 1;
            set._values.pop();
            delete set._indexes[value];
            return true;
        } else {
            return false;
        }
    }

    function contains(
        UintSet storage set,
        uint256 value
    ) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(UintSet storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(
        UintSet storage set,
        uint256 index
    ) internal view returns (uint256) {
        require(
            set._values.length > index,
            "EnumerableSet: index out of bounds"
        );
        return set._values[index];
    }

    function getAll(
        UintSet storage set
    ) internal view returns (uint256[] memory) {
        return set._values;
    }

    function get(
        UintSet storage set,
        uint256 _page,
        uint256 _limit
    ) internal view returns (uint256[] memory) {
        require(_page > 0 && _limit > 0);
        uint256 tempLength = _limit;
        uint256 cursor = (_page - 1) * _limit;
        uint256 _uintLength = length(set);
        if (cursor >= _uintLength) {
            return new uint256[](0);
        }
        if (tempLength > _uintLength - cursor) {
            tempLength = _uintLength - cursor;
        }
        uint256[] memory uintList = new uint256[](tempLength);
        for (uint256 i = 0; i < tempLength; i++) {
            uintList[i] = at(set, cursor + i);
        }
        return uintList;
    }
}

// File contracts/bitkubdatafeed/subscription/DataFeedSubscription.sol

pragma solidity ^0.8.0;

contract DataFeedSubscription is
    CommitteeControlledAuthorization,
    KYCHandler,
    Pausable,
    ReentrancyGuard,
    DataFeedSubscriptionInterface,
    DataFeedSubscriptionAdminInterface
{
    using EnumerableSetAddress for EnumerableSetAddress.AddressSet;
    using EnumerableSetUint for EnumerableSetUint.UintSet;

    event TokenWithdrawn(
        address indexed token,
        address indexed to,
        uint256 amount
    );
    event KYCSet(
        address indexed oldKYC,
        address indexed newKYC,
        address indexed caller
    );
    event AcceptedKYCLevelSet(
        uint256 indexed oldAcceptedKYCLevel,
        uint256 indexed newAcceptedKYCLevel,
        address indexed caller
    );
    event AdminKAP20RouterSet(
        address indexed oldAdminKAP20Router,
        address indexed newAdminKAP20Router,
        address indexed caller
    );
    event BitkubDataFeedNFTSet(
        address indexed oldBitkubDataFeedNFT,
        address indexed newBitkubDataFeedNFT,
        address indexed caller
    );
    event DataFeedTypeSet(
        address indexed oldDataFeedType,
        address indexed newDataFeedType,
        address indexed caller
    );

    modifier checkID(uint256 _ID) {
        require(_ID != 0, "DataFeedSubscription: invalid ID");
        _;
    }

    modifier onlyNFTOwner(uint256 _tokenID, address _caller) {
        require(
            bitkubDataFeedNFT.ownerOf(_tokenID) == _caller,
            "DataFeedSubscription: restricted only owner of NFT"
        );
        _;
    }

    modifier onlyTokenOfThisInfo(uint256 _tokenID) {
        require(
            bitkubDataFeedNFT.getTokenInfoAddress(_tokenID) == address(this),
            "DataFeedSubscription: restricted only token of this info address"
        );
        _;
    }

    modifier checkBitkubNext(address _bitkubNext) {
        require(
            kyc.kycsLevel(_bitkubNext) >= acceptedKYCLevel,
            "DataFeedSubscription: only BitkubNext user"
        );
        _;
    }

    PackageDetails[] internal _packageDetails;

    mapping(uint256 => SubscriptionRenewalAndMiscDetails)
        internal _subscriptionRenewalAndMiscDetails;
    mapping(uint256 => SubscriptionPermissionDetails)
        internal _subscriptionPermissionDetails;

    IKAP20 public immutable KKUB;
    IAdminKAP20Router public adminKAP20Router;
    BitkubDataFeedNFTInterface public bitkubDataFeedNFT;
    DataFeedTypeInterface public dataFeedType;

    constructor(
        address _adminProjectRouter,
        address _committee,
        address _kyc,
        uint256 _acceptedKYCLevel,
        address _KKUB,
        address _adminKAP20Router,
        address _bitkubDataFeedNFT,
        address _dataFeedType
    ) {
        adminProjectRouter = IAdminProjectRouter(_adminProjectRouter);
        committee = _committee;

        kyc = IKYCBitkubChain(_kyc);
        acceptedKYCLevel = _acceptedKYCLevel;

        KKUB = IKAP20(_KKUB);
        adminKAP20Router = IAdminKAP20Router(_adminKAP20Router);

        bitkubDataFeedNFT = BitkubDataFeedNFTInterface(_bitkubDataFeedNFT);
        dataFeedType = DataFeedTypeInterface(_dataFeedType);
    }

    bool public initialized;

    function initialize(address _bitkubDataFeedNFT) external onlySuperAdmin {
        require(!initialized, "DataFeedSubscription: already initialized");
        initialized = true;

        bitkubDataFeedNFT = BitkubDataFeedNFTInterface(_bitkubDataFeedNFT);
    }

    ////////////////////////////////////////////////////////////////////////////////////////

    function isSubscribed(
        uint256 _tokenID,
        address _dataFeedAddr
    ) external view override checkID(_tokenID) returns (bool) {
        SubscriptionPermissionDetails
            memory localSubscriptionPermissionDetails = _subscriptionPermissionDetails[
                _tokenID
            ];
        if (
            block.timestamp <= localSubscriptionPermissionDetails.endDate && // check time
            !localSubscriptionPermissionDetails.disabled && // check disabled
            dataFeedType.inDataFeedType(
                localSubscriptionPermissionDetails.dataFeedType,
                _dataFeedAddr
            ) // check if reading the exact dataFeedType
        ) {
            return true;
        }
        return false;
    }

    // returns SubscriptionPermissionDetails.readerCount
    function getMaximumReaderCount(
        uint256 _tokenID
    )
        external
        view
        override
        checkID(_tokenID)
        onlyTokenOfThisInfo(_tokenID)
        returns (uint256)
    {
        return _subscriptionPermissionDetails[_tokenID].readerCount;
    }

    ////////////////////////////////////////////////////////////////////////////////////////

    function setKYC(address _kyc) public override onlyCommittee {
        emit KYCSet(address(kyc), _kyc, msg.sender);
        _setKYC(_kyc);
    }

    function setAcceptedKYCLevel(
        uint256 _acceptedKYCLevel
    ) public override onlyCommittee {
        emit AcceptedKYCLevelSet(
            acceptedKYCLevel,
            _acceptedKYCLevel,
            msg.sender
        );
        _setAcceptedKYCLevel(_acceptedKYCLevel);
    }

    function setAdminKAP20Router(
        address _adminKAP20Router
    ) external onlyCommittee {
        emit AdminKAP20RouterSet(
            address(adminKAP20Router),
            _adminKAP20Router,
            msg.sender
        );
        adminKAP20Router = IAdminKAP20Router(_adminKAP20Router);
    }

    function setBitkubDataFeedNFT(
        address _bitkubDataFeedNFT
    ) external onlySuperAdmin {
        emit BitkubDataFeedNFTSet(
            address(bitkubDataFeedNFT),
            _bitkubDataFeedNFT,
            msg.sender
        );
        bitkubDataFeedNFT = BitkubDataFeedNFTInterface(_bitkubDataFeedNFT);
    }

    function setDataFeedType(address _dataFeedType) external onlySuperAdmin {
        emit DataFeedTypeSet(address(dataFeedType), _dataFeedType, msg.sender);
        dataFeedType = DataFeedTypeInterface(_dataFeedType);
    }

    ////////////////////////////////////////////////////////////////////////////////////////

    function adminTokenWithdraw(
        address _token,
        address _to,
        uint256 _amount
    ) external onlySuperAdmin {
        IKAP20(_token).transfer(_to, _amount);
        emit TokenWithdrawn(_token, _to, _amount);
    }

    function pause() external onlySuperAdmin {
        _pause();
    }

    function unpause() external onlySuperAdmin {
        _unpause();
    }

    function addPackage(
        PackageDetails memory _details
    ) external override onlySuperAdmin {
        _packageDetails.push(_details);
        emit PackageAdded(_packageDetails.length, msg.sender, _details);
    }

    function _updatePackage(
        uint256 _packageID,
        PackageDetails memory _oldDetails,
        PackageDetails memory _newDetails
    ) internal {
        _packageDetails[_packageID - 1] = _newDetails;
        emit PackageUpdated(_packageID, msg.sender, _oldDetails, _newDetails);
    }

    function updatePackage(
        uint256 _packageID,
        PackageDetails memory _details
    ) external override onlySuperAdmin {
        PackageDetails memory oldPackageDetails = packageDetails(_packageID);
        _updatePackage(_packageID, oldPackageDetails, _details);
    }

    function disablePackage(
        uint256 _packageID,
        bool _disabled
    ) external override onlySuperAdmin {
        PackageDetails memory oldPackageDetails = packageDetails(_packageID);
        PackageDetails memory newPackageDetails = PackageDetails({
            name: oldPackageDetails.name,
            price: oldPackageDetails.price,
            subscriptionPeriod: oldPackageDetails.subscriptionPeriod,
            quotaLeft: oldPackageDetails.quotaLeft,
            renewalCount: oldPackageDetails.renewalCount,
            readerCount: oldPackageDetails.readerCount,
            dataFeedType: oldPackageDetails.dataFeedType,
            disabled: _disabled
        });
        _updatePackage(_packageID, oldPackageDetails, newPackageDetails);
    }

    function _editSubscription(
        uint256 _tokenID,
        SubscriptionDetails memory _oldDetails,
        SubscriptionDetails memory _newDetails
    ) internal onlyTokenOfThisInfo(_tokenID) {
        _subscriptionRenewalAndMiscDetails[
            _tokenID
        ] = SubscriptionRenewalAndMiscDetails({
            name: _newDetails.name,
            price: _newDetails.price,
            subscriptionPeriod: _newDetails.subscriptionPeriod,
            renewalCount: _newDetails.renewalCount
        });
        _subscriptionPermissionDetails[
            _tokenID
        ] = SubscriptionPermissionDetails({
            endDate: _newDetails.endDate,
            readerCount: _newDetails.readerCount,
            dataFeedType: _newDetails.dataFeedType,
            disabled: _newDetails.disabled
        });
        emit SubscriptionEdited(_tokenID, msg.sender, _oldDetails, _newDetails);
    }

    function editSubscription(
        uint256 _tokenID,
        SubscriptionDetails memory _details
    ) external override onlySuperAdmin {
        SubscriptionDetails memory oldSubscriptionDetails = subscriptionDetails(
            _tokenID
        );
        _editSubscription(_tokenID, oldSubscriptionDetails, _details);
    }

    function disableSubscription(
        uint256 _tokenID,
        bool _disabled
    ) external override onlySuperAdmin {
        SubscriptionDetails memory oldSubscriptionDetails = subscriptionDetails(
            _tokenID
        );
        SubscriptionDetails
            memory newSubscriptionDetails = SubscriptionDetails({
                name: oldSubscriptionDetails.name,
                price: oldSubscriptionDetails.price,
                endDate: oldSubscriptionDetails.endDate,
                subscriptionPeriod: oldSubscriptionDetails.subscriptionPeriod,
                renewalCount: oldSubscriptionDetails.renewalCount,
                readerCount: oldSubscriptionDetails.readerCount,
                dataFeedType: oldSubscriptionDetails.dataFeedType,
                disabled: _disabled
            });
        _editSubscription(
            _tokenID,
            oldSubscriptionDetails,
            newSubscriptionDetails
        );
    }

    ////////////////////////////////////////////////////////////////////////////////////////

    function packageCount() external view override returns (uint256) {
        return _packageDetails.length;
    }

    function packageDetails()
        external
        view
        override
        returns (PackageDetails[] memory)
    {
        return _packageDetails;
    }

    function packageDetails(
        uint256 _packageID
    ) public view override checkID(_packageID) returns (PackageDetails memory) {
        return _packageDetails[_packageID - 1];
    }

    function packageDetailsByIDs(
        uint256[] calldata _packageIDs
    ) external view override returns (PackageDetails[] memory) {
        PackageDetails[] memory results = new PackageDetails[](
            _packageIDs.length
        );
        for (uint256 i = 0; i < _packageIDs.length; i++) {
            results[i] = packageDetails(_packageIDs[i]);
        }
        return results;
    }

    ////////////////////////////////////////////////////////////////////////////////////////

    function subscriptionRenewalAndMiscDetails(
        uint256 _tokenID
    )
        public
        view
        override
        checkID(_tokenID)
        onlyTokenOfThisInfo(_tokenID)
        returns (SubscriptionRenewalAndMiscDetails memory)
    {
        return _subscriptionRenewalAndMiscDetails[_tokenID];
    }

    function subscriptionPermissionDetails(
        uint256 _tokenID
    )
        public
        view
        override
        checkID(_tokenID)
        onlyTokenOfThisInfo(_tokenID)
        returns (SubscriptionPermissionDetails memory)
    {
        return _subscriptionPermissionDetails[_tokenID];
    }

    function subscriptionDetails(
        uint256 _tokenID
    ) public view override returns (SubscriptionDetails memory) {
        SubscriptionRenewalAndMiscDetails
            memory tmp1 = subscriptionRenewalAndMiscDetails(_tokenID);
        SubscriptionPermissionDetails
            memory tmp2 = subscriptionPermissionDetails(_tokenID);
        return
            SubscriptionDetails({
                name: tmp1.name,
                price: tmp1.price,
                endDate: tmp2.endDate,
                subscriptionPeriod: tmp1.subscriptionPeriod,
                renewalCount: tmp1.renewalCount,
                readerCount: tmp2.readerCount,
                dataFeedType: tmp2.dataFeedType,
                disabled: tmp2.disabled
            });
    }

    function subscriptionRenewalAndMiscDetailsByIDs(
        uint256[] memory _tokenIDs
    )
        external
        view
        override
        returns (SubscriptionRenewalAndMiscDetails[] memory)
    {
        SubscriptionRenewalAndMiscDetails[]
            memory results = new SubscriptionRenewalAndMiscDetails[](
                _tokenIDs.length
            );
        for (uint256 i = 0; i < _tokenIDs.length; i++) {
            results[i] = subscriptionRenewalAndMiscDetails(_tokenIDs[i]);
        }
        return results;
    }

    function subscriptionPermissionDetailsByIDs(
        uint256[] memory _tokenIDs
    ) external view override returns (SubscriptionPermissionDetails[] memory) {
        SubscriptionPermissionDetails[]
            memory results = new SubscriptionPermissionDetails[](
                _tokenIDs.length
            );
        for (uint256 i = 0; i < _tokenIDs.length; i++) {
            results[i] = subscriptionPermissionDetails(_tokenIDs[i]);
        }
        return results;
    }

    function subscriptionDetailsByIDs(
        uint256[] memory _tokenIDs
    ) external view override returns (SubscriptionDetails[] memory) {
        SubscriptionDetails[] memory results = new SubscriptionDetails[](
            _tokenIDs.length
        );
        for (uint256 i = 0; i < _tokenIDs.length; i++) {
            results[i] = subscriptionDetails(_tokenIDs[i]);
        }
        return results;
    }

    ////////////////////////////////////////////////////////////////////////////////////////

    function _subscribe(
        uint256 _packageID,
        PackageDetails memory _details,
        address _caller
    ) internal {
        require(!_details.disabled, "DataFeedSubscription: disabled");
        require(
            _details.quotaLeft > 0,
            "DataFeedSubscription: no more subscription allowed"
        );

        uint256 tokenID = bitkubDataFeedNFT.mint(_caller);

        _subscriptionRenewalAndMiscDetails[
            tokenID
        ] = SubscriptionRenewalAndMiscDetails({
            name: _details.name,
            price: _details.price,
            subscriptionPeriod: _details.subscriptionPeriod,
            renewalCount: _details.renewalCount
        });
        _subscriptionPermissionDetails[
            tokenID
        ] = SubscriptionPermissionDetails({
            endDate: uint128(block.timestamp) + _details.subscriptionPeriod,
            readerCount: _details.readerCount,
            dataFeedType: _details.dataFeedType,
            disabled: false
        });

        _packageDetails[_packageID - 1].quotaLeft = _details.quotaLeft - 1;
        emit NewSubscription(_packageID, tokenID, _caller, _details);
    }

    // metamask
    function subscribe(
        uint256 _packageID
    ) external override whenNotPaused nonReentrant {
        PackageDetails memory localPackageDetails = packageDetails(_packageID);
        _subscribe(_packageID, localPackageDetails, msg.sender);
        KKUB.transferFrom(msg.sender, address(this), localPackageDetails.price);
    }

    // bitkubNext only
    function subscribe(
        uint256 _packageID,
        address _bitkubNext
    )
        external
        override
        onlySuperAdmin
        whenNotPaused
        checkBitkubNext(_bitkubNext)
        nonReentrant
    {
        PackageDetails memory localPackageDetails = packageDetails(_packageID);
        _subscribe(_packageID, localPackageDetails, _bitkubNext);
        adminKAP20Router.externalTransferKKUB(
            address(0),
            _bitkubNext,
            address(this),
            localPackageDetails.price,
            0
        );
    }

    function _renew(
        uint256 _tokenID,
        SubscriptionDetails memory _details,
        address _caller
    ) internal {
        require(!_details.disabled, "DataFeedSubscription: disabled");
        require(
            _details.endDate >= block.timestamp && _details.renewalCount > 0,
            "DataFeedSubscription: no more renewal allowed"
        );

        SubscriptionDetails
            memory oldSubscriptionDetails = SubscriptionDetails({
                name: _details.name,
                price: _details.price,
                endDate: _details.endDate,
                subscriptionPeriod: _details.subscriptionPeriod,
                renewalCount: _details.renewalCount,
                readerCount: _details.readerCount,
                dataFeedType: _details.dataFeedType,
                disabled: _details.disabled
            });

        _details.renewalCount -= 1;
        _details.endDate += _details.subscriptionPeriod;
        _subscriptionRenewalAndMiscDetails[_tokenID].renewalCount = _details
            .renewalCount;
        _subscriptionPermissionDetails[_tokenID].endDate = _details.endDate;

        emit SubscriptionRenewed(
            _tokenID,
            _caller,
            oldSubscriptionDetails,
            _details
        );
    }

    // metamask
    function renew(
        uint256 _tokenID
    )
        external
        override
        whenNotPaused
        onlyNFTOwner(_tokenID, msg.sender)
        nonReentrant
    {
        SubscriptionDetails
            memory localSubscriptionDetails = subscriptionDetails(_tokenID);
        _renew(_tokenID, localSubscriptionDetails, msg.sender);
        KKUB.transferFrom(
            msg.sender,
            address(this),
            localSubscriptionDetails.price
        );
    }

    // bitkubNext only
    function renew(
        uint256 _tokenID,
        address _bitkubNext
    )
        external
        override
        onlySuperAdmin
        whenNotPaused
        checkBitkubNext(_bitkubNext)
        onlyNFTOwner(_tokenID, _bitkubNext)
        nonReentrant
    {
        SubscriptionDetails
            memory localSubscriptionDetails = subscriptionDetails(_tokenID);
        _renew(_tokenID, localSubscriptionDetails, _bitkubNext);
        adminKAP20Router.externalTransferKKUB(
            address(0),
            _bitkubNext,
            address(this),
            localSubscriptionDetails.price,
            0
        );
    }
}
