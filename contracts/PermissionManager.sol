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

// File contracts/bitkubdatafeed/subscription/PermissionManager.sol

pragma solidity ^0.8.0;

struct AdminInput {
    address adminProjectRouter;
    address committee;
}

struct KYCInput {
    address kyc;
    uint256 acceptedKYCLevel;
}

struct ConstructorInput {
    AdminInput adminInput;
    KYCInput kycInput;
    address bitkubDataFeedNFT;
    string[] ownerFunctions;
}

contract PermissionManager is
    CommitteeControlledAuthorization,
    Pausable,
    KYCHandler,
    IPermissionManager
{
    using EnumerableSetAddress for EnumerableSetAddress.AddressSet;

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
    event BitkubDataFeedNFTSet(
        address indexed oldBitkubDataFeedNFT,
        address indexed newBitkubDataFeedNFT,
        address indexed caller
    );
    event CheckOwnerSignaturesSet(
        string[] oldOwnerFunctions,
        string[] newOwnerFunctions,
        address indexed caller
    );

    modifier checkTokenID(uint256 _tokenID) {
        require(_tokenID != 0, "PermissionManager: invalid tokenID");
        _;
    }

    modifier onlyNFTOwner(uint256 _tokenID, address _caller) {
        require(
            bitkubDataFeedNFT.ownerOf(_tokenID) == _caller,
            "PermissionManager: restricted only owner of NFT"
        );
        _;
    }

    modifier checkBitkubNext(address _bitkubNext) {
        require(
            kyc.kycsLevel(_bitkubNext) >= acceptedKYCLevel,
            "PermissionManager: only BitkubNext user"
        );
        _;
    }

    // contract address => tokenID (0 means no access)
    mapping(address => uint256) public override currentTokenID;

    // contract tokenID (can't be 0) => set of contact addresses
    mapping(uint256 => EnumerableSetAddress.AddressSet)
        internal _allowedAddresses;

    BitkubDataFeedNFTInterface public bitkubDataFeedNFT;

    bytes4[] public ownerFunctionSignature;
    string[] public ownerFunctionName;

    constructor(ConstructorInput memory _input) {
        adminProjectRouter = IAdminProjectRouter(
            _input.adminInput.adminProjectRouter
        );
        committee = _input.adminInput.committee;

        kyc = IKYCBitkubChain(_input.kycInput.kyc);
        acceptedKYCLevel = _input.kycInput.acceptedKYCLevel;

        bitkubDataFeedNFT = BitkubDataFeedNFTInterface(
            _input.bitkubDataFeedNFT
        );

        _setCheckOwnerSignatures(_input.ownerFunctions);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    function _setCheckOwnerSignatures(
        string[] memory _ownerFunctions
    ) internal {
        bytes4[] memory localOwnerFunctionSignatures = new bytes4[](
            _ownerFunctions.length
        );
        for (uint256 i = 0; i < _ownerFunctions.length; i++) {
            bytes memory tmpBytes = abi.encodeWithSignature(_ownerFunctions[i]);
            bytes4 tmpBytes4;
            assembly {
                tmpBytes4 := mload(add(tmpBytes, 0x20))
            }
            localOwnerFunctionSignatures[i] = tmpBytes4;
        }
        ownerFunctionSignature = localOwnerFunctionSignatures;
        ownerFunctionName = _ownerFunctions;
    }

    function setCheckOwnerSignatures(
        string[] memory _ownerFunctions
    ) external override onlySuperAdmin {
        emit CheckOwnerSignaturesSet(
            ownerFunctionName,
            _ownerFunctions,
            msg.sender
        );
        _setCheckOwnerSignatures(_ownerFunctions);
    }

    function pause() external onlySuperAdmin {
        _pause();
    }

    function unpause() external onlySuperAdmin {
        _unpause();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    function ownerFunctionSignatures()
        external
        view
        override
        returns (bytes4[] memory)
    {
        return ownerFunctionSignature;
    }

    function ownerFunctionNames()
        external
        view
        override
        returns (string[] memory)
    {
        return ownerFunctionName;
    }

    function allowedAddressesCount(
        uint256 _tokenID
    ) external view override checkTokenID(_tokenID) returns (uint256) {
        return _allowedAddresses[_tokenID].length();
    }

    function allowedAddresses(
        uint256 _tokenID
    ) external view override checkTokenID(_tokenID) returns (address[] memory) {
        return _allowedAddresses[_tokenID].getAll();
    }

    function allowedAddressesByPage(
        uint256 _tokenID,
        uint256 _page,
        uint256 _limit
    ) external view override checkTokenID(_tokenID) returns (address[] memory) {
        return _allowedAddresses[_tokenID].get(_page, _limit);
    }

    function hasAccess(
        address _user,
        bytes memory _calldata
    ) external view override returns (bool) {
        uint256 tokenID = currentTokenID[_user]; // get tokenID of consumer contract
        if (
            tokenID != 0 && // check if consumer contract is allowed
            DataFeedSubscriptionInterface(
                bitkubDataFeedNFT.getTokenInfoAddress(tokenID)
            ).isSubscribed(
                    tokenID,
                    abi.decode(_calldata, (address)) // data feed address
                ) // check whether this tokenID has the access to read data feed or not
        ) {
            return true;
        }
        return false;
    }

    function _staticCall(
        address _target,
        bytes memory _data
    ) internal view returns (address) {
        (bool success, bytes memory returndata) = _target.staticcall(_data);
        if (success && returndata.length > 0) {
            return abi.decode(returndata, (address));
        } else {
            return address(0);
        }
    }

    // check the owner of the target contract
    function _checkOwner(address _target, address _caller) internal view {
        uint256 tmpLength = ownerFunctionSignature.length;
        for (uint256 i = 0; i < tmpLength; i++) {
            address owner = _staticCall(
                _target,
                abi.encodeWithSelector(ownerFunctionSignature[i])
            );
            if (owner == _caller) {
                return;
            }
        }
        revert("PermissionManager: caller is not owner of the contract");
    }

    function _checkReaderCount(
        uint256 _tokenID,
        uint256 _currentAddressLength,
        uint256 _newAddressLength
    ) internal view checkTokenID(_tokenID) {
        uint256 maximumReaderCount = DataFeedSubscriptionInterface(
            bitkubDataFeedNFT.getTokenInfoAddress(_tokenID)
        ).getMaximumReaderCount(_tokenID);
        require(
            _currentAddressLength + _newAddressLength <= maximumReaderCount,
            "PermissionManager: exceeds maxmimum reader count"
        );
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    function _addAddress(
        uint256 _tokenID,
        address _addr,
        address _caller
    ) internal checkTokenID(_tokenID) {
        require(
            _addr != address(0) && _addr != address(this),
            "PermissionManager: invalid address"
        );
        _checkOwner(_addr, _caller);

        uint256 oldTokenID = currentTokenID[_addr];
        require(
            _tokenID != oldTokenID,
            "PermissionManager: address already exists"
        );
        if (_allowedAddresses[oldTokenID].contains(_addr)) {
            _removeAddress(oldTokenID, _addr, _caller);
        }

        _allowedAddresses[_tokenID].add(_addr);
        currentTokenID[_addr] = _tokenID;
        emit AddressAdded(_tokenID, _addr, _caller);
    }

    function _removeAddress(
        uint256 _tokenID,
        address _addr,
        address _caller
    ) internal checkTokenID(_tokenID) {
        require(
            _allowedAddresses[_tokenID].remove(_addr),
            "PermissionManager: address does not exist"
        );
        currentTokenID[_addr] = 0;
        emit AddressRemoved(_tokenID, _addr, _caller);
    }

    function _setAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _caller
    ) internal {
        uint256 tmpLength = _allowedAddresses[_tokenID].length();
        for (uint256 i = 0; i < tmpLength; i++) {
            _removeAddress(
                _tokenID,
                _allowedAddresses[_tokenID].at(0),
                _caller
            );
        }

        _checkReaderCount(_tokenID, 0, _addrs.length);
        for (uint256 i = 0; i < _addrs.length; i++) {
            _addAddress(_tokenID, _addrs[i], _caller);
        }
    }

    function _addAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _caller
    ) internal {
        _checkReaderCount(
            _tokenID,
            _allowedAddresses[_tokenID].length(),
            _addrs.length
        );
        for (uint256 i = 0; i < _addrs.length; i++) {
            _addAddress(_tokenID, _addrs[i], _caller);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setAddresses(
        uint256 _tokenID,
        address[] calldata _addrs
    ) external override whenNotPaused onlyNFTOwner(_tokenID, msg.sender) {
        _setAddresses(_tokenID, _addrs, msg.sender);
    }

    function setAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _bitkubNext
    )
        external
        override
        onlySuperAdmin
        whenNotPaused
        checkBitkubNext(_bitkubNext)
        onlyNFTOwner(_tokenID, _bitkubNext)
    {
        _setAddresses(_tokenID, _addrs, _bitkubNext);
    }

    function addAddresses(
        uint256 _tokenID,
        address[] calldata _addrs
    ) external override whenNotPaused onlyNFTOwner(_tokenID, msg.sender) {
        _addAddresses(_tokenID, _addrs, msg.sender);
    }

    function addAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _bitkubNext
    )
        external
        override
        onlySuperAdmin
        whenNotPaused
        checkBitkubNext(_bitkubNext)
        onlyNFTOwner(_tokenID, _bitkubNext)
    {
        _addAddresses(_tokenID, _addrs, _bitkubNext);
    }

    function removeAddresses(
        uint256 _tokenID,
        address[] calldata _addrs
    ) external override whenNotPaused onlyNFTOwner(_tokenID, msg.sender) {
        for (uint256 i = 0; i < _addrs.length; i++) {
            _removeAddress(_tokenID, _addrs[i], msg.sender);
        }
    }

    function removeAddresses(
        uint256 _tokenID,
        address[] calldata _addrs,
        address _bitkubNext
    )
        external
        override
        onlySuperAdmin
        whenNotPaused
        checkBitkubNext(_bitkubNext)
        onlyNFTOwner(_tokenID, _bitkubNext)
    {
        for (uint256 i = 0; i < _addrs.length; i++) {
            _removeAddress(_tokenID, _addrs[i], _bitkubNext);
        }
    }
}
