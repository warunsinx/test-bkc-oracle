// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./AggregatorInterface.sol";

contract TestOracle {
    mapping(string => address) aggregatorAddr;

    function setAggregatorAddr(string memory _symbol, address _addr) external {
        aggregatorAddr[_symbol] = _addr;
    }

    function dataFeedOwner() external view returns (address) {
        return address(0x9B75E1E69857f2eDF8A29395AC419AdD4EdaCc67);
    }

    function getPrice(string memory _symbol) external view returns (int256) {
        return AggregatorInterface(aggregatorAddr[_symbol]).latestAnswer();
    }
}
