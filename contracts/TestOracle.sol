// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import "./AggregatorInterface.sol";
import "./lib/MathUtils.sol";
import "./amm/IUniswapV2Oracle.sol";

contract TestOracle {
    using MathUtils for uint256[];

    IUniswapV2Oracle public swapOracle;
    address public kusdtToken;
    address public owner;
    mapping(address => address) aggregatorAddr;

    constructor(address swapOracle_, address kusdtToken_) {
        owner = msg.sender;
        kusdtToken = kusdtToken_;
        swapOracle = IUniswapV2Oracle(swapOracle_);
    }

    function setAggregatorAddr(
        address _tokenAddr,
        address _aggregatorAddr
    ) external {
        aggregatorAddr[_tokenAddr] = _aggregatorAddr;
    }

    function dataFeedOwner() external view returns (address) {
        return owner;
    }

    function getPrice(address _tokenAddr) external view returns (int256) {
        return
            AggregatorInterface(aggregatorAddr[_tokenAddr]).latestAnswer() *
            10 ** 10;
    }

    function getLatestPrice(address token) public view returns (uint256) {
        if (token == kusdtToken) {
            return 1e18;
        } else return swapOracle.consult(token, 1e18, kusdtToken);
    }
}
