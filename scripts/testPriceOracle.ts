import hre from "hardhat";
import addressUtils from "../utils/addressUtils";
import { TestOracle__factory } from "../typechain-types/factories/TestOracle__factory";
import { ethers } from "ethers";

async function main() {
  const addressList = await addressUtils.getAddressList(hre.network.name);
  const [owner] = await hre.ethers.getSigners();

  const TestOracle = TestOracle__factory.connect(
    addressList["TestOracle"],
    owner
  );

  const btcPrice = await TestOracle.getPrice("BTC");
  const ethPrice = await TestOracle.getPrice("ETH");

  console.log({
    btcPrice: ethers.utils.formatUnits(btcPrice, 8),
    ethPrice: ethers.utils.formatUnits(ethPrice, 8),
  });
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
