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

  const kubPrice = await TestOracle.getPrice(addressList["KKUB"]);
  const kusdcPrice = await TestOracle.getPrice(addressList["KUSDC"]);
  const yesPrice = await TestOracle.getLatestPrice(addressList["YES"]);
  const kusdtPrie = await TestOracle.getLatestPrice(addressList["KUSDT"]);

  console.log({
    kubPrice: ethers.utils.formatEther(kubPrice),
    kusdcPrice: ethers.utils.formatEther(kusdcPrice),
    yesPrice: ethers.utils.formatEther(yesPrice),
    kusdtPrie: ethers.utils.formatEther(kusdtPrie),
  });
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
