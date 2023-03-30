import hre from "hardhat";
import addressUtils from "../utils/addressUtils";
import { TestOracle__factory } from "../typechain-types/factories/TestOracle__factory";

async function main() {
  const addressList = await addressUtils.getAddressList(hre.network.name);
  const [owner] = await hre.ethers.getSigners();

  const TestOracle = TestOracle__factory.connect(
    addressList["TestOracle"],
    owner
  );

  await (
    await TestOracle.setAggregatorAddr(
      addressList["KKUB"],
      addressList["KUB/USDT"]
    )
  ).wait();

  await (
    await TestOracle.setAggregatorAddr(
      addressList["KUSDC"],
      addressList["USDC/USDT"]
    )
  ).wait();
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
