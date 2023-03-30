import hre from "hardhat";
import addressUtils from "../utils/addressUtils";
import { TestOracle__factory } from "../typechain-types/factories/TestOracle__factory";

export const main = async () => {
  const [owner] = await hre.ethers.getSigners();
  const addressList = await addressUtils.getAddressList(hre.network.name);

  const testOracle = (await hre.ethers.getContractFactory(
    "TestOracle"
  )) as TestOracle__factory;

  const testOracleContract = await testOracle
    .connect(owner)
    .deploy(addressList["SlidingWindowOracle"], addressList["KUSDT"]);

  await testOracleContract.deployTransaction
    .wait()
    .then((res) => res.transactionHash);

  console.log(`TestOracle: `, testOracleContract.address);

  await addressUtils.saveAddresses(hre.network.name, {
    TestOracle: testOracleContract.address,
  });
};

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
