import hre from "hardhat";
import addressUtils from "../utils/addressUtils";
import { IERC20__factory } from "../typechain-types/factories/IERC20__factory";
import { DataFeedSubscription__factory } from "../typechain-types/factories/DataFeedSubscription.sol/DataFeedSubscription__factory";
import { BitkubDataFeedNFT__factory } from "../typechain-types/factories/BitkubDataFeedNFT.sol/BitkubDataFeedNFT__factory";
import { PermissionManager__factory } from "../typechain-types/factories/PermissionManager.sol/PermissionManager__factory";
import { ethers } from "ethers";

async function main() {
  const addressList = await addressUtils.getAddressList(hre.network.name);
  const [owner] = await hre.ethers.getSigners();

  const KKUB = IERC20__factory.connect(addressList["KKUB"], owner);

  const BitkubDataFeedNFT = BitkubDataFeedNFT__factory.connect(
    addressList["BitkubDataFeedNFT"],
    owner
  );

  const DataFeedSubscription = DataFeedSubscription__factory.connect(
    addressList["DataFeedSubscription"],
    owner
  );

  const PermissionManager = PermissionManager__factory.connect(
    addressList["PermissionManager"],
    owner
  );

  //convert KUB to KKUB
  // await (
  //   await owner.sendTransaction({
  //     to: addressList["KKUB"],
  //     value: ethers.utils.parseEther("10"),
  //   })
  // ).wait();

  // const balance = await KKUB.balanceOf(owner.address);
  // console.log(ethers.utils.formatEther(balance));

  // await KKUB.approve(
  //   addressList["DataFeedSubscription"],
  //   ethers.constants.MaxUint256
  // ).then((tx) => tx.wait());

  // await (await DataFeedSubscription["subscribe(uint256)"](1)).wait();

  const tokenIds = await BitkubDataFeedNFT.tokenOfOwnerAll(owner.address);

  await PermissionManager["addAddresses(uint256,address[])"](
    tokenIds[0].toString(),
    [addressList["TestOracle"]]
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
