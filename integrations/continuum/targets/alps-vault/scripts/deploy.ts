import { ethers } from "hardhat";

async function main() {
  const Vault = await ethers.getContractFactory("RewardVault");
  const vault = await Vault.deploy(process.env.STAKE_TOKEN!, process.env.PRICE_PAIR!);
  await vault.waitForDeployment();
  console.log("RewardVault", await vault.getAddress());
}
main();
