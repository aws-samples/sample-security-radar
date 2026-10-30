import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

// DELIBERATELY VULNERABLE DEMO TARGET for Security Radar: the key below is the PUBLIC Hardhat default
// account #0 key (printed by every `npx hardhat node`). Shipping it in a production network config is the bug.
// It is a PUBLIC TEST KEY: never use it on a real network and never send funds to its address — anyone can spend them.
const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    bsc: {
      url: "https://bsc-dataseed.bnbchain.org",
      chainId: 56,
      accounts: ["0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"],
    },
  },
};
export default config;
