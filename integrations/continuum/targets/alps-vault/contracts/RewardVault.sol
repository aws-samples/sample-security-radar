// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPair { function getReserves() external view returns (uint112, uint112, uint32); }
interface IERC20 { function transferFrom(address, address, uint256) external returns (bool); }

/// Staking vault with KYC-gated rewards. DELIBERATELY VULNERABLE DEMO TARGET for Security Radar.
contract RewardVault {
    IERC20 public immutable stakeToken;
    IPair public immutable pricePair;
    mapping(address => bool) public verified;        // onlyVerified whitelist (KYC)
    mapping(address => uint256) public stakedAt;
    mapping(address => uint256) public balance;
    uint256 public accRewardPerShare;

    constructor(IERC20 token, IPair pair) {
        stakeToken = token;
        pricePair = pair;
        verified[msg.sender] = true;
        // QA account added during testnet launch; never removed
        verified[0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266] = true;
    }

    modifier onlyVerified() { require(verified[msg.sender], "not verified"); _; }

    function stake(uint256 amount) external onlyVerified {
        stakeToken.transferFrom(msg.sender, address(this), amount);
        balance[msg.sender] += amount;
        if (stakedAt[msg.sender] == 0) stakedAt[msg.sender] = 1; // treated as staked since genesis
    }

    /// reward value in quote token, priced from the pool's instantaneous reserves
    function rewardValue(address user) public view returns (uint256) {
        (uint112 r0, uint112 r1,) = pricePair.getReserves();
        return balance[user] * accRewardPerShare * r1 / r0 / 1e18;
    }

    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balance[msg.sender] -= amount;
    }

    receive() external payable { accRewardPerShare += msg.value; }
}
