// Fixture: RISKY — should land in REVIEW (score 50-79, no critical findings).
// A 15% treasury grant to a brand-new program: no timelock, 2-of-2 multisig,
// direct ETH to an EOA, and a distributor contract with a floating pragma and
// timestamp-based vesting. Nothing fatal, but a human must look at it first.
export default {
  id: 'prop-risky-001',
  title: 'Community grant: 15% of treasury to new builder program',
  description:
    'Fund a new builder grants program with 150,000 USDC (15% of treasury). ' +
    'The program will run quarterly cohorts and publish transparent reports. ' +
    'The proposer is new to the DAO but has shipped two public-goods tools ' +
    'before. We ask for fast execution because the first cohort starts soon.',
  proposer: '0xNew00000000000000000000000000000000000001',
  proposerProposals: 0,
  treasuryBalance: 1000000,
  requestedAmount: 150000,
  timelockSeconds: 0,
  executor: { type: 'multisig', signers: 2 },
  targets: [
    {
      to: '0xGrantee000000000000000000000000000000000001',
      value: 150000,
      calldata: '0x',
      description: 'Send 150,000 USDC to the builder program wallet',
      toIsContract: false,
    },
  ],
  claimsNoCodeChange: false,
  collectsUserData: true,
  dataDescription:
    'We collect applicant wallet addresses with opt-in consent; addresses are hashed before storage, no emails stored.',
  code: [
    {
      file: 'GrantDistributor.sol',
      source: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GrantDistributor {
    address public owner;
    mapping(address => uint256) public grants;
    mapping(address => uint256) public releaseTime;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function scheduleGrant(address recipient, uint256 amount, uint256 delay) external onlyOwner {
        require(recipient != address(0), "zero recipient");
        grants[recipient] = amount;
        releaseTime[recipient] = block.timestamp + delay;
    }

    function claim() external {
        require(block.timestamp >= releaseTime[msg.sender], "too early");
        uint256 amount = grants[msg.sender];
        grants[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
`,
    },
  ],
};
