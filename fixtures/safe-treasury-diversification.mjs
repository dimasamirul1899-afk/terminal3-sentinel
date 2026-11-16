// Fixture: SAFE — should score 100, verdict APPROVE.
// A boring, well-written treasury diversification: 5% of treasury into an
// audited staking vault, 48h timelock, timelock-contract executor, guarded code.
export default {
  id: 'prop-safe-001',
  title: 'Diversify 5% of treasury into stETH',
  description:
    'Move 50,000 USDC (5% of treasury) into the audited staking vault to earn ' +
    'yield while keeping 95% liquid. The vault contract was audited by two firms ' +
    'in Q3 2026; the audit reports are linked in the forum thread. Execution is ' +
    'via the DAO timelock with a 48h delay, so holders can exit before it runs.',
  proposer: '0xA11ce00000000000000000000000000000000001',
  proposerProposals: 4,
  treasuryBalance: 1000000,
  requestedAmount: 50000,
  timelockSeconds: 172800,
  executor: { type: 'timelock', signers: 0 },
  targets: [
    {
      to: '0xVault0000000000000000000000000000000000001',
      value: 0,
      calldata: '0xdeposit(uint256)',
      description: 'Deposit 50,000 USDC into the audited staking vault',
      toIsContract: true,
    },
  ],
  claimsNoCodeChange: false,
  collectsUserData: false,
  code: [
    {
      file: 'TreasuryDiversifier.sol',
      source: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 shares) external;
}

contract TreasuryDiversifier {
    address public owner;
    address public vault;
    uint256 public diversified;

    event Diversified(uint256 amount);

    constructor(address _vault) {
        require(_vault != address(0), "zero vault");
        owner = msg.sender;
        vault = _vault;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setVault(address _vault) external onlyOwner {
        require(_vault != address(0), "zero vault");
        vault = _vault;
    }

    function executeDiversification(uint256 amount) external onlyOwner {
        require(amount > 0, "zero amount");
        diversified += amount;
        IVault(vault).deposit(amount);
        emit Diversified(amount);
    }
}
`,
    },
  ],
};
