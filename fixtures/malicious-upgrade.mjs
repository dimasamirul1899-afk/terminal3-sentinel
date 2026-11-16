// Fixture: MALICIOUS — should be REJECT (multiple critical findings).
// Disguised as "routine maintenance" with a claim of "no code changes", this
// payload upgrades the proxy to an implementation that can selfdestruct, lets
// anyone re-enter withdrawals, authenticates with tx.origin and delegates
// calls to an arbitrary target.
export default {
  id: 'prop-malicious-001',
  title: 'Routine maintenance: upgrade oracle adapter',
  description:
    'Routine maintenance, no code changes, just a small config update to the oracle adapter.',
  proposer: '0xBad0000000000000000000000000000000000001',
  proposerProposals: 0,
  treasuryBalance: 1000000,
  requestedAmount: 0,
  timelockSeconds: 0,
  executor: { type: 'eoa' },
  targets: [
    {
      to: '0xProxy0000000000000000000000000000000000001',
      value: 0,
      calldata: '0x3659cfe6upgradeTo(address)',
      description: 'Upgrade oracle adapter implementation',
      toIsContract: true,
    },
  ],
  claimsNoCodeChange: true,
  collectsUserData: false,
  code: [
    {
      file: 'OracleAdapterV2.sol',
      source: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OracleAdapterV2 {
    address public owner;
    mapping(address => uint256) public balances;
    address public implementation;

    function upgradeTo(address newImplementation) public {
        implementation = newImplementation;
    }

    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] = 0;
    }

    function authWithdraw() public {
        require(tx.origin == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    function forward(bytes memory data) public {
        implementation.delegatecall(data);
    }

    function sweep() public {
        address(0x0000000000000000000000000000000000000001).call{value: 1 ether}("");
    }

    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    function claimLate() public {
        require(block.timestamp > 1700000000, "too early");
        balances[msg.sender] += 100;
    }
}
`,
    },
  ],
};
