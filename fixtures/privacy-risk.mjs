// Fixture: PRIVACY RISK — should land in REVIEW.
// A voter-registry proposal that stores emails and phone numbers in plaintext
// on-chain and collects user data with no mention of consent or minimisation.
// No critical security bugs — the problem is privacy, which is exactly the
// failure mode Terminal 3 exists to prevent.
export default {
  id: 'prop-privacy-001',
  title: 'Voter registry for airdrop notifications',
  description:
    'Build an on-chain voter registry so the DAO can notify voters about ' +
    'upcoming airdrops and governance deadlines. Voters register their email ' +
    'and phone number; the registry contract stores them for the notification ' +
    'service to read. Execution via the timelock with a 48h delay.',
  proposer: '0xReg00000000000000000000000000000000000001',
  proposerProposals: 2,
  treasuryBalance: 1000000,
  requestedAmount: 0,
  timelockSeconds: 172800,
  executor: { type: 'timelock', signers: 0 },
  targets: [
    {
      to: '0xRegistry000000000000000000000000000000000001',
      value: 0,
      calldata: '0xdeployRegistry()',
      description: 'Deploy the voter registry contract',
      toIsContract: true,
    },
  ],
  claimsNoCodeChange: false,
  collectsUserData: true,
  dataDescription: 'Store voter email and phone for airdrop notifications',
  code: [
    {
      file: 'VoterRegistry.sol',
      source: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract VoterRegistry {
    address public owner;

    struct Voter {
        string email;
        string phoneNumber;
        bool registered;
    }

    mapping(address => Voter) public voters;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function register(string calldata email, string calldata phoneNumber) external {
        voters[msg.sender] = Voter(email, phoneNumber, true);
    }

    function remove(address voter) external onlyOwner {
        delete voters[voter];
    }
}
`,
    },
  ],
};
