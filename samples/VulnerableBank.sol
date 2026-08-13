// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Deliberately vulnerable contract used to prove the scanner catches
///      real bugs. DO NOT deploy. Classic reentrancy: external call happens
///      before the balance is zeroed.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        // BUG: external call BEFORE state update -> reentrancy
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
