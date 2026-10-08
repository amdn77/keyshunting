// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Keyshunting Research Token
/// @notice Minimal self-contained ERC-20 used by the address-poisoning research pipeline
///         (counterfeit-token transfer detection / test flows). Fixed supply minted to the deployer.
contract KeyshuntingResearchToken {
    string public name = "Keyshunting Research Token";
    string public symbol = "KRT";
    uint8 public constant decimals = 18;

    uint256 public constant TOTAL_SUPPLY = 400_000_000_000_000 * 10 ** 18; // 400 trillion tokens

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        balanceOf[msg.sender] = TOTAL_SUPPLY;
        emit Transfer(address(0), msg.sender, TOTAL_SUPPLY);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= value, "KRT: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - value;
            emit Approval(from, msg.sender, allowance[from][msg.sender]);
        }
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "KRT: transfer to zero address");
        uint256 bal = balanceOf[from];
        require(bal >= value, "KRT: insufficient balance");
        unchecked {
            balanceOf[from] = bal - value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
    }
}
