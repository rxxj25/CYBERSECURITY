# CYBERSECURITY

# 📘 Blockchain Development Labs – 2025

This repository contains a series of hands-on blockchain development labs using **Solidity** and **Python**. The labs explore key concepts such as smart contracts, token systems, Merkle Trees, Proof-of-Work, and decentralized peer-to-peer networking.

---

## 🔍 Lab Overview

| Lab No. | Title                                | Language | Key Concepts                                      |
|--------|--------------------------------------|----------|--------------------------------------------------|
| 2      | Control Flow in Solidity             | Solidity | if-else, while, do-while, for, break, continue   |
| 3      | Token Management System              | Solidity | ERC-20 basics, admin control, modifiers, events  |
| 6–7    | Structs, Mappings & MetaMask         | Solidity | Structs, mappings, data access, Sepolia testnet  |
| 7      | P2P Blockchain Network               | Python   | Socket programming, peer sync, block validation  |
| 8–9    | Merkle Tree + Blockchain Integrity   | Python   | Merkle root, tamper detection, hash validation   |
| 10     | Blockchain with Mining (PoW)         | Python   | Proof-of-Work, nonce, mining difficulty          |

---

## 🧪 Lab Details

### 🔹 Lab 2: Control Flow in Solidity
Implemented Solidity functions demonstrating control flow:
- `isPositive`
- `recursiveSum` (using `while`)
- `sumBackwards` (using `do-while`)
- `factorial` (using `for`)
- `stopCountAtFive` (using `break`)
- `skipSumAtThree` (using `continue`)

### 🔹 Lab 3: Token Management System
Built a token system with:
- `view`, `pure`, `payable`, and `fallback` functions
- Access control using `onlyAdmin` modifier
- Error handling: `require`, `revert`, `assert`
- Token events: `Transfer`, `Deposit`

### 🔹 Lab 6–7: Structs and Mappings with MetaMask
Student Management System:
- Functions: `addStudent`, `getStudent`, `updateStudent`, `studentExists`
- Deployment on **Sepolia Testnet** via **MetaMask**
- Used **structs** and **mappings** for efficient data storage

### 🔹 Lab 7: P2P Blockchain in Python
Simulated a decentralized blockchain:
- Nodes connect using TCP sockets
- Broadcast blocks to connected peers
- Handle invalid and stale blocks with validation logic

### 🔹 Lab 8–9: Blockchain with Merkle Tree
Implemented Merkle Tree for transaction integrity:
- Each block computes a Merkle Root
- Tampering detection by altering transactions
- Revalidation of hashes and root

### 🔹 Lab 10: Proof-of-Work Blockchain
Simulated mining:
- Mining process requires hash to match difficulty (e.g., leading zeros)
- Adjustable difficulty
- Validates block hashes and linkage for chain integrity
