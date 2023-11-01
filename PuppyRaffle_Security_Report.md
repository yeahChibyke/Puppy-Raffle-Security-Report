<p align="center">
<img src="https://drive.google.com/file/d/1dW5sfoL00mvejf9C5FSzy_TAAjXPEPxr/view?usp=sharing">
<img src="https://drive.google.com/file/d/1IBRvP0BeZ1q57PUHISVerwLnpVPjNhBu/view?usp=sharing">
<br>

# Security Findings Per My Participation In The [`CodeHawks First Flights PuppyRaffle 🐶 Contest`](https://www.codehawks.com/contests/clo383y5c000jjx087qrkbrj8)

### I conducted a security review of the [`PuppyRaffle 🐶 codebase`](https://github.com/Cyfrin/2023-10-Puppy-Raffle), and below are my findings:

* ## Lack of input validation in the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92)function could lead to a possible DoS attack

### Impact

An attacker could potentially send an array of invalid addresses to the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function, causing the function to consume all the gas available and prevent other users from interacting with the contract.
This is because the function iterates over the `newPlayers` array and checks if each address is valid. If an invalid address is encountered, the function will throw an error and consume all the gas available.

### Recommended Mitigation

In the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function, the contract should check if each address in the `newPlayers` array is a valid Ethereum address before processing it.
This can be done by using the `require` statement with the condition:

```javascript
newPlayers[i] != address(0);
```

This check ensures that the function does not proceed if any of the addresses provided are invalid, and below I have written how it can be implemented in the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function:

```javascript
function enterRaffle(address[] memory newPlayers) public payable {
       require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
       for (uint256 i = 0; i < newPlayers.length; i++) {
           require(newPlayers[i] != address(0), "PuppyRaffle: Invalid player address");
           bool isDuplicate = false;
           for (uint256 j = 0; j < players.length; j++) {
               if (players[j] == newPlayers[i]) {
                  isDuplicate = true;
                  break;
               }
           }
           if (!isDuplicate) {
               players.push(newPlayers[i]);
           } else {
               emit RaffleEnter(newPlayers);
           }
       }
   }
```

* ## Inefficient duplicate check in [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function

### Impact

In the current implementation, checks are done after addresses are added to the `players` array.
This could lead to unnecessary gas costs, as the function iterates over the entire `players` array for each address in the `newPlayers` array. If for instance, a user calls the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function and passes an array of 100 addresses, the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function adds each address to the `players` array and checks for duplicates. This results in the function iterating over the `players` array 100 times, which is highly inefficient and could consume a lot of gas. Also, because of CEI (Check Events Interactions) failure, this could lead to possible reentrancy attacks. A function could be created that calls this particular function, and then manipulated for malicious purposes.

### Recommended Mitigation

Modify the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function to check for duplicates before adding the addresses to the `players` array.
This is done by iterating over the `players` array for each address in the `newPlayers` array and checking if the address already exists in the `players` array.
This is more efficient than checking for duplicates after they have been added to the array.

```javascript
function enterRaffle(address[] memory newPlayers) public payable {
       require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
       for (uint256 i = 0; i < newPlayers.length; i++) {
           require(newPlayers[i] != address(0), "PuppyRaffle: Invalid player address");
           bool isDuplicate = false;
           for (uint256 j = 0; j < players.length; j++) {
               if (players[j] == newPlayers[i]) {
                  isDuplicate = true;
                  break;
               }
           }
           if (!isDuplicate) {
               players.push(newPlayers[i]);
           } else {
               emit RaffleEnter(newPlayers);
           }
       }
   }
```

* ## The [`refund()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L96-L105) function does not check if the player's address is the zero address, which is a valid Ethereum address.

The [`refund()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L96-L105) function does not check if the player's address is the zero address, which is a valid Ethereum address.

### Impact

If the function is called with the zero address, it will attempt to send the entrance fee to the zero address, which is not possible because the zero address does not have a balance. This will cause the function to fail and consume all the gas available for the transaction.

### Recommended Mitigation

The [`refund()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L96-L105) function should check if the player's address is the zero address before attempting to send the entrance fee. This can be done using the `require` statement with the condition:

```javascript
 playerAddress != address(0)
```

This check ensures that the function does not proceed if the player's address is the zero address.

I modified the [`refund()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L96-L105) function with this check

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress != address(0), "PuppyRaffle: Invalid player address");
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");

    payable(msg.sender).sendValue(entranceFee);

    players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

* ## Possible DoS Attack Risk In [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) Function

The [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function does not check if the `feeAddress` is the zero address, which is a valid Ethereum address.
If the function is called with the zero address, it will attempt to send the fees to the zero address, which is not possible because the zero address does not have a balance.

### Impact

Let's say an attacker wants to disrupt the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function. The attacker could call the `changeFeeAddress()` function with the zero address as the new fee address.
The [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function will then attempt to send the fees to the zero address, causing the function to fail and consume all the gas available for the transaction.

### Recommended Mitigation

To mitigate this issue, the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function should check if the `feeAddress` is the zero address before attempting to send the fees.
This can be done using the `require` statement with the condition:

```javascript
feeAddress != address(0)
```

This check ensures that the function does not proceed if the `feeAddress` is the zero address.

Here's how the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function is modified to include this check:

```javascript
function withdrawFees() external {
    require(feeAddress != address(0), "PuppyRaffle: Invalid fee address");
    require(address(this).balance == uint256(totalFees), "PuppyRaffle: Incorrect balance");

    payable(feeAddress).transfer(address(this).balance);
    totalFees = 0;

    emit FeesWithdrawn(feeAddress);
}
```

* ## Possible DoS attack could happen in [`changeFeeAddress()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L167-L170) due to no zero address check

### Impact

If the function is called with the zero address, it will update the `feeAddress` to the zero address. This is not a problem on its own, but if the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function is called afterwards, it will attempt to send the fees to the zero address, which is not possible because the zero address does not have a balance. This will cause the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function to fail and consume all the gas available for the transaction.

Here's a potential attack scenario:

Let's say an attacker wants to disrupt the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function. The attacker could call the [`changeFeeAddress()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L167-L170) function with the zero address as the new fee address. The [`changeFeeAddress()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L167-L170) function will then update the `feeAddress` to the zero address. When the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function is called afterwards, it will attempt to send the fees to the zero address, causing the function to fail and consume all the gas available for the transaction.

### Recommended Mitigations

To mitigate this issue, the [`changeFeeAddress()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L167-L170) function should check if the new fee address is the zero address before updating the `feeAddress`.
This can be done using the `require` statement with the condition:

```javascript
newFeeAddress != address(0)
```

This check ensures that the function does not proceed if the new fee address is the zero address.

Here's how the [`changeFeeAddress()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L167-L170) function could be modified to include this check:

```javascript
function changeFeeAddress(address newFeeAddress) external onlyOwner {
    require(newFeeAddress != address(0), "PuppyRaffle: Invalid fee address");
    feeAddress = newFeeAddress;
    emit FeeAddressChanged(newFeeAddress);
}
```

In this modified version of the [`changeFeeAddress()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L167-L170) function, the function will revert the transaction if the new fee address is the zero address. This prevents the [`withdrawFees()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L157-L163) function from failing and consuming all the gas available for the transaction, mitigating the risk of a DoS attack.

* ## Possible reentrancy attack in [`selectWinner()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L125-L154) function

### Impact 

The [`selectWinner()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L125-L154) function in the original smart contract is vulnerable to a reentrancy attack because it makes an external call to transfer the prize pool to the winner's address before it updates the state of the contract. If the winner's address is a contract, it could potentially call back into the [`selectWinner()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L125-L154) function before it's finished, leading to a reentrancy attack.

### Recommended Mitigations

The state changes (updating the `players`, `raffleStartTime`, and `previousWinner` variables and deleting the `players` array) should be made before the external call to transfer the prize pool to the winner's address. This ensures that even if the winner's address is a malicious contract that calls back into the [`selectWinner()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L125-L154) function, it won't be able to manipulate the state of the contract.

```javascript
function selectWinner() external {
    require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
    require(players.length >= 4, "PuppyRaffle: Need at least 4 players");

    uint256 winnerIndex =
        uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
    address winner = players[winnerIndex];

    uint256 totalAmountCollected = players.length * entranceFee;
    uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 fee = (totalAmountCollected * 20) / 100;
    totalFees = totalFees + uint64(fee);

    uint256 tokenId = totalSupply();

    uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;
    if (rarity <= COMMON_RARITY) {
        tokenIdToRarity[tokenId] = COMMON_RARITY;
    } else if (rarity <= COMMON_RARITY + RARE_RARITY) {
        tokenIdToRarity[tokenId] = RARE_RARITY;
    } else {
        tokenIdToRarity[tokenId] = LEGENDARY_RARITY;
    }

    delete players;
    raffleStartTime = block.timestamp;
    previousWinner = winner;

    // External call made after all state changes
    (bool success,) = winner.call{value: prizePool}("");
    require(success, "PuppyRaffle: Failed to send prize pool to winner");
    _safeMint(winner, tokenId);
}
```

* ## No Event Emitted in [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) Function on Player Multi-Entry Into Raffle

The [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function does not emit an event when a player tries to enter the raffle multiple times. This is a bug because it could make it difficult for users and developers to track the behavior of the contract and detect any potential issues.

### Impact

Let's say a user tries to enter the raffle multiple times with the same address. The [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function will allow this and add the address to the `players` array multiple times. However, because the function does not emit an event when a duplicate is found, the user will not be notified that they are trying to enter the raffle multiple times. This could potentially lead to confusion and misunderstanding.

### Recommended Mitigations

To mitigate this issue, the [`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function should emit an event when a player tries to enter the raffle multiple times. This can be done by adding an `emit` statement in the function. Here's an example of how this could be done:

```javascript
event RaffleEnter(address indexed player, bool duplicate);

function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == (newPlayers.length * entranceFee), "PuppyRaffle: Incorrect amount of Ether provided");

    for (uint256 i = 0; i < newPlayers.length; i++) {
        bool isDuplicate = false;
        for (uint256 j = 0; j < players.length; j++) {
            if (players[j] == newPlayers[i]) {
                isDuplicate = true;
                break;
            }
        }
        if (!isDuplicate) {
            players.push(newPlayers[i]);
        }
        emit RaffleEnter(newPlayers[i], isDuplicate);
    }
}
```

In this modified version of the[`enterRaffle()`](https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-L92) function, the function emits a `RaffleEnter` event for each address in the `newPlayers` array. The event includes the address of the player and a boolean indicating whether the address is a duplicate. This provides feedback to the user that they are trying to enter the raffle multiple times and makes the contract's behavior more transparent and easier to track.
