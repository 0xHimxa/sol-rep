
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Counter {
    uint256 public number;

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    function increment() public {
        number++;
    }
}


contract DynamicReturnHandler{



function callAndGetString(address target) external returns(string memory){



assembly{
//


  // Can't send ETH with delegatecall!
    // The value parameter doesn't exist
let success := delegatecall(
        50000,      // gas to send
        target,     // address of contract whose code to run
        0x00,       // args offset in memory
        36,         // args size (4 + 32)
        0x80,       // return data offset
        32          // return data size
    )
    





if iszero(success) {
    revert(0, 0)
}

let size := returndatasize()
let ptr := mload(0x40)


mstore(0x40, add(ptr, size))

returndatacopy(ptr, 0, size)

return(ptr, size)



// to get calldata








           // 1. Prepare calldata for getName()
            mstore(0x00, shl(224, 0x17d7de7c))  // function signature
            
            // 2. Make the call
            let success := call(50000, target, 0, 0x00, 4, 0, 0)
            if iszero(success) {
                revert(0, 0)
            }
            
            // 3. Get the size of return data (64 bytes in our example)
            let size := returndatasize()
            
            // 4. Reserve memory
            let ptr := mload(0x40)  // Get free memory pointer (e.g., 0x80)
            mstore(0x40, add(ptr, size))  // Update free pointer
            
            // 5. Copy return data from EVM's internal buffer to memory
            // Copies 64 bytes: [length (32 bytes)] + ["Alice" (5 bytes) + padding (27 bytes)]
            returndatacopy(ptr, 0, size)
            
            // After this line, memory at ptr looks like:
            // ptr+0 to ptr+31:   0x0000...0005 (length)
            // ptr+32 to ptr+63:  0x416c6963650000... (Alice + zeros)
            
            // 6. Return to Solidity
            // The data is ALREADY in the correct format!
            // Solidity expects: [32-byte length][actual data]
            // That's exactly what we have in memory
            return(ptr, size)  // Return 64 bytes
}




}





}