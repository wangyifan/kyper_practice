// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0 <0.9.0;

contract bls {
    bytes public input;
    bool public lastVerify;
    uint256 public counter;
    event VerifyResult(bool);

    function Verify(bytes memory toVerify) public returns (bool) {
        input = toVerify;
        lastVerify = verify(toVerify);
        emit VerifyResult(lastVerify);
        if (lastVerify) {
            counter += 1;
        }

        return lastVerify;
    }

    function verify(bytes memory toVerify) public view returns (bool) {
        bytes32 output;
        assembly {
            let out := mload(0x40)
            let precompile := 0x42
            let inputSize := 0x300
            let outputSize := 0x20
            let success := staticcall(
                gas(),
                precompile,
                add(toVerify, 0x20),
                inputSize,
                out,
                outputSize
            )
            switch success
                case 0 {
                     revert(0,0)
             } default {
                 output := mload(out)
            }
        }

        if (output[31] != 0) {
            return true;
        }
        return false;
    }
}
