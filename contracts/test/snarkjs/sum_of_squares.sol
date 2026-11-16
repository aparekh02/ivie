// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity ^0.8.0;

contract SnarkjsSumOfSquaresVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 19768456208616854044352166796934805962015315004489086824382940043201928654350;
    uint256 constant alphay  = 499363061120280305497200827596485261803755010596634159939580313342101510792;
    uint256 constant betax1  = 21402697053270840130402778470091956095767277583859816460695564931007768447744;
    uint256 constant betax2  = 9990825919846322638481700142676978265322678989886671527731974359348768200671;
    uint256 constant betay1  = 5261105167849955667564552016224601956383212794467171252749336138466570190837;
    uint256 constant betay2  = 17068576845568261614805347801051943007734236114310580610404880559909996418359;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 7209017000408054710023649788495390413565799705783820742414237557716330866484;
    uint256 constant deltax2 = 9802049690951464633164313118607987413700300556690725327876596753538803569205;
    uint256 constant deltay1 = 10416837527239028820176920640115426412405609259653487926280130518045101025276;
    uint256 constant deltay2 = 6147265460740080342330790103302669899961868975997655007717068275642670597570;

    
    uint256 constant IC0x = 5371683853242429146767964747602248197825700286967391471681612360137563638819;
    uint256 constant IC0y = 9454597279846852779551240873440611446459064307216485058669192880986773424399;
    
    uint256 constant IC1x = 1149168579542788609006428433022511520282182941033951385387546739236033176759;
    uint256 constant IC1y = 1218022069163851192475069437427459927667066280109221511853515701150057286404;
    
    uint256 constant IC2x = 14675578702812826565441555102823942674614506238665180049451874368080860858790;
    uint256 constant IC2y = 4396711401765672976679648451921177930209544066230306514308400761483467008893;
    
    uint256 constant IC3x = 18280057703782971067190639465947750213128084664116776214203052957309715752457;
    uint256 constant IC3y = 11088453672362241008646175864337684405026126134117809026737363609888550512401;
    
    uint256 constant IC4x = 20985900781089942256837378713280639900580907789827855435224299353999000854529;
    uint256 constant IC4y = 5133808797203320011312796604494444931275206027633090531085972841014234180739;
    
    uint256 constant IC5x = 9036625391052780830908385246799839677560466062518720245039293303097504039604;
    uint256 constant IC5y = 5110312819096942269425543860277231670443703791279815491809742496389570280564;
    
    uint256 constant IC6x = 2131617683596506777863418208413071366077666181531427285633264192715506267407;
    uint256 constant IC6y = 13687449620750909677689692430231880103468899352861281244684961441600265293121;
    
    uint256 constant IC7x = 7518109838187339872454815608806481688409741271738316448200705546060579040115;
    uint256 constant IC7y = 2096651437851409639666939638276619602208712895079809177929812304244761000418;
    
    uint256 constant IC8x = 20365547547854565265479395649121241667185694923809010026126887835879211967313;
    uint256 constant IC8y = 10294957133196997676411415529924982516417675710070691279035195151791588590149;
    
    uint256 constant IC9x = 8041236141474976163796810275962898647800380342621131558437680308246047344980;
    uint256 constant IC9y = 15618900449837088482342854060782132454422249899369897042337891494542635264689;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[9] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
