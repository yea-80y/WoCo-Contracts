// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @dev WoCo v2 (audit 964 M-2): the hash binds the chain id as well as the
///      target. Our deployer has already produced one address on two chains
///      (`0x172031E6…` is the mainnet L1Resolver and, separately, an Arbitrum
///      Sepolia contract), so "one deployment" is not a property the address
///      alone guarantees. The legacy preimage (94 bytes) and this one (126 bytes)
///      differ in length, so one gateway key can sign both during a swap without
///      either verifying as the other.
library SignatureVerifier {
    /**
     * @dev Generates a hash for signing/verifying.
     * @param target: The address the signature is for.
     * @param chainId: The chain `target` lives on.
     * @param request: The original request that was sent.
     * @param result: The `result` field of the response (not including the signature part).
     */
    function makeSignatureHash(
        address target,
        uint256 chainId,
        uint64 expires,
        bytes memory request,
        bytes memory result
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    hex"1900",
                    target,
                    chainId,
                    expires,
                    keccak256(request),
                    keccak256(result)
                )
            );
    }

    /**
     * @dev Verifies a signed message returned from a callback.
     * @param request: The original request that was sent.
     * @param response: An ABI encoded tuple of `(bytes result, uint64 expires, bytes sig)`, where `result` is the data to return
     *        to the caller, and `sig` is the (r,s,v) encoded message signature.
     * @return signer: The address that signed this message.
     * @return result: The `result` decoded from `response`.
     */
    function verify(
        bytes memory request,
        bytes memory response
    ) internal view returns (address, bytes memory) {
        (bytes memory result, uint64 expires, bytes memory sig) = abi.decode(
            response,
            (bytes, uint64, bytes)
        );
        address signer = ECDSA.recover(
            makeSignatureHash(address(this), block.chainid, expires, request, result),
            sig
        );
        require(
            expires >= block.timestamp,
            "SignatureVerifier: Signature expired"
        );
        return (signer, result);
    }
}
