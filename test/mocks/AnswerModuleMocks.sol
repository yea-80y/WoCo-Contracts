// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IAnswerModule, Lookup} from "../../src/durin/interfaces/IAnswerModule.sol";

/// @dev An offchain module that tags everything it touches. `prepare` binds the
///      whole query into `callData`; `verify` refuses a `callData` it did not
///      prepare for `q` and a response not addressed to it, and echoes the
///      `moduleData` it saw, so a test can see exactly what reached it.
contract TaggingModule is IAnswerModule {
    bytes32 public immutable tag;

    error WrongCallData();
    error Rejected();

    constructor(bytes32 tag_) {
        tag = tag_;
    }

    function prepare(Lookup calldata q) external view returns (string[] memory urls, bytes memory callData) {
        urls = new string[](1);
        urls[0] = string.concat("https://module.test/", _tagHex(tag), "/{data}");
        callData = _callDataFor(q);
    }

    function verify(Lookup calldata q, bytes calldata callData, bytes calldata response)
        external
        view
        returns (bytes memory)
    {
        if (keccak256(callData) != keccak256(_callDataFor(q))) revert WrongCallData();
        if (keccak256(response) != keccak256(abi.encode(tag, "ok"))) revert Rejected();
        return abi.encode(tag, q.moduleData);
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IAnswerModule).interfaceId || id == type(IERC165).interfaceId;
    }

    function _callDataFor(Lookup calldata q) internal view returns (bytes memory) {
        return abi.encode(tag, q.name, q.data, q.chainId, q.registry, q.moduleData);
    }

    function _tagHex(bytes32 b) internal pure returns (string memory) {
        bytes memory out = new bytes(8);
        bytes16 digits = "0123456789abcdef";
        for (uint256 i; i < 4; ++i) {
            out[2 * i] = digits[uint8(b[i]) >> 4];
            out[2 * i + 1] = digits[uint8(b[i]) & 0x0f];
        }
        return string(out);
    }
}

/// @dev Answers onchain: no URLs, so `callData` is the answer.
contract SyncModule is IAnswerModule {
    function prepare(Lookup calldata q) external pure returns (string[] memory urls, bytes memory callData) {
        urls = new string[](0);
        callData = abi.encode("onchain", q.data);
    }

    function verify(Lookup calldata, bytes calldata, bytes calldata) external pure returns (bytes memory) {
        revert("SyncModule never goes offchain");
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IAnswerModule).interfaceId || id == type(IERC165).interfaceId;
    }
}

/// @dev Has code and answers ERC-165, but not for IAnswerModule.
contract NotAModule {
    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IERC165).interfaceId;
    }
}
