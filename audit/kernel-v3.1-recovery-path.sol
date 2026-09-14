// VERBATIM COPY FOR AUDIT CONTEXT ONLY - not compiled or deployed by WoCo.
// Source: github.com/zerodevapp/kernel, tag v3.1, commit 03f7f5cf5871cda0070e4223f196f5b577f6cde2.
// The three files below are byte-identical to that commit, each under its own SPDX header, and match the
// verified source of the Kernel v3.1 implementation 0xBAC849bB641841b44E965fB01A4Bf5F074f84b4D on Arbitrum One.
// WoCoGuardianHook runs inside these: Kernel.fallback, installModule, uninstallModule;
// SelectorManager._installSelector, _uninstallSelector; HookManager._installHook, _uninstallHook, _doPreHook, _doPostHook.

// ===================================================================================================
// FILE: src/Kernel.sol  (sha256 13f9287eccb559dd71acc34a3c0b15cc0992dd253069561952dd45160c43045f)
// ===================================================================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "./interfaces/PackedUserOperation.sol";
import {IAccount, ValidationData, ValidAfter, ValidUntil, parseValidationData} from "./interfaces/IAccount.sol";
import {IEntryPoint} from "./interfaces/IEntryPoint.sol";
import {IAccountExecute} from "./interfaces/IAccountExecute.sol";
import {IERC7579Account} from "./interfaces/IERC7579Account.sol";
import {ModuleLib} from "./utils/ModuleLib.sol";
import {
    ValidationManager,
    ValidationMode,
    ValidationId,
    ValidatorLib,
    ValidationType,
    PermissionId,
    PassFlag,
    SKIP_SIGNATURE
} from "./core/ValidationManager.sol";
import {HookManager} from "./core/HookManager.sol";
import {ExecutorManager} from "./core/ExecutorManager.sol";
import {SelectorManager} from "./core/SelectorManager.sol";
import {IModule, IValidator, IHook, IExecutor, IFallback, IPolicy, ISigner} from "./interfaces/IERC7579Modules.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ExecLib, ExecMode, CallType, ExecType, ExecModeSelector, ExecModePayload} from "./utils/ExecLib.sol";
import {
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    ERC1967_IMPLEMENTATION_SLOT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    EXECTYPE_TRY,
    EXECTYPE_DEFAULT,
    EXEC_MODE_DEFAULT,
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_STATIC
} from "./types/Constants.sol";

contract Kernel is IAccount, IAccountExecute, IERC7579Account, ValidationManager {
    error ExecutionReverted();
    error InvalidExecutor();
    error InvalidFallback();
    error InvalidCallType();
    error OnlyExecuteUserOp();
    error InvalidModuleType();
    error InvalidCaller();
    error InvalidSelector();
    error InitConfigError(uint256 idx);

    event Received(address sender, uint256 amount);
    event Upgraded(address indexed implementation);

    IEntryPoint public immutable entrypoint;

    // NOTE : when eip 1153 has been enabled, this can be transient storage
    mapping(bytes32 userOpHash => IHook) internal executionHook;

    constructor(IEntryPoint _entrypoint) {
        entrypoint = _entrypoint;
        _validationStorage().rootValidator = ValidationId.wrap(bytes21(abi.encodePacked(hex"deadbeef")));
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entrypoint)) {
            revert InvalidCaller();
        }
        _;
    }

    modifier onlyEntryPointOrSelfOrRoot() {
        IValidator validator = ValidatorLib.getValidator(_validationStorage().rootValidator);
        if (
            msg.sender != address(entrypoint) && msg.sender != address(this) // do rootValidator hook
        ) {
            if (validator.isModuleType(4)) {
                bytes memory ret = IHook(address(validator)).preCheck(msg.sender, msg.value, msg.data);
                _;
                IHook(address(validator)).postCheck(ret);
            } else {
                revert InvalidCaller();
            }
        } else {
            _;
        }
    }

    function initialize(
        ValidationId _rootValidator,
        IHook hook,
        bytes calldata validatorData,
        bytes calldata hookData,
        bytes[] calldata initConfig
    ) external {
        ValidationStorage storage vs = _validationStorage();
        require(ValidationId.unwrap(vs.rootValidator) == bytes21(0), "already initialized");
        if (ValidationId.unwrap(_rootValidator) == bytes21(0)) {
            revert InvalidValidator();
        }
        ValidationType vType = ValidatorLib.getType(_rootValidator);
        if (vType != VALIDATION_TYPE_VALIDATOR && vType != VALIDATION_TYPE_PERMISSION) {
            revert InvalidValidationType();
        }
        _setRootValidator(_rootValidator);
        ValidationConfig memory config = ValidationConfig({nonce: uint32(1), hook: hook});
        vs.currentNonce = 1;
        _installValidation(_rootValidator, config, validatorData, hookData);
        for (uint256 i = 0; i < initConfig.length; i++) {
            (bool success,) = address(this).call(initConfig[i]);
            if (!success) {
                revert InitConfigError(i);
            }
        }
    }

    function changeRootValidator(
        ValidationId _rootValidator,
        IHook hook,
        bytes calldata validatorData,
        bytes calldata hookData
    ) external payable onlyEntryPointOrSelfOrRoot {
        ValidationStorage storage vs = _validationStorage();
        if (ValidationId.unwrap(_rootValidator) == bytes21(0)) {
            revert InvalidValidator();
        }
        ValidationType vType = ValidatorLib.getType(_rootValidator);
        if (vType != VALIDATION_TYPE_VALIDATOR && vType != VALIDATION_TYPE_PERMISSION) {
            revert InvalidValidationType();
        }
        _setRootValidator(_rootValidator);
        if (_validationStorage().validationConfig[_rootValidator].hook == IHook(address(0))) {
            // when new rootValidator is not installed yet
            ValidationConfig memory config = ValidationConfig({nonce: uint32(vs.currentNonce), hook: hook});
            _installValidation(_rootValidator, config, validatorData, hookData);
        }
    }

    function upgradeTo(address _newImplementation) external payable onlyEntryPointOrSelfOrRoot {
        assembly {
            sstore(ERC1967_IMPLEMENTATION_SLOT, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel";
        version = "0.3.1";
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    fallback() external payable {
        SelectorConfig memory config = _selectorConfig(msg.sig);
        bool success;
        bytes memory result;
        if (address(config.hook) == address(0)) {
            revert InvalidSelector();
        }
        // action installed
        bytes memory context;
        if (address(config.hook) != address(1) && address(config.hook) != 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF) {
            context = _doPreHook(config.hook, msg.value, msg.data);
        } else if (address(config.hook) == 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF) {
            // for selector manager, address(0) for the hook will default to type(address).max,
            // and this will only allow entrypoints to interact
            if (msg.sender != address(entrypoint)) {
                revert InvalidCaller();
            }
        }
        // execute action
        if (config.callType == CALLTYPE_SINGLE) {
            (success, result) = ExecLib.doFallback2771Call(config.target);
        } else if (config.callType == CALLTYPE_DELEGATECALL) {
            (success, result) = ExecLib.executeDelegatecall(config.target, msg.data);
        } else {
            revert NotSupportedCallType();
        }
        if (!success) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
        if (address(config.hook) != address(1) && address(config.hook) != 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF) {
            _doPostHook(config.hook, context);
        }
        assembly {
            return(add(result, 0x20), mload(result))
        }
    }

    // validation part
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        override
        onlyEntryPoint
        returns (ValidationData validationData)
    {
        ValidationStorage storage vs = _validationStorage();
        // ONLY ENTRYPOINT
        // Major change for v2 => v3
        // 1. instead of packing 4 bytes prefix to userOp.signature to determine the mode, v3 uses userOp.nonce's first 2 bytes to check the mode
        // 2. instead of packing 20 bytes in userOp.signature for enable mode to provide the validator address, v3 uses userOp.nonce[2:22]
        // 3. In v2, only 1 plugin validator(aside from root validator) can access the selector.
        //    In v3, you can use more than 1 plugin to use the exact selector, you need to specify the validator address in userOp.nonce[2:22] to use the validator

        (ValidationMode vMode, ValidationType vType, ValidationId vId) = ValidatorLib.decodeNonce(userOp.nonce);
        if (vType == VALIDATION_TYPE_ROOT) {
            vId = vs.rootValidator;
        }
        validationData = _doValidation(vMode, vId, userOp, userOpHash);
        ValidationConfig memory vc = vs.validationConfig[vId];
        // allow when nonce is not revoked or vType is sudo
        if (vType != VALIDATION_TYPE_ROOT && vc.nonce < vs.validNonceFrom) {
            revert InvalidNonce();
        }
        IHook execHook = vc.hook;
        if (address(execHook) == address(0)) {
            revert InvalidValidator();
        }
        executionHook[userOpHash] = execHook;

        if (address(execHook) == address(1)) {
            // does not require hook
            if (vType != VALIDATION_TYPE_ROOT && !vs.allowedSelectors[vId][bytes4(userOp.callData[0:4])]) {
                revert InvalidValidator();
            }
        } else {
            // requires hook
            if (vType != VALIDATION_TYPE_ROOT && !vs.allowedSelectors[vId][bytes4(userOp.callData[4:8])]) {
                revert InvalidValidator();
            }
            if (bytes4(userOp.callData[0:4]) != this.executeUserOp.selector) {
                revert OnlyExecuteUserOp();
            }
        }

        assembly {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
        }
    }

    // --- Execution ---
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        onlyEntryPoint
    {
        bytes memory context;
        IHook hook = executionHook[userOpHash];
        if (address(hook) != address(1)) {
            // removed 4bytes selector
            context = _doPreHook(hook, msg.value, userOp.callData[4:]);
        }
        (bool success, bytes memory ret) = ExecLib.executeDelegatecall(address(this), userOp.callData[4:]);
        if (!success) {
            revert ExecutionReverted();
        }
        if (address(hook) != address(1)) {
            _doPostHook(hook, context);
        }
    }

    function executeFromExecutor(ExecMode execMode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        // no modifier needed, checking if msg.sender is registered executor will replace the modifier
        IHook hook = _executorConfig(IExecutor(msg.sender)).hook;
        if (address(hook) == address(0)) {
            revert InvalidExecutor();
        }
        bytes memory context;
        if (address(hook) != address(1)) {
            context = _doPreHook(hook, msg.value, msg.data);
        }
        returnData = ExecLib.execute(execMode, executionCalldata);
        if (address(hook) != address(1)) {
            _doPostHook(hook, context);
        }
    }

    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable onlyEntryPointOrSelfOrRoot {
        ExecLib.execute(execMode, executionCalldata);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        ValidationStorage storage vs = _validationStorage();
        (ValidationId vId, bytes calldata sig) = ValidatorLib.decodeSignature(signature);
        if (ValidatorLib.getType(vId) == VALIDATION_TYPE_ROOT) {
            vId = vs.rootValidator;
        }
        if (address(vs.validationConfig[vId].hook) == address(0)) {
            revert InvalidValidator();
        }
        if (ValidatorLib.getType(vId) == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(vId);
            return validator.isValidSignatureWithSender(msg.sender, _toWrappedHash(hash), sig);
        } else {
            PermissionId pId = ValidatorLib.getPermissionId(vId);
            PassFlag permissionFlag = vs.permissionConfig[pId].permissionFlag;
            if (PassFlag.unwrap(permissionFlag) & PassFlag.unwrap(SKIP_SIGNATURE) != 0) {
                revert PermissionNotAlllowedForSignature();
            }
            return _checkPermissionSignature(pId, msg.sender, hash, sig);
        }
    }

    function installModule(uint256 moduleType, address module, bytes calldata initData)
        external
        payable
        override
        onlyEntryPointOrSelfOrRoot
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            ValidationStorage storage vs = _validationStorage();
            ValidationId vId = ValidatorLib.validatorToIdentifier(IValidator(module));
            if (vs.validationConfig[vId].nonce == vs.currentNonce) {
                // only increase currentNonce when vId's currentNonce is same
                unchecked {
                    vs.currentNonce++;
                }
            }
            ValidationConfig memory config =
                ValidationConfig({nonce: vs.currentNonce, hook: IHook(address(bytes20(initData[0:20])))});
            bytes calldata validatorData;
            bytes calldata hookData;
            bytes calldata selectorData;
            assembly {
                validatorData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 20)))
                validatorData.length := calldataload(sub(validatorData.offset, 32))
                hookData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 52)))
                hookData.length := calldataload(sub(hookData.offset, 32))
                selectorData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 84)))
                selectorData.length := calldataload(sub(selectorData.offset, 32))
            }
            _installValidation(vId, config, validatorData, hookData);
            if (selectorData.length == 4) {
                // NOTE: we don't allow configure on selector data on v3.1, but using bytes instead of bytes4 for selector data to make sure we are future proof
                _setSelector(vId, bytes4(selectorData[0:4]), true);
            }
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            bytes calldata executorData;
            bytes calldata hookData;
            assembly {
                executorData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 20)))
                executorData.length := calldataload(sub(executorData.offset, 32))
                hookData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 52)))
                hookData.length := calldataload(sub(hookData.offset, 32))
            }
            IHook hook = IHook(address(bytes20(initData[0:20])));
            _installExecutor(IExecutor(module), executorData, hook);
            _installHook(hook, hookData);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            bytes calldata selectorData;
            bytes calldata hookData;
            assembly {
                selectorData.offset := add(add(initData.offset, 56), calldataload(add(initData.offset, 24)))
                selectorData.length := calldataload(sub(selectorData.offset, 32))
                hookData.offset := add(add(initData.offset, 56), calldataload(add(initData.offset, 56)))
                hookData.length := calldataload(sub(hookData.offset, 32))
            }
            _installSelector(bytes4(initData[0:4]), module, IHook(address(bytes20(initData[4:24]))), selectorData);
            _installHook(IHook(address(bytes20(initData[4:24]))), hookData);
        } else if (moduleType == MODULE_TYPE_HOOK) {
            // force call onInstall for hook
            // NOTE: for hook, kernel does not support independent hook install,
            // hook is expected to be paired with proper validator/executor/selector
            IHook(module).onInstall(initData);
            emit ModuleInstalled(moduleType, module);
        } else if (moduleType == MODULE_TYPE_POLICY) {
            // force call onInstall for policy
            // NOTE: for policy, kernel does not support independent policy install,
            // policy is expected to be paired with proper permissionId
            // to "ADD" permission, use "installValidations()" function
            IPolicy(module).onInstall(initData);
            emit ModuleInstalled(moduleType, module);
        } else if (moduleType == MODULE_TYPE_SIGNER) {
            // force call onInstall for signer
            // NOTE: for signer, kernel does not support independent signer install,
            // signer is expected to be paired with proper permissionId
            // to "ADD" permission, use "installValidations()" function
            ISigner(module).onInstall(initData);
            emit ModuleInstalled(moduleType, module);
        } else {
            revert InvalidModuleType();
        }
    }

    function installValidations(
        ValidationId[] calldata vIds,
        ValidationConfig[] memory configs,
        bytes[] calldata validationData,
        bytes[] calldata hookData
    ) external payable onlyEntryPointOrSelfOrRoot {
        _installValidations(vIds, configs, validationData, hookData);
    }

    function uninstallValidation(ValidationId vId, bytes calldata deinitData, bytes calldata hookDeinitData)
        external
        payable
        onlyEntryPointOrSelfOrRoot
    {
        IHook hook = _uninstallValidation(vId, deinitData);
        _uninstallHook(hook, hookDeinitData);
    }

    function invalidateNonce(uint32 nonce) external payable onlyEntryPointOrSelfOrRoot {
        _invalidateNonce(nonce);
    }

    function uninstallModule(uint256 moduleType, address module, bytes calldata deInitData)
        external
        payable
        override
        onlyEntryPointOrSelfOrRoot
    {
        if (moduleType == 1) {
            ValidationId vId = ValidatorLib.validatorToIdentifier(IValidator(module));
            _uninstallValidation(vId, deInitData);
        } else if (moduleType == 2) {
            _uninstallExecutor(IExecutor(module), deInitData);
        } else if (moduleType == 3) {
            bytes4 selector = bytes4(deInitData[0:4]);
            _uninstallSelector(selector, deInitData[4:]);
        } else if (moduleType == 4) {
            ValidationId vId = _validationStorage().rootValidator;
            if (_validationStorage().validationConfig[vId].hook == IHook(module)) {
                // when root validator hook is being removed
                // remove hook on root validator to prevent kernel from being locked
                _validationStorage().validationConfig[vId].hook = IHook(address(1));
            }
            // force call onUninstall for hook
            // NOTE: for hook, kernel does not support independent hook install,
            // hook is expected to be paired with proper validator/executor/selector
            ModuleLib.uninstallModule(module, deInitData);
            emit ModuleUninstalled(moduleType, module);
        } else if (moduleType == 5) {
            ValidationId rootValidator = _validationStorage().rootValidator;
            bytes32 permissionId = bytes32(deInitData[0:32]);
            if (ValidatorLib.getType(rootValidator) == VALIDATION_TYPE_PERMISSION) {
                if (permissionId == bytes32(PermissionId.unwrap(ValidatorLib.getPermissionId(rootValidator)))) {
                    revert RootValidatorCannotBeRemoved();
                }
            }
            // force call onUninstall for policy
            // NOTE: for policy, kernel does not support independent policy install,
            // policy is expected to be paired with proper permissionId
            // to "REMOVE" permission, use "uninstallValidation()" function
            ModuleLib.uninstallModule(module, deInitData);
            emit ModuleUninstalled(moduleType, module);
        } else if (moduleType == 6) {
            ValidationId rootValidator = _validationStorage().rootValidator;
            bytes32 permissionId = bytes32(deInitData[0:32]);
            if (ValidatorLib.getType(rootValidator) == VALIDATION_TYPE_PERMISSION) {
                if (permissionId == bytes32(PermissionId.unwrap(ValidatorLib.getPermissionId(rootValidator)))) {
                    revert RootValidatorCannotBeRemoved();
                }
            }
            // force call onUninstall for signer
            // NOTE: for signer, kernel does not support independent signer install,
            // signer is expected to be paired with proper permissionId
            // to "REMOVE" permission, use "uninstallValidation()" function
            ModuleLib.uninstallModule(module, deInitData);
            emit ModuleUninstalled(moduleType, module);
        } else {
            revert InvalidModuleType();
        }
    }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        if (moduleTypeId < 7) {
            return true;
        } else {
            return false;
        }
    }

    function isModuleInstalled(uint256 moduleType, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            return _validationStorage().validationConfig[ValidatorLib.validatorToIdentifier(IValidator(module))].hook
                != IHook(address(0));
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            return address(_executorConfig(IExecutor(module)).hook) != address(0);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            return _selectorConfig(bytes4(additionalContext[0:4])).target == module;
        } else {
            return false;
        }
    }

    function accountId() external pure override returns (string memory accountImplementationId) {
        return "kernel.advanced.v0.3.1";
    }

    function supportsExecutionMode(ExecMode mode) external pure override returns (bool) {
        (CallType callType, ExecType execType, ExecModeSelector selector, ExecModePayload payload) =
            ExecLib.decode(mode);
        if (
            callType != CALLTYPE_BATCH && callType != CALLTYPE_SINGLE && callType != CALLTYPE_DELEGATECALL
                && callType != CALLTYPE_STATIC
        ) {
            return false;
        }

        if (
            ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_TRY)
                && ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_DEFAULT)
        ) {
            return false;
        }

        if (ExecModeSelector.unwrap(selector) != ExecModeSelector.unwrap(EXEC_MODE_DEFAULT)) {
            return false;
        }

        if (ExecModePayload.unwrap(payload) != bytes22(0)) {
            return false;
        }
        return true;
    }
}

// ===================================================================================================
// FILE: src/core/SelectorManager.sol  (sha256 ed9e53eb352cee5e6d5601f810805db1deaacbb34d374a9cb43dfa4018665e12)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IHook, IFallback, IModule} from "../interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "../interfaces/IERC7579Account.sol";
import {CallType} from "../utils/ExecLib.sol";
import {
    SELECTOR_MANAGER_STORAGE_SLOT,
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    MODULE_TYPE_FALLBACK
} from "../types/Constants.sol";
import {ModuleLib} from "../utils/ModuleLib.sol";

abstract contract SelectorManager {
    error NotSupportedCallType();

    struct SelectorConfig {
        IHook hook; // 20 bytes for hook address
        address target; // 20 bytes target will be fallback module, called with call
        CallType callType;
    }

    struct SelectorStorage {
        mapping(bytes4 => SelectorConfig) selectorConfig;
    }

    function selectorConfig(bytes4 selector) external view returns (SelectorConfig memory) {
        return _selectorConfig(selector);
    }

    function _selectorConfig(bytes4 selector) internal view returns (SelectorConfig storage config) {
        config = _selectorStorage().selectorConfig[selector];
    }

    function _selectorStorage() internal pure returns (SelectorStorage storage ss) {
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
    }

    function _installSelector(bytes4 selector, address target, IHook hook, bytes calldata selectorData) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF));
        }
        SelectorConfig storage ss = _selectorConfig(selector);
        // we are going to install only through call/delegatecall
        CallType callType = CallType.wrap(bytes1(selectorData[0]));
        if (callType == CALLTYPE_SINGLE) {
            IModule(target).onInstall(selectorData[1:]);
            emit IERC7579Account.ModuleInstalled(MODULE_TYPE_FALLBACK, target);
        } else if (callType != CALLTYPE_DELEGATECALL) {
            // NOTE : we are not going to call onInstall for delegatecall, and we support only CALL & DELEGATECALL
            revert NotSupportedCallType();
        }
        ss.hook = hook;
        ss.target = target;
        ss.callType = callType;
    }

    function _uninstallSelector(bytes4 selector, bytes calldata selectorDeinitData) internal returns (IHook hook) {
        SelectorConfig storage ss = _selectorConfig(selector);
        hook = ss.hook;
        ss.hook = IHook(address(0));
        if (ss.callType == CALLTYPE_SINGLE) {
            ModuleLib.uninstallModule(ss.target, selectorDeinitData);
            emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_FALLBACK, ss.target);
        }
        ss.target = address(0);
        ss.callType = CallType.wrap(bytes1(0x00));
    }
}

// ===================================================================================================
// FILE: src/core/HookManager.sol  (sha256 dbf557281bceac23fa2f6fbaa3abec6cce07282ccd6915db66b69499a3c622f8)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {ModuleLib} from "../utils/ModuleLib.sol";
import {IERC7579Account} from "../interfaces/IERC7579Account.sol";
import {MODULE_TYPE_HOOK} from "../types/Constants.sol";

abstract contract HookManager {
    // NOTE: currently, all install/uninstall calls onInstall/onUninstall
    // I assume this does not pose any security risks, but there should be a way to branch if hook needs call to onInstall/onUninstall
    // --- Hook ---
    // Hook is activated on these scenarios
    // - on 4337 flow, userOp.calldata starts with executeUserOp.selector && validator requires hook
    // - executeFromExecutor() is invoked and executor requires hook
    // - when fallback function has been invoked and fallback requires hook => native functions will not invoke hook
    function _doPreHook(IHook hook, uint256 value, bytes calldata callData) internal returns (bytes memory context) {
        context = hook.preCheck(msg.sender, value, callData);
    }

    function _doPostHook(IHook hook, bytes memory context) internal {
        // bool success,
        // bytes memory result
        hook.postCheck(context);
    }

    // @notice if hook is not initialized before, kernel will call hook.onInstall no matter what flag it shows, with hookData[1:]
    // @param hookData is encoded into (1bytes flag + actual hookdata) flag is for identifying if the hook has to be initialized or not
    function _installHook(IHook hook, bytes calldata hookData) internal {
        if (address(hook) == address(0) || address(hook) == address(1)) {
            return;
        }
        if (!hook.isInitialized(address(this))) {
            // if hook is not installed, it should call onInstall
            hook.onInstall(hookData[1:]);
        } else if (bytes1(hookData[0]) == bytes1(0xff)) {
            // 0xff means you want to explicitly call install hook
            hook.onInstall(hookData[1:]);
        }
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_HOOK, address(hook));
    }

    // @param hookData encoded as (1bytes flag + actual hookdata) flag is for identifying if the hook has to be initialized or not
    function _uninstallHook(IHook hook, bytes calldata hookData) internal {
        if (address(hook) == address(0) || address(hook) == address(1)) {
            return;
        }
        if (bytes1(hookData[0]) == bytes1(0xff)) {
            // 0xff means you want to call uninstall hook
            ModuleLib.uninstallModule(address(hook), hookData[1:]);
        }
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_HOOK, address(hook));
    }
}

