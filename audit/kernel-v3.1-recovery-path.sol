// VERBATIM COPIES FOR AUDIT CONTEXT ONLY - not compiled or deployed by WoCo. Source: github.com/zerodevapp/kernel.
// Every file below is byte-identical to the commit named on its FILE line, keeps its own SPDX header (all MIT) and
// carries its sha256. Each section matches the verified source of the contract deployed on Arbitrum One:
//   A. Kernel v3.1 (tag v3.1, 03f7f5cf5871cda0070e4223f196f5b577f6cde2): implementation 0xBAC849bB641841b44E965fB01A4Bf5F074f84b4D,
//      KernelFactory 0xaac5D4240AF87249B3f71BC8E4A2cae074A3E419
//   B. ECDSAValidator (8f7fd9946b9d351bb5be0428bf34c87bad7ed6c9): 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57, the user account's root validator
//   C. WeightedECDSAValidator (00dd9e46413b37f6a7da58f85e8d950c5762243c): 0xeD89244160CfE273800B58b1B534031699dFeEEE, a guardian account's root validator
// Why these files: WoCoGuardianHook runs inside Kernel.fallback / installModule / uninstallModule / execute (SelectorManager,
// HookManager, ExecLib, ModuleLib, Constants, Types, IERC7579Modules); recovery rotates the owner in ECDSAValidator; guardian
// accounts are KernelFactory proxies whose root validator is WeightedECDSAValidator.
// Types, Constants and PackedUserOperation are identical at all three commits. IERC7579Modules is not: B's copy differs from
// A's only by a one-word comment typo, and C's copy (included in section C) has the older IHook.postCheck signature.
// Not included, deliberately: ValidationManager, ValidationTypeLib, ExecutorManager (standard Kernel authorisation of an
// account's own calls, not on the hook's path) and the solady libraries (ECDSA, EIP712, LibClone).

// ###################################################################################################
// SECTION A - ZeroDev Kernel v3.1 (tag v3.1)
// ###################################################################################################
// ===================================================================================================
// FILE: src/Kernel.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 13f9287eccb559dd71acc34a3c0b15cc0992dd253069561952dd45160c43045f)
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
// FILE: src/core/SelectorManager.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 ed9e53eb352cee5e6d5601f810805db1deaacbb34d374a9cb43dfa4018665e12)
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
// FILE: src/core/HookManager.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 dbf557281bceac23fa2f6fbaa3abec6cce07282ccd6915db66b69499a3c622f8)
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

// ===================================================================================================
// FILE: src/utils/ExecLib.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 bf12b6d16943d9f9c4dc9684e578062efbcd65980e95b074c4bcfad6fe46f4b7)
// ===================================================================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ExecMode, CallType, ExecType, ExecModeSelector, ExecModePayload} from "../types/Types.sol";
import {
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    EXECTYPE_DEFAULT,
    EXEC_MODE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_DELEGATECALL
} from "../types/Constants.sol";
import {Execution} from "../types/Structs.sol";

/**
 * @dev ExecLib is a helper library for execution
 */
library ExecLib {
    error ExecutionFailed();

    event TryExecuteUnsuccessful(uint256 batchExecutionindex, bytes result);

    function execute(ExecMode execMode, bytes calldata executionCalldata)
        internal
        returns (bytes[] memory returnData)
    {
        (CallType callType, ExecType execType,,) = decode(execMode);

        // check if calltype is batch or single
        if (callType == CALLTYPE_BATCH) {
            // destructure executionCallData according to batched exec
            Execution[] calldata executions = decodeBatch(executionCalldata);
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) returnData = execute(executions);
            else if (execType == EXECTYPE_TRY) returnData = tryExecute(executions);
            else revert("Unsupported");
        } else if (callType == CALLTYPE_SINGLE) {
            // destructure executionCallData according to single exec
            (address target, uint256 value, bytes calldata callData) = decodeSingle(executionCalldata);
            returnData = new bytes[](1);
            bool success;
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) {
                returnData[0] = execute(target, value, callData);
            } else if (execType == EXECTYPE_TRY) {
                (success, returnData[0]) = tryExecute(target, value, callData);
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else {
                revert("Unsupported");
            }
        } else if (callType == CALLTYPE_DELEGATECALL) {
            returnData = new bytes[](1);
            address delegate = address(bytes20(executionCalldata[0:20]));
            bytes calldata callData = executionCalldata[20:];
            bool success;
            (success, returnData[0]) = executeDelegatecall(delegate, callData);
            if (execType == EXECTYPE_TRY) {
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else if (execType == EXECTYPE_DEFAULT) {
                if (!success) revert("Delegatecall failed");
            } else {
                revert("Unsupported");
            }
        } else {
            revert("Unsupported");
        }
    }

    function execute(Execution[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);

        for (uint256 i; i < length; i++) {
            Execution calldata _exec = executions[i];
            result[i] = execute(_exec.target, _exec.value, _exec.callData);
        }
    }

    function tryExecute(Execution[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);

        for (uint256 i; i < length; i++) {
            Execution calldata _exec = executions[i];
            bool success;
            (success, result[i]) = tryExecute(_exec.target, _exec.value, _exec.callData);
            if (!success) emit TryExecuteUnsuccessful(i, result[i]);
        }
    }

    function execute(address target, uint256 value, bytes calldata callData) internal returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            if iszero(call(gas(), target, value, result, callData.length, codesize(), 0x00)) {
                // Bubble up the revert if the call reverts.
                returndatacopy(result, 0x00, returndatasize())
                revert(result, returndatasize())
            }
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function tryExecute(address target, uint256 value, bytes calldata callData)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            success := call(gas(), target, value, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    /// @dev Execute a delegatecall with `delegate` on this account.
    function executeDelegatecall(address delegate, bytes calldata callData)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            // Forwards the `data` to `delegate` via delegatecall.
            success := delegatecall(gas(), delegate, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function decode(ExecMode mode)
        internal
        pure
        returns (CallType _calltype, ExecType _execType, ExecModeSelector _modeSelector, ExecModePayload _modePayload)
    {
        assembly {
            _calltype := mode
            _execType := shl(8, mode)
            _modeSelector := shl(48, mode)
            _modePayload := shl(80, mode)
        }
    }

    function encode(CallType callType, ExecType execType, ExecModeSelector mode, ExecModePayload payload)
        internal
        pure
        returns (ExecMode)
    {
        return ExecMode.wrap(
            bytes32(abi.encodePacked(callType, execType, bytes4(0), ExecModeSelector.unwrap(mode), payload))
        );
    }

    function encodeSimpleBatch() internal pure returns (ExecMode mode) {
        mode = encode(CALLTYPE_BATCH, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0x00));
    }

    function encodeSimpleSingle() internal pure returns (ExecMode mode) {
        mode = encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, EXEC_MODE_DEFAULT, ExecModePayload.wrap(0x00));
    }

    function getCallType(ExecMode mode) internal pure returns (CallType calltype) {
        assembly {
            calltype := mode
        }
    }

    function decodeBatch(bytes calldata callData) internal pure returns (Execution[] calldata executionBatch) {
        /*
         * Batch Call Calldata Layout
         * Offset (in bytes)    | Length (in bytes) | Contents
         * 0x0                  | 0x4               | bytes4 function selector
        *  0x4                  | -                 |
        abi.encode(IERC7579Execution.Execution[])
         */
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let dataPointer := add(callData.offset, calldataload(callData.offset))

            // Extract the ERC7579 Executions
            executionBatch.offset := add(dataPointer, 32)
            executionBatch.length := calldataload(dataPointer)
        }
    }

    function encodeBatch(Execution[] memory executions) internal pure returns (bytes memory callData) {
        callData = abi.encode(executions);
    }

    function decodeSingle(bytes calldata executionCalldata)
        internal
        pure
        returns (address target, uint256 value, bytes calldata callData)
    {
        target = address(bytes20(executionCalldata[0:20]));
        value = uint256(bytes32(executionCalldata[20:52]));
        callData = executionCalldata[52:];
    }

    function encodeSingle(address target, uint256 value, bytes memory callData)
        internal
        pure
        returns (bytes memory userOpCalldata)
    {
        userOpCalldata = abi.encodePacked(target, value, callData);
    }

    function doFallback2771Static(address fallbackHandler) internal view returns (bool success, bytes memory result) {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            // Add 20 bytes for the address appended add the end
            success := staticcall(gas(), fallbackHandler, calldataPtr, add(calldatasize(), 20), 0, 0)

            result := mload(0x40)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function doFallback2771Call(address target) internal returns (bool success, bytes memory result) {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            // Add 20 bytes for the address appended add the end
            success := call(gas(), target, 0, calldataPtr, add(calldatasize(), 20), 0, 0)

            result := mload(0x40)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }
}

// ===================================================================================================
// FILE: src/utils/ModuleLib.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 41aafdda4e1dc02d1844e84d3b7461566e35eda07f635fa5973fc1849c5d2315)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ExcessivelySafeCall} from "ExcessivelySafeCall/ExcessivelySafeCall.sol";
import {IModule} from "../interfaces/IERC7579Modules.sol";

library ModuleLib {
    event ModuleUninstallResult(address module, bool result);

    function uninstallModule(address module, bytes memory deinitData) internal returns (bool result) {
        (result,) = ExcessivelySafeCall.excessivelySafeCall(
            module, gasleft(), 0, 0, abi.encodeWithSelector(IModule.onUninstall.selector, deinitData)
        );
        emit ModuleUninstallResult(module, result);
    }
}

// ===================================================================================================
// FILE: src/types/Constants.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 a1ba2b1df22f6c1afe77c2115f0098fed577165a57e85485bdcedf29f4f6a651)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {CallType, ExecType, ExecModeSelector} from "./Types.sol";
import {PassFlag, ValidationMode, ValidationType} from "./Types.sol";
import {ValidationData} from "./Types.sol";

// --- ERC7579 calltypes ---
// Default CallType
CallType constant CALLTYPE_SINGLE = CallType.wrap(0x00);
// Batched CallType
CallType constant CALLTYPE_BATCH = CallType.wrap(0x01);
CallType constant CALLTYPE_STATIC = CallType.wrap(0xFE);
// @dev Implementing delegatecall is OPTIONAL!
// implement delegatecall with extreme care.
CallType constant CALLTYPE_DELEGATECALL = CallType.wrap(0xFF);

// --- ERC7579 exectypes ---
// @dev default behavior is to revert on failure
// To allow very simple accounts to use mode encoding, the default behavior is to revert on failure
// Since this is value 0x00, no additional encoding is required for simple accounts
ExecType constant EXECTYPE_DEFAULT = ExecType.wrap(0x00);
// @dev account may elect to change execution behavior. For example "try exec" / "allow fail"
ExecType constant EXECTYPE_TRY = ExecType.wrap(0x01);

// --- ERC7579 mode selector ---
ExecModeSelector constant EXEC_MODE_DEFAULT = ExecModeSelector.wrap(bytes4(0x00000000));

// --- Kernel permission skip flags ---
PassFlag constant SKIP_USEROP = PassFlag.wrap(0x0001);
PassFlag constant SKIP_SIGNATURE = PassFlag.wrap(0x0002);

// --- Kernel validation modes ---
ValidationMode constant VALIDATION_MODE_DEFAULT = ValidationMode.wrap(0x00);
ValidationMode constant VALIDATION_MODE_ENABLE = ValidationMode.wrap(0x01);
ValidationMode constant VALIDATION_MODE_INSTALL = ValidationMode.wrap(0x02);

// --- Kernel validation types ---
ValidationType constant VALIDATION_TYPE_ROOT = ValidationType.wrap(0x00);
ValidationType constant VALIDATION_TYPE_VALIDATOR = ValidationType.wrap(0x01);
ValidationType constant VALIDATION_TYPE_PERMISSION = ValidationType.wrap(0x02);

// --- storage slots ---
// bytes32(uint256(keccak256('kernel.v3.selector')) - 1)
bytes32 constant SELECTOR_MANAGER_STORAGE_SLOT = 0x7c341349a4360fdd5d5bc07e69f325dc6aaea3eb018b3e0ea7e53cc0bb0d6f3b;
// bytes32(uint256(keccak256('kernel.v3.executor')) - 1)
bytes32 constant EXECUTOR_MANAGER_STORAGE_SLOT = 0x1bbee3173dbdc223633258c9f337a0fff8115f206d302bea0ed3eac003b68b86;
// bytes32(uint256(keccak256('kernel.v3.hook')) - 1)
bytes32 constant HOOK_MANAGER_STORAGE_SLOT = 0x4605d5f70bb605094b2e761eccdc27bed9a362d8612792676bf3fb9b12832ffc;
// bytes32(uint256(keccak256('kernel.v3.validation')) - 1)
bytes32 constant VALIDATION_MANAGER_STORAGE_SLOT = 0x7bcaa2ced2a71450ed5a9a1b4848e8e5206dbc3f06011e595f7f55428cc6f84f;
bytes32 constant ERC1967_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

// --- Kernel validation nonce incremental size limit ---
uint32 constant MAX_NONCE_INCREMENT_SIZE = 10;

// -- EIP712 type hash ---
bytes32 constant ENABLE_TYPE_HASH = 0xb17ab1224aca0d4255ef8161acaf2ac121b8faa32a4b2258c912cc5f8308c505;
bytes32 constant KERNEL_WRAPPER_TYPE_HASH = 0x1547321c374afde8a591d972a084b071c594c275e36724931ff96c25f2999c83;

// --- ERC constants ---
// ERC4337 constants
uint256 constant SIG_VALIDATION_FAILED_UINT = 1;
uint256 constant SIG_VALIDATION_SUCCESS_UINT = 0;
ValidationData constant SIG_VALIDATION_FAILED = ValidationData.wrap(SIG_VALIDATION_FAILED_UINT);

// ERC-1271 constants
bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;
bytes4 constant ERC1271_INVALID = 0xffffffff;

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_HOOK = 4;
uint256 constant MODULE_TYPE_POLICY = 5;
uint256 constant MODULE_TYPE_SIGNER = 6;

// ===================================================================================================
// FILE: src/types/Types.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 990e1e32f5252ac3383ea6a3cd73f672a35e6ea9b5ef3af2a1218d70a349ebf5)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

// Custom type for improved developer experience
type ExecMode is bytes32;

type CallType is bytes1;

type ExecType is bytes1;

type ExecModeSelector is bytes4;

type ExecModePayload is bytes22;

using {eqModeSelector as ==} for ExecModeSelector global;
using {eqCallType as ==} for CallType global;
using {notEqCallType as !=} for CallType global;
using {eqExecType as ==} for ExecType global;

function eqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) == CallType.unwrap(b);
}

function notEqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) != CallType.unwrap(b);
}

function eqExecType(ExecType a, ExecType b) pure returns (bool) {
    return ExecType.unwrap(a) == ExecType.unwrap(b);
}

function eqModeSelector(ExecModeSelector a, ExecModeSelector b) pure returns (bool) {
    return ExecModeSelector.unwrap(a) == ExecModeSelector.unwrap(b);
}

type ValidationMode is bytes1;

type ValidationId is bytes21;

type ValidationType is bytes1;

type PermissionId is bytes4;

type PolicyData is bytes22; // 2bytes for flag on skip, 20 bytes for validator address

type PassFlag is bytes2;

using {vModeEqual as ==} for ValidationMode global;
using {vTypeEqual as ==} for ValidationType global;
using {vIdentifierEqual as ==} for ValidationId global;
using {vModeNotEqual as !=} for ValidationMode global;
using {vTypeNotEqual as !=} for ValidationType global;
using {vIdentifierNotEqual as !=} for ValidationId global;

// nonce = uint192(key) + nonce
// key = mode + (vtype + validationDataWithoutType) + 2bytes parallelNonceKey
// key = 0x00 + 0x00 + 0x000 .. 00 + 0x0000
// key = 0x00 + 0x01 + 0x1234...ff + 0x0000
// key = 0x00 + 0x02 + ( ) + 0x000

function vModeEqual(ValidationMode a, ValidationMode b) pure returns (bool) {
    return ValidationMode.unwrap(a) == ValidationMode.unwrap(b);
}

function vModeNotEqual(ValidationMode a, ValidationMode b) pure returns (bool) {
    return ValidationMode.unwrap(a) != ValidationMode.unwrap(b);
}

function vTypeEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) == ValidationType.unwrap(b);
}

function vTypeNotEqual(ValidationType a, ValidationType b) pure returns (bool) {
    return ValidationType.unwrap(a) != ValidationType.unwrap(b);
}

function vIdentifierEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) == ValidationId.unwrap(b);
}

function vIdentifierNotEqual(ValidationId a, ValidationId b) pure returns (bool) {
    return ValidationId.unwrap(a) != ValidationId.unwrap(b);
}

type ValidationData is uint256;

type ValidAfter is uint48;

type ValidUntil is uint48;

function getValidationResult(ValidationData validationData) pure returns (address result) {
    assembly {
        result := validationData
    }
}

function packValidationData(ValidAfter validAfter, ValidUntil validUntil) pure returns (uint256) {
    return uint256(ValidAfter.unwrap(validAfter)) << 208 | uint256(ValidUntil.unwrap(validUntil)) << 160;
}

function parseValidationData(uint256 validationData)
    pure
    returns (ValidAfter validAfter, ValidUntil validUntil, address result)
{
    assembly {
        result := validationData
        validUntil := and(shr(160, validationData), 0xffffffffffff)
        switch iszero(validUntil)
        case 1 { validUntil := 0xffffffffffff }
        validAfter := shr(208, validationData)
    }
}

// ===================================================================================================
// FILE: src/interfaces/IERC7579Modules.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 9b23dc3afba5c65484fce3553fed0b12e77202195694db257932b4b98c8aeb58)
// ===================================================================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {PackedUserOperation} from "./PackedUserOperation.sol";

interface IModule {
    error AlreadyInitialized(address smartAccount);
    error NotInitialized(address smartAccount);

    /**
     * @dev This function is called by the smart account during installation of the module
     * @param data arbitrary data that may be required on the module during `onInstall`
     * initialization
     *
     * MUST revert on error (i.e. if module is already enabled)
     */
    function onInstall(bytes calldata data) external payable;

    /**
     * @dev This function is called by the smart account during uninstallation of the module
     * @param data arbitrary data that may be required on the module during `onUninstall`
     * de-initialization
     *
     * MUST revert on error
     */
    function onUninstall(bytes calldata data) external payable;

    /**
     * @dev Returns boolean value if module is a certain type
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     *
     * MUST return true if the module is of the given type and false otherwise
     */
    function isModuleType(uint256 moduleTypeId) external view returns (bool);

    /**
     * @dev Returns if the module was already initialized for a provided smartaccount
     */
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    error InvalidTargetAddress(address target);

    /**
     * @dev Validates a transaction on behalf of the account.
     *         This function is intended to be called by the MSA during the ERC-4337 validation phase
     *         Note: solely relying on bytes32 hash and signature is not sufficient for some
     * validation implementations (i.e. SessionKeys often need access to userOp.calldata)
     * @param userOp The user operation to be validated. The userOp MUST NOT contain any metadata.
     * The MSA MUST clean up the userOp before sending it to the validator.
     * @param userOpHash The hash of the user operation to be validated
     * @return return value according to ERC-4337
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        returns (uint256);

    /**
     * Validator can be used for ERC-1271 validation
     */
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}

interface IExecutor is IModule {}

interface IHook is IModule {
    function preCheck(address msgSender, uint256 msgValue, bytes calldata msgData)
        external
        payable
        returns (bytes memory hookData);

    function postCheck(bytes calldata hookData) external payable;
}

interface IFallback is IModule {}

interface IPolicy is IModule {
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp) external payable returns (uint256);
    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (uint256);
}

interface ISigner is IModule {
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        returns (uint256);
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4);
}

// ===================================================================================================
// FILE: src/interfaces/PackedUserOperation.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 da71298af29edd1d470f4ab120e6725b82bef18c30c71ef08a28980af9ef7c0f)
// ===================================================================================================
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.5;

/**
 * User Operation struct
 * @param sender                - The sender account of this request.
 * @param nonce                 - Unique value the sender uses to verify it is not a replay.
 * @param initCode              - If set, the account contract will be created by this constructor/
 * @param callData              - The method call to execute on this account.
 * @param accountGasLimits      - Packed gas limits for validateUserOp and gas limit passed to the callData method call.
 * @param preVerificationGas    - Gas not calculated by the handleOps method, but added to the gas paid.
 *                                Covers batch overhead.
 * @param gasFees                - packed gas fields maxFeePerGas and maxPriorityFeePerGas - Same as EIP-1559 gas parameter.
 * @param paymasterAndData      - If set, this field holds the paymaster address, verification gas limit, postOp gas limit and paymaster-specific extra data
 *                                The paymaster will pay for the transaction instead of the sender.
 * @param signature             - Sender-verified signature over the entire request, the EntryPoint address and the chain ID.
 */
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees; //maxPriorityFee and maxFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

// ===================================================================================================
// FILE: src/factory/KernelFactory.sol  @ 03f7f5cf5871cda0070e4223f196f5b577f6cde2  (sha256 a21b7f24a4b847e257b9bffbb724f558ff13e04d2be274eeabcb2b9b6b400aae)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {LibClone} from "solady/utils/LibClone.sol";

contract KernelFactory {
    error InitializeError();

    address public immutable implementation;

    constructor(address _impl) {
        implementation = _impl;
    }

    function createAccount(bytes calldata data, bytes32 salt) public payable returns (address) {
        bytes32 actualSalt = keccak256(abi.encodePacked(data, salt));
        (bool alreadyDeployed, address account) =
            LibClone.createDeterministicERC1967(msg.value, implementation, actualSalt);
        if (!alreadyDeployed) {
            (bool success,) = account.call(data);
            if (!success) {
                revert InitializeError();
            }
        }
        return account;
    }

    function getAddress(bytes calldata data, bytes32 salt) public view virtual returns (address) {
        bytes32 actualSalt = keccak256(abi.encodePacked(data, salt));
        return LibClone.predictDeterministicAddressERC1967(implementation, actualSalt, address(this));
    }
}

// ###################################################################################################
// SECTION B - ECDSAValidator (user account root validator)
// ###################################################################################################
// ===================================================================================================
// FILE: src/validator/ECDSAValidator.sol  @ 8f7fd9946b9d351bb5be0428bf34c87bad7ed6c9  (sha256 f889ab378a9c47ed7e080ff5d6a2a1fc15f87324e2a4a99bb6903cdbd0b9457e)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants.sol";

struct ECDSAValidatorStorage {
    address owner;
}

contract ECDSAValidator is IValidator, IHook {
    event OwnerRegistered(address indexed kernel, address indexed owner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function onInstall(bytes calldata _data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        address owner = address(bytes20(_data[0:20]));
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerRegistered(msg.sender, owner);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete ecdsaValidatorStorage[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return ecdsaValidatorStorage[smartAccount].owner != address(0);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        bytes calldata sig = userOp.signature;
        if (owner == ECDSA.recover(userOpHash, sig)) {
            return SIG_VALIDATION_SUCCESS_UINT;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);
        address recovered = ECDSA.recover(ethHash, sig);
        if (owner != recovered) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        if (owner == ECDSA.recover(hash, sig)) {
            return ERC1271_MAGICVALUE;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.recover(ethHash, sig);
        if (owner != recovered) {
            return ERC1271_INVALID;
        }
        return ERC1271_MAGICVALUE;
    }

    function preCheck(address msgSender, uint256 value, bytes calldata)
        external
        payable
        override
        returns (bytes memory)
    {
        require(msgSender == ecdsaValidatorStorage[msg.sender].owner, "ECDSAValidator: sender is not owner");
        return hex"";
    }

    function postCheck(bytes calldata hookData) external payable override {}
}

// ###################################################################################################
// SECTION C - WeightedECDSAValidator (guardian account root validator) and the IERC7579Modules it compiled against
// ###################################################################################################
// ===================================================================================================
// FILE: src/validator/WeightedECDSAValidator.sol  @ 00dd9e46413b37f6a7da58f85e8d950c5762243c  (sha256 7e3068e25e48a1f823a248efe2673c10afe6bc68a3fb5bceaf8b9fea3168c5a8)
// ===================================================================================================
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../types/Types.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {IValidator} from "../interfaces/IERC7579Modules.sol";
import {
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK
} from "../types/Constants.sol";

struct WeightedECDSAValidatorStorage {
    uint24 totalWeight;
    uint24 threshold;
    uint48 delay;
    address firstGuardian;
}

struct GuardianStorage {
    uint24 weight;
    address nextGuardian;
}

enum ProposalStatus {
    Ongoing, // all proposal is ongoing by default
    Approved,
    Rejected,
    Executed
}

struct ProposalStorage {
    ProposalStatus status;
    ValidAfter validAfter;
}

enum VoteStatus {
    NA,
    Approved
}

struct VoteStorage {
    VoteStatus status;
}

contract WeightedECDSAValidator is EIP712, IValidator {
    mapping(address kernel => WeightedECDSAValidatorStorage) public weightedStorage;
    mapping(address guardian => mapping(address kernel => GuardianStorage)) public guardian;
    mapping(bytes32 callDataAndNonceHash => mapping(address kernel => ProposalStorage)) public proposalStatus;
    mapping(bytes32 callDataAndNonceHash => mapping(address guardian => mapping(address kernel => VoteStorage))) public
        voteStatus;

    event GuardianAdded(address indexed guardian, address indexed kernel, uint24 weight);
    event GuardianRemoved(address indexed guardian, address indexed kernel);

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("WeightedECDSAValidator", "0.0.3");
    }

    function _addGuardians(address[] memory _guardians, uint24[] memory _weights, address _kernel) internal {
        uint24 totalWeight = weightedStorage[_kernel].totalWeight;
        require(_guardians.length == _weights.length, "Length mismatch");
        uint160 prevGuardian = uint160(weightedStorage[_kernel].firstGuardian);
        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != _kernel, "Guardian cannot be self");
            require(_guardians[i] != address(0), "Guardian cannot be 0");
            require(_weights[i] != 0, "Weight cannot be 0");
            require(guardian[_guardians[i]][_kernel].weight == 0, "Guardian already enabled");
            require(uint160(_guardians[i]) < prevGuardian, "Guardians not sorted");
            guardian[_guardians[i]][_kernel] =
                GuardianStorage({weight: _weights[i], nextGuardian: weightedStorage[_kernel].firstGuardian});
            weightedStorage[_kernel].firstGuardian = _guardians[i];
            totalWeight += _weights[i];
            prevGuardian = uint160(_guardians[i]);
            emit GuardianAdded(_guardians[i], _kernel, _weights[i]);
        }
        weightedStorage[_kernel].totalWeight = totalWeight;
    }

    function onInstall(bytes calldata _data) external payable override {
        (address[] memory _guardians, uint24[] memory _weights, uint24 _threshold, uint48 _delay) =
            abi.decode(_data, (address[], uint24[], uint24, uint48));
        require(_guardians.length == _weights.length, "Length mismatch");
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        weightedStorage[msg.sender].firstGuardian = address(uint160(type(uint160).max));
        _addGuardians(_guardians, _weights, msg.sender);
        weightedStorage[msg.sender].delay = _delay;
        weightedStorage[msg.sender].threshold = _threshold;
        require(_threshold <= weightedStorage[msg.sender].totalWeight, "Threshold too high");
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        address currentGuardian = weightedStorage[msg.sender].firstGuardian;
        while (currentGuardian != address(uint160(type(uint160).max))) {
            address nextGuardian = guardian[currentGuardian][msg.sender].nextGuardian;
            emit GuardianRemoved(currentGuardian, msg.sender);
            delete guardian[currentGuardian][msg.sender];
            currentGuardian = nextGuardian;
        }
        delete weightedStorage[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return weightedStorage[smartAccount].totalWeight != 0;
    }

    function renew(address[] calldata _guardians, uint24[] calldata _weights, uint24 _threshold, uint48 _delay)
        external
        payable
    {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        address currentGuardian = weightedStorage[msg.sender].firstGuardian;
        while (currentGuardian != address(uint160(type(uint160).max))) {
            address nextGuardian = guardian[currentGuardian][msg.sender].nextGuardian;
            emit GuardianRemoved(currentGuardian, msg.sender);
            delete guardian[currentGuardian][msg.sender];
            currentGuardian = nextGuardian;
        }
        delete weightedStorage[msg.sender];
        require(_guardians.length == _weights.length, "Length mismatch");
        weightedStorage[msg.sender].firstGuardian = address(uint160(type(uint160).max));
        _addGuardians(_guardians, _weights, msg.sender);
        weightedStorage[msg.sender].delay = _delay;
        weightedStorage[msg.sender].threshold = _threshold;
    }

    function approve(bytes32 _callDataAndNonceHash, address _kernel) external {
        require(guardian[msg.sender][_kernel].weight != 0, "Guardian not enabled");
        require(weightedStorage[_kernel].threshold != 0, "Kernel not enabled");
        ProposalStorage storage proposal = proposalStatus[_callDataAndNonceHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        VoteStorage storage vote = voteStatus[_callDataAndNonceHash][msg.sender][_kernel];
        require(vote.status == VoteStatus.NA, "Already voted");
        vote.status = VoteStatus.Approved;
        (, bool isApproved) = getApproval(_kernel, _callDataAndNonceHash);
        if (isApproved) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function approveWithSig(bytes32 _callDataAndNonceHash, address _kernel, bytes calldata sigs) external {
        uint256 sigCount = sigs.length / 65;
        require(weightedStorage[_kernel].threshold != 0, "Kernel not enabled");
        ProposalStorage storage proposal = proposalStatus[_callDataAndNonceHash][_kernel];
        require(proposal.status == ProposalStatus.Ongoing, "Proposal not ongoing");
        for (uint256 i = 0; i < sigCount; i++) {
            address signer = ECDSA.recover(
                _hashTypedData(
                    keccak256(abi.encode(keccak256("Approve(bytes32 callDataAndNonceHash)"), _callDataAndNonceHash))
                ),
                sigs[i * 65:(i + 1) * 65]
            );
            VoteStorage storage vote = voteStatus[_callDataAndNonceHash][signer][_kernel];
            require(vote.status == VoteStatus.NA, "Already voted");
            vote.status = VoteStatus.Approved;
        }

        (, bool isApproved) = getApproval(_kernel, _callDataAndNonceHash);
        if (isApproved) {
            proposal.status = ProposalStatus.Approved;
            proposal.validAfter = ValidAfter.wrap(uint48(block.timestamp + weightedStorage[_kernel].delay));
        }
    }

    function veto(bytes32 _callDataAndNonceHash) external {
        ProposalStorage storage proposal = proposalStatus[_callDataAndNonceHash][msg.sender];
        require(
            proposal.status == ProposalStatus.Ongoing || proposal.status == ProposalStatus.Approved,
            "Proposal not ongoing"
        );
        proposal.status = ProposalStatus.Rejected;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        bytes32 callDataAndNonceHash = keccak256(abi.encode(userOp.sender, userOp.callData, userOp.nonce));
        ProposalStorage storage proposal = proposalStatus[callDataAndNonceHash][msg.sender];
        WeightedECDSAValidatorStorage storage strg = weightedStorage[msg.sender];
        if (strg.threshold == 0) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        (uint256 totalWeight, bool passed) = getApproval(msg.sender, callDataAndNonceHash);
        uint256 threshold = strg.threshold;
        if (proposal.status == ProposalStatus.Ongoing && !passed) {
            if (strg.delay != 0) {
                // if delay > 0, only allow proposal to be approved before execution
                return SIG_VALIDATION_FAILED_UINT;
            }
            bytes calldata sig = userOp.signature;
            // parse sig with 65 bytes
            uint256 sigCount = sig.length / 65;
            require(sigCount > 0, "No sig");
            address signer;
            VoteStorage storage vote;
            for (uint256 i = 0; i < sigCount - 1 && !passed; i++) {
                signer = ECDSA.recover(
                    _hashTypedData(
                        keccak256(abi.encode(keccak256("Approve(bytes32 callDataAndNonceHash)"), callDataAndNonceHash))
                    ),
                    sig[i * 65:(i + 1) * 65]
                );
                vote = voteStatus[callDataAndNonceHash][signer][msg.sender];
                if (vote.status != VoteStatus.NA) {
                    continue;
                } // skip if already voted
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
                if (totalWeight >= threshold) {
                    passed = true;
                }
            }
            // userOpHash verification for the last sig
            signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), sig[sig.length - 65:]);
            vote = voteStatus[callDataAndNonceHash][signer][msg.sender];
            if (vote.status == VoteStatus.NA) {
                vote.status = VoteStatus.Approved;
                totalWeight += guardian[signer][msg.sender].weight;
                if (totalWeight >= threshold) {
                    passed = true;
                }
            }
            proposal.status = ProposalStatus.Executed;
            if (passed && guardian[signer][msg.sender].weight != 0) {
                return packValidationData(ValidAfter.wrap(0), ValidUntil.wrap(0));
            }
            return SIG_VALIDATION_FAILED_UINT;
        } else if (proposal.status == ProposalStatus.Approved || passed) {
            if (userOp.paymasterAndData.length == 0 || address(bytes20(userOp.paymasterAndData[0:20])) == address(0)) {
                address signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), userOp.signature);
                if (guardian[signer][msg.sender].weight != 0) {
                    proposal.status = ProposalStatus.Executed;
                    return packValidationData(proposal.validAfter, ValidUntil.wrap(0));
                }
            } else {
                proposal.status = ProposalStatus.Executed;
                return packValidationData(proposal.validAfter, ValidUntil.wrap(0));
            }
        }
        return SIG_VALIDATION_FAILED_UINT;
    }

    function getApproval(address kernel, bytes32 hash) public view returns (uint256 approvals, bool passed) {
        WeightedECDSAValidatorStorage storage strg = weightedStorage[kernel];
        for (
            address currentGuardian = strg.firstGuardian;
            currentGuardian != address(0);
            currentGuardian = guardian[currentGuardian][kernel].nextGuardian
        ) {
            if (voteStatus[hash][currentGuardian][kernel].status == VoteStatus.Approved) {
                approvals += guardian[currentGuardian][kernel].weight;
            }
        }
        ProposalStorage storage proposal = proposalStatus[hash][kernel];
        if (proposal.status == ProposalStatus.Rejected) {
            passed = false;
        } else {
            passed = approvals >= strg.threshold;
        }
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata data) external view returns (bytes4) {
        WeightedECDSAValidatorStorage storage strg = weightedStorage[msg.sender];
        if (strg.threshold == 0) {
            return ERC1271_INVALID;
        }

        uint256 sigCount = data.length / 65;
        if (sigCount == 0) {
            return ERC1271_INVALID;
        }
        uint256 totalWeight = 0;
        address prevSigner = address(uint160(type(uint160).max));
        for (uint256 i = 0; i < sigCount; i++) {
            address signer = ECDSA.recover(hash, data[i * 65:(i + 1) * 65]);
            totalWeight += guardian[signer][msg.sender].weight;
            if (totalWeight >= strg.threshold) {
                return ERC1271_MAGICVALUE;
            }
            if (signer >= prevSigner) {
                return ERC1271_INVALID;
            }
            prevSigner = signer;
        }
        return ERC1271_INVALID;
    }
}

// ===================================================================================================
// FILE: src/interfaces/IERC7579Modules.sol  @ 00dd9e46413b37f6a7da58f85e8d950c5762243c  (sha256 9c3c1e8116884fee2c150527f0c5f075543526040e65f66708ca94eef9a3778d)
// ===================================================================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {PackedUserOperation} from "./PackedUserOperation.sol";

interface IModule {
    error AlreadyInitialized(address smartAccount);
    error NotInitialized(address smartAccount);

    /**
     * @dev This function is called by the smart account during installation of the module
     * @param data arbitrary data that may be required on the module during `onInstall`
     * initialization
     *
     * MUST revert on error (i.e. if module is already enabled)
     */
    function onInstall(bytes calldata data) external payable;

    /**
     * @dev This function is called by the smart account during uninstallation of the module
     * @param data arbitrary data that may be required on the module during `onUninstall`
     * de-initialization
     *
     * MUST revert on error
     */
    function onUninstall(bytes calldata data) external payable;

    /**
     * @dev Returns boolean value if module is a certain type
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     *
     * MUST return true if the module is of the given type and false otherwise
     */
    function isModuleType(uint256 moduleTypeId) external view returns (bool);

    /**
     * @dev Returns if the module was already initialized for a provided smartaccount
     */
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    error InvalidTargetAddress(address target);

    /**
     * @dev Validates a transaction on behalf of the account.
     *         This function is intended to be called by the MSA during the ERC-4337 validaton phase
     *         Note: solely relying on bytes32 hash and signature is not sufficient for some
     * validation implementations (i.e. SessionKeys often need access to userOp.calldata)
     * @param userOp The user operation to be validated. The userOp MUST NOT contain any metadata.
     * The MSA MUST clean up the userOp before sending it to the validator.
     * @param userOpHash The hash of the user operation to be validated
     * @return return value according to ERC-4337
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        returns (uint256);

    /**
     * Validator can be used for ERC-1271 validation
     */
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}

interface IExecutor is IModule {}

interface IHook is IModule {
    /**
     * @dev Called by the smart account before execution
     * @param msgSender the address that called the smart account
     * @param value the value that was sent to the smart account
     * @param msgData the data that was sent to the smart account
     *
     * MAY return arbitrary data in the `hookData` return value
     */
    function preCheck(address msgSender, uint256 value, bytes calldata msgData)
        external
        payable
        returns (bytes memory hookData);

    /**
     * @dev Called by the smart account after execution
     * @param hookData the data that was returned by the `preCheck` function
     * @param executionSuccess whether the execution(s) was (were) successful
     * @param executionReturn the return/revert data of the execution(s)
     *
     * MAY validate the `hookData` to validate transaction context of the `preCheck` function
     */
    function postCheck(bytes calldata hookData, bool executionSuccess, bytes calldata executionReturn)
        external
        payable;
}

interface IFallback is IModule {}

interface IPolicy is IModule {
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp) external payable returns (uint256);
    function checkSignaturePolicy(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (uint256);
}

interface ISigner is IModule {
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        returns (uint256);
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4);
}

