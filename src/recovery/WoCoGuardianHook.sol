// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WoCoGuardianHook
/// @notice ERC-7579 hook (module type 4) that pins WHICH guardian accounts may call a
///         Kernel's recovery route, with SET semantics and a real per-guardian revoke.
///
/// @dev WHY THIS EXISTS (WoCo-Event-App #164). ZeroDev's caller hook stores
///      `allowed[guardian][kernel]` and only ever ORs `true` into it: no revoke
///      entrypoint, and its `onUninstall` clears an init flag, not the mapping. Kernel
///      v3.1's selector uninstall (`SelectorManager._uninstallSelector`) discards the
///      hook without calling `onUninstall` at all. Net effect: a guardian once added
///      keeps account-takeover power forever, and "remove all backups, then add a new
///      one" silently resurrects every guardian the account ever had.
///
///      Kernel v3.1 makes a different hook the supported fix: `_installSelector`
///      overwrites `ss.hook` unconditionally, so pointing the `doRecovery` selector at
///      THIS contract leaves the old hook's storage unreachable, and `_installHook`
///      calls `onInstall` again whenever the 0xff flag is passed — i.e. re-installing is
///      the documented "replace the set" path.
///
///      HOW THE KERNEL CALLS IT. On a routed fallback call `Kernel.fallback()` runs
///      `hook.preCheck(msg.sender, msg.value, msg.data)` — so inside this contract
///      `msg.sender` is the ACCOUNT and `msgSender` is the original caller (the
///      guardian account). Every mutator below is likewise keyed by `msg.sender`: an
///      account can only ever edit its OWN set (the account calls us through its own
///      sudo-signed `execute`), and a stranger calling `setGuardians` configures a set
///      for an address nothing routes through. No owner, no admin, no upgrade path —
///      a permissionless singleton.
///
///      DELIBERATE DEVIATION from the ERC-7579 comment "onInstall MUST revert if the
///      module is already enabled": `onInstall` REPLACES the set. That is the whole
///      point (see above), it is what Kernel's 0xff re-install flag is for, and the
///      account is the only party that can trigger it.
///
///      Wire format: `onInstall(abi.encode(address[] guardians))` — identical to the
///      ZeroDev hook's, so an installing client only swaps the hook address.
contract WoCoGuardianHook {
    /// @dev ERC-7579 module type id for hooks.
    uint256 public constant MODULE_TYPE_HOOK = 4;
    /// @dev Bounds every loop below. Social recovery sets are small; this keeps a
    ///      replace/clear cheap and makes an unbounded-growth mistake impossible.
    uint256 public constant MAX_GUARDIANS = 32;

    struct GuardianSet {
        address[] list;
        /// @dev index in `list` + 1; 0 means "not a guardian". O(1) membership + swap-pop.
        mapping(address guardian => uint256) indexPlusOne;
    }

    mapping(address account => GuardianSet) private _sets;

    event GuardiansSet(address indexed account, address[] guardians);
    event GuardianAdded(address indexed account, address indexed guardian);
    event GuardianRevoked(address indexed account, address indexed guardian);
    event GuardiansCleared(address indexed account);

    error NotAGuardian(address account, address caller);
    error ZeroGuardian();
    error DuplicateGuardian(address guardian);
    error UnknownGuardian(address account, address guardian);
    error TooManyGuardians(uint256 count);

    // ------------------------------------------------------------------ ERC-7579

    /// @notice Kernel calls this on install (and on every 0xff-flagged re-install):
    ///         the set for `msg.sender` becomes exactly `guardians` — previous entries
    ///         are removed, not kept.
    function onInstall(bytes calldata data) external payable {
        address[] memory guardians = abi.decode(data, (address[]));
        _set(msg.sender, guardians);
    }

    /// @notice Clears the set for `msg.sender`. Kernel reaches this through
    ///         `uninstallModule(4, hook, data)`; the selector-route uninstall does NOT
    ///         call it — which is fine here, because a later install REPLACES the set.
    function onUninstall(bytes calldata) external payable {
        _clear(msg.sender);
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view returns (bool) {
        return _sets[account].list.length > 0;
    }

    /// @notice Kernel's pre-hook: refuse unless the original caller is in the
    ///         account's CURRENT set. Reads one slot; writes nothing; returns no context.
    function preCheck(address msgSender, uint256, bytes calldata) external payable returns (bytes memory) {
        if (_sets[msg.sender].indexPlusOne[msgSender] == 0) revert NotAGuardian(msg.sender, msgSender);
        return "";
    }

    function postCheck(bytes calldata) external payable {}

    // ----------------------------------------------- account-callable management

    /// @notice Replace the caller's set wholesale (same semantics as `onInstall`).
    function setGuardians(address[] calldata guardians) external {
        _set(msg.sender, guardians);
    }

    /// @notice Add one guardian to the caller's set. Reverts on zero, duplicate or cap
    ///         — an add that changed nothing must not look like one that did.
    function addGuardian(address guardian) external {
        _add(msg.sender, guardian);
        emit GuardianAdded(msg.sender, guardian);
    }

    /// @notice Remove one guardian from the caller's set. Reverts if it is not in the
    ///         set, for the same reason `addGuardian` does.
    function revokeGuardian(address guardian) external {
        GuardianSet storage s = _sets[msg.sender];
        uint256 idx = s.indexPlusOne[guardian];
        if (idx == 0) revert UnknownGuardian(msg.sender, guardian);
        uint256 lastIdx = s.list.length; // 1-based index of the last element
        if (idx != lastIdx) {
            address moved = s.list[lastIdx - 1];
            s.list[idx - 1] = moved;
            s.indexPlusOne[moved] = idx;
        }
        s.list.pop();
        delete s.indexPlusOne[guardian];
        emit GuardianRevoked(msg.sender, guardian);
    }

    /// @notice Remove every guardian from the caller's set.
    function clearGuardians() external {
        _clear(msg.sender);
    }

    // ------------------------------------------------------------------- views

    /// @notice The account's current guardian set — on-chain truth for the UI.
    function guardiansOf(address account) external view returns (address[] memory) {
        return _sets[account].list;
    }

    function isGuardian(address account, address guardian) external view returns (bool) {
        return _sets[account].indexPlusOne[guardian] != 0;
    }

    function guardianCount(address account) external view returns (uint256) {
        return _sets[account].list.length;
    }

    // ---------------------------------------------------------------- internal

    function _set(address account, address[] memory guardians) internal {
        if (guardians.length > MAX_GUARDIANS) revert TooManyGuardians(guardians.length);
        _clear(account);
        for (uint256 i; i < guardians.length; ++i) {
            _add(account, guardians[i]);
        }
        emit GuardiansSet(account, guardians);
    }

    function _add(address account, address guardian) internal {
        if (guardian == address(0)) revert ZeroGuardian();
        GuardianSet storage s = _sets[account];
        if (s.indexPlusOne[guardian] != 0) revert DuplicateGuardian(guardian);
        if (s.list.length >= MAX_GUARDIANS) revert TooManyGuardians(s.list.length + 1);
        s.list.push(guardian);
        s.indexPlusOne[guardian] = s.list.length;
    }

    function _clear(address account) internal {
        GuardianSet storage s = _sets[account];
        uint256 n = s.list.length;
        for (uint256 i; i < n; ++i) {
            delete s.indexPlusOne[s.list[i]];
        }
        delete s.list;
        emit GuardiansCleared(account);
    }
}
