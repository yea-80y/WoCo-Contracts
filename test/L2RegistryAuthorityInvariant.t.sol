// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";

/**
 * The per-TRANSACTION authority invariant (Fable 950 design consult §8).
 *
 * Why the other campaigns missed audits 948 / 949 / 950: their handlers make
 * ONE registry call per action, and a Foundry handler action is one
 * transaction. Those findings are properties of a transaction — who had
 * authority when it began versus what changed by the time it ended — reached
 * by composing calls that are each individually allowed. Here one handler
 * action is one transaction in which ONE caller makes up to four registry
 * calls back to back, each chosen from the live state just before it (so the
 * composition is adaptive, as an attacker's would be), and the registry's
 * state is snapshotted before and after.
 *
 *   PROPERTY. For every name, if the caller had no authority over it when the
 *   transaction began, the name ends the transaction with the same holder and
 *   the same record version. "Came back to its holder" must mean unchanged.
 *
 *   AUTHORITY at the start of the transaction, over a name n:
 *     - the caller held n, or any name above n (the holder of a name may take
 *       and release the names beneath it, one level at a time, so within one
 *       transaction it can reach its whole subtree — the owner's fusion);
 *     - the caller is the registry admin (adminTransfer reaches every name);
 *     - the caller is the registrar and n's top-level name did not exist (a
 *       registrar may mint beneath the base name, and what it mints to itself
 *       is then its own);
 *     - a holder's release signature for n, relayed by the caller, which
 *       authorises exactly one thing: n's burn — after which the label is
 *       free, and whoever may mint it (for a top-level name, the registrar)
 *       may mint it again in the same transaction.
 *   Nothing else — in particular no ERC-721 approval, which v2.2 refuses.
 *
 * Run against v2.1 (7dc5638) with the rules oracle and the approval check
 * switched off, so that only this property could fail, it failed in about a
 * second: the admin had made the registrar an operator, and the registrar then
 * took a name the admin held — the audit 950 root. Under v2.2 it holds, and it
 * PINS the class: any later edit that lets a non-authority path reach
 * `_update` fails the campaign.
 *
 * The handler also predicts every call's outcome from the rules and the live
 * state, and a disagreement in EITHER direction is recorded — a refused
 * legitimate call is as much a defect as an accepted illegitimate one.
 *
 * NOT COVERED: the admin handover (the admin is fixed; the unit suites and
 * the 950 regressions pin the epoch), and ERC-1271 / ERC-6492 signers (the
 * signature suites pin them). Names are drawn from a closed universe of eleven
 * — the base name, two beneath it, two beneath each of those, one beneath each
 * of those — so every node the campaign can create is one it checks.
 */
contract AuthorityHandler is Test {
    L2Registry public immutable registry;
    address public immutable admin;
    address public immutable registrarActor;
    bytes32 public immutable baseNode;

    uint256 internal constant N = 11;
    uint256 internal constant MAX_STEPS = 4;

    bytes32[N] internal node;
    uint256[N] internal parentIdx; // index of the name directly above; base's is itself
    string[N] internal labelOf;

    uint256[4] internal keys;
    address[4] internal people;

    struct Snap {
        address holder;
        uint64 version;
    }

    // ── Witnesses (Foundry checks these after EVERY run) ────────────────────
    uint256 public composedTxs;
    uint256 public multiChangeTxs; // two or more ACCEPTED state changes in one transaction
    uint256 public acceptedCalls;
    uint256 public refusedCalls;
    uint256 public nonAuthorityAttempts; // calls on a name the caller had no authority over
    uint256 public refusedTakes; // a non-holder's attempt to move a name to itself
    uint256 public refusedDelegations;
    uint256 public ancestorActions; // accepted parentTransfer, or release by the parent's holder
    uint256 public signedReleases;
    uint256 public batchCreates; // createSubnode with a non-empty batch, accepted

    bool public oracleDisagreed;
    string public oracleDisagreement;
    bool public authorityViolated;
    string public authorityViolation;

    constructor(L2Registry registry_, address admin_, address registrar_) {
        registry = registry_;
        admin = admin_;
        registrarActor = registrar_;
        baseNode = registry_.baseNode();

        keys = [uint256(0xA11CE), 0xB0B, 0xCA401, 0xDA5E];
        for (uint256 i; i < 4; ++i) people[i] = vm.addr(keys[i]);

        node[0] = baseNode;
        parentIdx[0] = 0;
        string[2] memory l1 = ["alpha", "bravo"];
        string[2] memory l2 = ["xray", "yank"];
        uint256 k = 1;
        for (uint256 a; a < 2; ++a) _add(k++, 0, l1[a]);
        for (uint256 p = 1; p <= 2; ++p) {
            for (uint256 b; b < 2; ++b) _add(k++, p, l2[b]);
        }
        for (uint256 p = 3; p <= 6; ++p) _add(k++, p, "zulu");
    }

    function _add(uint256 i, uint256 parent, string memory label) internal {
        node[i] = keccak256(abi.encodePacked(node[parent], keccak256(bytes(label))));
        parentIdx[i] = parent;
        labelOf[i] = label;
    }

    function nodeAt(uint256 i) external view returns (bytes32) {
        return node[i];
    }

    function parentOfIdx(uint256 i) external view returns (uint256) {
        return parentIdx[i];
    }

    function everyone() external view returns (address[] memory all) {
        all = new address[](6);
        for (uint256 i; i < 4; ++i) all[i] = people[i];
        all[4] = admin;
        all[5] = registrarActor;
    }

    // ── The one action: a transaction of up to four calls by one caller ────

    /// ONE handler call = ONE transaction. A focus name and a caller in a
    /// ROLE relative to it (consult §8: holder, parent's holder, admin,
    /// registrar, stranger), then up to four calls on that name, its children
    /// and its parent, each chosen from the live state.
    function composed(uint256 seed, uint8 k, uint8 roleSeed, bool grant) external {
        Snap[N] memory before;
        for (uint256 i; i < N; ++i) before[i] = _snap(i);

        uint256 f = _focus(seed, before);
        address caller = _role(f, roleSeed, seed, before);
        // Half the transactions follow a named composition (`_template`),
        // half are free: up to four calls chosen at random from the live state.
        bool scripted = k >= 128;
        uint256 t = seed % TEMPLATES;
        uint256 steps = scripted ? _templateLength(t) : uint256(k) % MAX_STEPS + 1;
        composedTxs++;

        // A holder's release signature the caller may relay: made before the
        // transaction, over the name as it was then.
        Grant memory g;
        if (grant) g = _makeGrant(f, before);

        grantBurned = false;
        uint256 changes;
        for (uint256 s; s < steps; ++s) {
            uint256 r = uint256(keccak256(abi.encode(seed, s)));
            Plan memory plan;
            if (scripted) plan = _template(t, s);
            if (_step(caller, r, g, before, f, s == 0, plan)) changes++;
        }
        if (changes >= 2) multiChangeTxs++;

        for (uint256 i; i < N; ++i) {
            Snap memory a = _snap(i);
            if (_hadAuthority(caller, i, before)) continue;
            if (g.live && g.idx == i && grantBurned) {
                // The one signed burn, and a re-mint of the freed label by
                // whoever may mint it: beneath the base name, the registrar.
                if (a.holder == address(0) || (parentIdx[i] == 0 && caller == registrarActor)) continue;
            }
            if (a.holder != before[i].holder) _violate("a non-authority moved or burned a name", i);
            else if (a.version != before[i].version) _violate("a name came back to its holder with its records gone", i);
        }
    }

    struct Grant {
        bool live;
        uint256 idx;
        address signer;
        uint256 expiration;
        bytes sig;
    }

    /// A person holding a name with nothing beneath it — the focus when it
    /// qualifies, else the next that does — signs a release of it.
    function _makeGrant(uint256 f, Snap[N] memory before) internal view returns (Grant memory g) {
        uint256 i = type(uint256).max;
        for (uint256 d; d < N; ++d) {
            uint256 j = (f + d) % N;
            if (j != 0 && _keyOf(before[j].holder) >= 0 && registry.childCount(node[j]) == 0) {
                i = j;
                break;
            }
        }
        if (i == type(uint256).max) return g;
        address h = before[i].holder;
        int256 key = _keyOf(h);
        g.idx = i;
        g.signer = h;
        g.expiration = block.timestamp + 10 minutes;
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(uint256(key), registry.releaseDigest(node[i], g.expiration));
        g.sig = abi.encodePacked(rr, ss, v);
        g.live = true;
    }

    /// One registry call, as the rules see it before it is made.
    struct Call {
        bool forced;
        uint256 kind;
        uint256 i;
        bytes32 n;
        address owner_;
        address to;
        address caller;
        uint256 r;
        bytes data;
        bool expected;
    }

    /// One call, chosen from the live state. Returns whether it was accepted
    /// AND changed a holder or a version.
    function _step(
        address caller,
        uint256 r,
        Grant memory g,
        Snap[N] memory before,
        uint256 f,
        bool first,
        Plan memory plan
    ) internal returns (bool) {
        Call memory c;
        c.caller = caller;
        c.r = r;
        c.forced = plan.forced;
        if (plan.forced) {
            c.kind = plan.kind;
            c.i = _resolveTarget(plan.target, f, r);
            c.to = plan.toSpec == TO_CALLER ? caller
                : plan.toSpec == TO_START_HOLDER ? before[f].holder : _pick(uint8(r >> 24));
            if (c.to == address(0)) c.to = _pick(uint8(r >> 24));
        } else {
            c.kind = KIND[r % 16];
            // A transaction holding a grant opens with it half the time — then
            // composes whatever follows around a burn it is allowed to make.
            if (first && g.live && (r >> 96) % 2 == 0) c.kind = 8;
            // Burns outpace mints, and an empty registry tests nothing: while
            // fewer names live than the run started with, a free step creates
            // half the time.
            else if (registry.totalSupply() < 7 && (r >> 100) % 2 == 0) c.kind = 5;
            c.i = _target(f, r);
            c.to = ((r >> 16) % 2 == 0) ? caller : _pick(uint8(r >> 24));
        }
        c.n = node[c.i];
        c.owner_ = registry.owner(c.n);
        if (!_hadAuthority(caller, c.i, before)) nonAuthorityAttempts++;

        if (c.kind == 0 || c.kind == 1 || c.kind == 11) _planMove(c);
        else if (c.kind == 2 || c.kind == 3 || c.kind == 4) _planTakeBack(c);
        else if (c.kind == 5) _planCreate(c);
        else if (c.kind == 6 || c.kind == 7) _planRecords(c);
        else if (c.kind == 8) _planSigned(c, g);
        else _planDelegation(c);
        lastIdx = c.i;

        Snap[N] memory pre;
        for (uint256 j; j < N; ++j) pre[j] = _snap(j);

        vm.prank(caller);
        (bool ok,) = address(registry).call(c.data);
        _account(c, g, ok);
        if (!ok) return false;
        for (uint256 j; j < N; ++j) {
            Snap memory post = _snap(j);
            if (post.holder != pre[j].holder || post.version != pre[j].version) return true;
        }
        return false;
    }

    /// transferFrom / safeTransferFrom; kind 11 is the take — to the caller,
    /// from the holder, the first move of every 950 shape.
    function _planMove(Call memory c) internal view {
        address from = (c.forced || c.kind == 11 || (c.r >> 32) % 4 != 0) ? c.owner_ : _pick(uint8(c.r >> 40));
        if (c.kind == 11) c.to = c.caller;
        c.data = c.kind == 1
            ? abi.encodeWithSignature("safeTransferFrom(address,address,uint256)", from, c.to, uint256(c.n))
            : abi.encodeWithSignature("transferFrom(address,address,uint256)", from, c.to, uint256(c.n));
        c.expected = c.owner_ != address(0) && c.caller == c.owner_ && from == c.owner_ && c.i != 0;
    }

    /// release, parentTransfer, adminTransfer.
    function _planTakeBack(Call memory c) internal view {
        address ph = _parentHolderLive(c.i);
        if (c.kind == 2) {
            c.data = abi.encodeCall(L2Registry.release, (c.n));
            c.expected = c.i != 0 && c.owner_ != address(0)
                && (c.caller == c.owner_ || (ph != address(0) && c.caller == ph)) && registry.childCount(c.n) == 0;
        } else if (c.kind == 3) {
            c.data = abi.encodeCall(L2Registry.parentTransfer, (c.n, c.to));
            c.expected = c.owner_ != address(0) && ph != address(0) && c.caller == ph && c.to != c.owner_;
        } else {
            c.data = abi.encodeCall(L2Registry.adminTransfer, (c.n, c.to));
            c.expected = c.caller == admin && c.i != 0 && c.owner_ != address(0) && c.to != c.owner_;
        }
    }

    /// createSubnode, with no batch, a record write in it, or a release in it
    /// (which the post-batch guard must always refuse). Aimed at a name that
    /// does not exist yet, beneath the target, when there is one.
    function _planCreate(Call memory c) internal {
        c.i = _creatable(c.i, c.r, c.caller);
        c.n = node[c.i];
        bytes32 parent = node[parentIdx[c.i]];
        uint256 variant = (c.r >> 56) % 4; // 0 none, 1 and 3 a record write, 2 a release
        if (variant == 3) variant = 1;
        bytes[] memory batch = new bytes[](variant == 0 ? 0 : 1);
        if (variant == 1) batch[0] = abi.encodeWithSignature("setContenthash(bytes32,bytes)", c.n, _value(c.r));
        if (variant == 2) batch[0] = abi.encodeCall(L2Registry.release, (c.n));
        c.data = abi.encodeCall(L2Registry.createSubnode, (parent, labelOf[c.i], c.to, batch));
        address parentHolder = registry.owner(parent);
        bool mayCreate = parentHolder == c.caller || (parentIdx[c.i] == 0 && c.caller == registrarActor);
        bool batchOk = variant == 0 || (variant == 1 && (c.caller == registrarActor || c.caller == c.to));
        c.expected = mayCreate && parentHolder != address(0) && registry.owner(c.n) == address(0) && batchOk;
        if (c.expected && variant != 0) batchCreates++;
    }

    /// clearRecords (the holder only) and a record write (the holder, or the
    /// registrar for any name but the base name).
    function _planRecords(Call memory c) internal view {
        if (c.kind == 6) {
            c.data = abi.encodeCall(L2Registry.clearRecords, (c.n));
            c.expected = c.owner_ != address(0) && c.caller == c.owner_;
        } else {
            c.data = abi.encodeWithSignature("setContenthash(bytes32,bytes)", c.n, _value(c.r));
            c.expected = c.owner_ != address(0) && (c.caller == c.owner_ || (c.caller == registrarActor && c.i != 0));
        }
    }

    /// releaseWithSignature: relaying the grant (the tx-start holder's
    /// signature) or the caller's own signature.
    function _planSigned(Call memory c, Grant memory g) internal view {
        uint256 exp;
        address signer;
        bytes memory sig;
        if (g.live && (c.r >> 64) % 4 != 0) {
            c.i = g.idx;
            c.n = node[c.i];
            c.owner_ = registry.owner(c.n);
            (exp, signer, sig) = (g.expiration, g.signer, g.sig);
        } else {
            exp = block.timestamp + 10 minutes;
            signer = c.caller;
            int256 key = _keyOf(c.caller);
            if (key >= 0 && c.owner_ != address(0) && c.i != 0) {
                (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(uint256(key), registry.releaseDigest(c.n, exp));
                sig = abi.encodePacked(rr, ss, v);
            } else {
                sig = hex"1271";
            }
        }
        c.data = abi.encodeCall(L2Registry.releaseWithSignature, (c.n, exp, signer, sig));
        bool sigValid = sig.length == 65 && _signedNow(c.n, exp, signer, sig);
        c.expected = c.i != 0 && c.owner_ != address(0) && signer == c.owner_ && sigValid
            && registry.childCount(c.n) == 0;
    }

    /// approve / setApprovalForAll: refused, always, for everyone.
    function _planDelegation(Call memory c) internal pure {
        c.data = c.kind == 9
            ? abi.encodeWithSignature("approve(address,uint256)", c.to, uint256(c.n))
            : abi.encodeWithSignature("setApprovalForAll(address,bool)", c.to, (c.r >> 72) % 2 == 0);
        c.expected = false;
    }

    function _account(Call memory c, Grant memory g, bool ok) internal {
        if (ok != c.expected) _disagree(c.kind, ok);
        if (ok) {
            acceptedCalls++;
            if (c.kind == 8 && g.live && c.i == g.idx) {
                signedReleases++;
                grantBurned = true;
            }
            if (c.kind == 3 || (c.kind == 2 && c.caller != c.owner_)) ancestorActions++;
        } else {
            refusedCalls++;
            if (c.kind == 9 || c.kind == 10) refusedDelegations++;
            if (c.kind == 11 && c.caller != c.owner_) refusedTakes++;
        }
    }

    // ── Compositions ───────────────────────────────────────────────────────

    /// One scripted step: a call kind (as `KIND`), whom it targets and whom it
    /// sends to. Unforced = chosen at random.
    struct Plan {
        bool forced;
        uint256 kind;
        uint256 target;
        uint256 toSpec;
    }

    uint256 internal constant T_FOCUS = 0;
    uint256 internal constant T_CHILD = 1;
    uint256 internal constant T_LAST = 2;
    uint256 internal constant TO_CALLER = 0;
    uint256 internal constant TO_START_HOLDER = 1;
    uint256 internal constant TO_RANDOM = 2;
    uint256 internal constant TEMPLATES = 8;

    /// The index the previous step acted on, for "then act on that".
    uint256 internal lastIdx;

    /// Whether this transaction's grant was used: the signed burn happened.
    bool internal grantBurned;

    /// Named compositions. Played by a caller without authority they are the
    /// audit 950 shapes and every call must be refused; played by a holder, a
    /// parent's holder, the admin or the registrar they are legitimate and
    /// must land. The property must hold either way.
    ///   0  take the focus, then release it                       (950 High)
    ///   1  take the focus, move a child to self, release it,
    ///      hand the focus back                                   (950 High)
    ///   2  move the focus to self, then back to its holder       (950 Medium)
    ///   3  write a record, then move the name
    ///   4  move a child to someone, then release it              (the fusion)
    ///   5  create beneath the focus, write it, release it
    ///   6  adminTransfer the focus away, then back
    ///   7  write a record, then clear the records
    function _template(uint256 t, uint256 s) internal pure returns (Plan memory) {
        uint8[3][4] memory st;
        if (t == 0) { st[0] = [11, 0, 0]; st[1] = [2, 0, 0]; }
        else if (t == 1) { st[0] = [11, 0, 0]; st[1] = [3, 1, 0]; st[2] = [2, 2, 0]; st[3] = [0, 0, 1]; }
        else if (t == 2) { st[0] = [0, 0, 0]; st[1] = [0, 0, 1]; }
        else if (t == 3) { st[0] = [7, 0, 0]; st[1] = [0, 0, 2]; }
        else if (t == 4) { st[0] = [3, 1, 2]; st[1] = [2, 2, 0]; }
        else if (t == 5) { st[0] = [5, 0, 0]; st[1] = [7, 2, 0]; st[2] = [2, 2, 0]; }
        else if (t == 6) { st[0] = [4, 0, 2]; st[1] = [4, 0, 1]; }
        else { st[0] = [7, 0, 0]; st[1] = [6, 0, 0]; }
        return Plan(true, st[s][0], st[s][1], st[s][2]);
    }

    function _templateLength(uint256 t) internal pure returns (uint256) {
        if (t == 1) return 4;
        if (t == 5) return 3;
        return 2;
    }

    function _resolveTarget(uint256 spec, uint256 f, uint256 r) internal view returns (uint256) {
        if (spec == T_LAST) return lastIdx;
        if (spec == T_CHILD) {
            // A LIVE child when there is one, so the parent doors are reached.
            for (uint256 d; d < N; ++d) {
                uint256 j = (r + d) % N;
                if (j != 0 && parentIdx[j] == f && registry.owner(node[j]) != address(0)) return j;
            }
            uint256 child = _childOf(f, r);
            return child == type(uint256).max ? f : child;
        }
        return f;
    }

    // ── Choosing: focus, role, target ──────────────────────────────────────

    /// Weighted toward calls that change state, so that transactions compose.
    uint8[16] internal KIND = [0, 1, 11, 2, 3, 3, 3, 4, 5, 5, 5, 6, 7, 8, 9, 10];

    /// A live name three times in four, when one exists; otherwise any. Half
    /// of those prefer a name below the top level, where the parent doors are
    /// (beneath the base name the parent's door is the admin's instead).
    function _focus(uint256 seed, Snap[N] memory before) internal view returns (uint256) {
        uint256 start = seed % N;
        if ((seed >> 8) % 4 != 0 && (seed >> 12) % 2 == 0) {
            for (uint256 d; d < N; ++d) {
                uint256 i = (start + d) % N;
                if (i != 0 && parentIdx[i] != 0 && before[i].holder != address(0)) return i;
            }
        }
        if ((seed >> 8) % 4 != 0) {
            for (uint256 d; d < N; ++d) {
                uint256 i = (start + d) % N;
                if (i != 0 && before[i].holder != address(0)) return i;
            }
        }
        return start;
    }

    function _role(uint256 f, uint8 roleSeed, uint256 seed, Snap[N] memory before) internal view returns (address) {
        uint256 role = uint256(roleSeed) % 5;
        if (role == 0 && before[f].holder != address(0)) return before[f].holder;
        if (role == 1 && f != 0) {
            address ph = before[parentIdx[f]].holder;
            if (ph != address(0)) return ph;
        }
        if (role == 2) return admin;
        if (role == 3) return registrarActor;
        // A stranger: a person holding neither the focus nor anything above it.
        for (uint256 d; d < 4; ++d) {
            address p = people[(seed >> 16 + d) % 4];
            if (!_holdsAncestorOrSelf(p, f, before)) return p;
        }
        return people[seed % 4];
    }

    /// The focus, one of its children, its parent, or any name.
    function _target(uint256 f, uint256 r) internal view returns (uint256) {
        uint256 which = (r >> 8) % 4;
        if (which == 0) return f;
        if (which == 1) {
            uint256 child = _childOf(f, r >> 80);
            return child == type(uint256).max ? f : child;
        }
        if (which == 2) return parentIdx[f];
        return (r >> 88) % N;
    }

    /// A name that does not exist yet: beneath `i`; else beneath a name the
    /// caller holds (so the tree regrows below the top level, where the parent
    /// doors are); else `i` itself; else any.
    function _creatable(uint256 i, uint256 r, address caller) internal view returns (uint256) {
        for (uint256 d; d < N; ++d) {
            uint256 j = (r + d) % N;
            if (j != 0 && parentIdx[j] == i && registry.owner(node[j]) == address(0)) return j;
        }
        for (uint256 d; d < N; ++d) {
            uint256 j = (r + d) % N;
            if (j != 0 && registry.owner(node[j]) == address(0) && registry.owner(node[parentIdx[j]]) == caller) {
                return j;
            }
        }
        if (i != 0 && registry.owner(node[i]) == address(0)) return i;
        for (uint256 d; d < N; ++d) {
            uint256 j = (r + d) % N;
            if (j != 0 && registry.owner(node[j]) == address(0)) return j;
        }
        return 1 + r % (N - 1);
    }

    function _childOf(uint256 f, uint256 r) internal view returns (uint256) {
        for (uint256 d; d < N; ++d) {
            uint256 j = (r + d) % N;
            if (j != 0 && parentIdx[j] == f) return j;
        }
        return type(uint256).max;
    }

    function _holdsAncestorOrSelf(address who, uint256 i, Snap[N] memory before) internal view returns (bool) {
        uint256 m = i;
        while (true) {
            if (before[m].holder == who) return true;
            if (m == 0) return false;
            m = parentIdx[m];
        }
        return false;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    function _hadAuthority(address caller, uint256 i, Snap[N] memory before) internal view returns (bool) {
        if (caller == admin) return true;
        uint256 m = i;
        while (true) {
            if (before[m].holder == caller) return true;
            if (m == 0) break;
            if (parentIdx[m] == 0) {
                // m is a top-level name: a registrar may mint it while it does not exist.
                if (caller == registrarActor && before[m].holder == address(0)) return true;
            }
            m = parentIdx[m];
            if (m == 0) break; // the base name's holder is the admin, handled above
        }
        return false;
    }

    function _parentHolderLive(uint256 i) internal view returns (address) {
        if (i == 0 || parentIdx[i] == 0) return address(0);
        return registry.owner(node[parentIdx[i]]);
    }

    function _signedNow(bytes32 n, uint256 exp, address signer, bytes memory sig) internal view returns (bool) {
        if (registry.owner(n) == address(0)) return false;
        (address rec, ECDSA_Err err,) = _tryRecover(registry.releaseDigest(n, exp), sig);
        return err == ECDSA_Err.None && rec == signer;
    }

    enum ECDSA_Err {
        None,
        Bad
    }

    function _tryRecover(bytes32 digest, bytes memory sig) internal pure returns (address, ECDSA_Err, bytes32) {
        bytes32 rr;
        bytes32 ss;
        uint8 v;
        assembly {
            rr := mload(add(sig, 0x20))
            ss := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        address rec = ecrecover(digest, v, rr, ss);
        return (rec, rec == address(0) ? ECDSA_Err.Bad : ECDSA_Err.None, bytes32(0));
    }

    function _snap(uint256 i) internal view returns (Snap memory) {
        return Snap(registry.owner(node[i]), registry.recordVersions(node[i]));
    }

    function _pick(uint8 seed) internal view returns (address) {
        uint256 k = uint256(seed) % 6;
        if (k < 4) return people[k];
        return k == 4 ? admin : registrarActor;
    }

    function _keyOf(address who) internal view returns (int256) {
        for (uint256 i; i < 4; ++i) if (people[i] == who) return int256(keys[i]);
        return -1;
    }

    function _value(uint256 r) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"e40101fa011b20", keccak256(abi.encode(r)));
    }

    function _disagree(uint256 kind, bool accepted) internal {
        if (oracleDisagreed) return;
        oracleDisagreed = true;
        oracleDisagreement = string.concat(
            "call kind ", vm.toString(kind), accepted ? " was accepted against the rules" : " was refused against the rules"
        );
    }

    function _violate(string memory what, uint256 i) internal {
        if (authorityViolated) return;
        authorityViolated = true;
        authorityViolation = string.concat(what, " (name index ", vm.toString(i), ")");
    }
}

contract L2RegistryAuthorityInvariantTest is Test {
    L2Registry registry;
    AuthorityHandler handler;

    function setUp() public {
        address admin = makeAddr("admin");
        address registrarActor = makeAddr("registrar");
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        vm.prank(admin);
        registry.addRegistrar(registrarActor);

        handler = new AuthorityHandler(registry, admin, registrarActor);

        // Every run starts from a tree three levels deep, parents and children
        // held by DIFFERENT people — the organiser / stallholder shape — so
        // the parent doors and the takes are reachable from the first call.
        address[] memory p = handler.everyone();
        bytes[] memory none = new bytes[](0);
        bytes32 base = registry.baseNode();
        vm.startPrank(registrarActor);
        bytes32 alpha = registry.createSubnode(base, "alpha", p[0], none);
        bytes32 bravo = registry.createSubnode(base, "bravo", p[1], none);
        vm.stopPrank();
        vm.startPrank(p[0]);
        bytes32 ax = registry.createSubnode(alpha, "xray", p[2], none);
        registry.createSubnode(alpha, "yank", p[3], none);
        vm.stopPrank();
        vm.prank(p[1]);
        registry.createSubnode(bravo, "xray", p[0], none);
        vm.prank(p[2]);
        registry.createSubnode(ax, "zulu", p[1], none);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = AuthorityHandler.composed.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// ONE campaign, three properties — each invariant function runs a whole
    /// campaign of its own, and this one is the slowest in the suite.
    ///   1. No transaction changed the holder or the record version of a name
    ///      its caller had no authority over when it began.
    ///   2. Every call inside those transactions went the way the rules say,
    ///      in both directions.
    ///   3. No approval exists, whatever the transactions attempted.
    /// forge-config: default.invariant.runs = 64
    function invariant_NoTransactionReachesANameItsCallerHadNoAuthorityOver() public view {
        assertFalse(handler.authorityViolated(), handler.authorityViolation());
        assertFalse(handler.oracleDisagreed(), handler.oracleDisagreement());
        _assertNoApproval();
    }

    function _assertNoApproval() internal view {
        for (uint256 i; i < 11; ++i) {
            bytes32 n = handler.nodeAt(i);
            if (registry.owner(n) != address(0)) {
                assertEq(registry.getApproved(uint256(n)), address(0), "a per-token approval exists");
            }
        }
        address[] memory all = handler.everyone();
        for (uint256 a; a < all.length; ++a) {
            for (uint256 b; b < all.length; ++b) {
                assertFalse(registry.isApprovedForAll(all[a], all[b]), "an operator approval exists");
            }
        }
    }

    /// Coverage: each run must have composed, attempted what it must refuse,
    /// and landed what it must allow — including the legitimate multi-step
    /// shapes the property must NOT flag.
    function afterInvariant() public view {
        assertGt(handler.composedTxs(), 0, "campaign never composed a transaction");
        assertGt(handler.multiChangeTxs(), 0, "campaign never landed two state changes in one transaction");
        assertGt(handler.acceptedCalls(), 0, "campaign never landed a call");
        assertGt(handler.refusedCalls(), 0, "campaign never had a call refused");
        assertGt(handler.nonAuthorityAttempts(), 0, "campaign never had a non-authority try");
        assertGt(handler.refusedTakes(), 0, "campaign never had a take refused");
        assertGt(handler.refusedDelegations(), 0, "campaign never had an approval refused");
        assertGt(handler.ancestorActions(), 0, "campaign never had a parent's holder act on a child");
        assertGt(handler.signedReleases(), 0, "campaign never relayed a holder's signed release");
        assertGt(handler.batchCreates(), 0, "campaign never created a name with a batch");
    }
}
