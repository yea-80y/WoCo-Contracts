// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title WoCoEscrow
 * @notice Time-locked escrow for event ticket payments with fee capture and dispute resolution.
 *
 * Flow:
 *   1. Attendee calls payETH(eventId, organiser, releaseTime) — auto-creates escrow on first
 *      payment. Subsequent payments only need the eventId (organiser + releaseTime ignored).
 *   2. After releaseTime, organiser calls release(eventId) to withdraw funds minus 1.5% fee.
 *
 * Trust + disputes:
 *   - Any address can call flagEvent(eventId) once to raise a dispute (before releaseTime).
 *   - A disputed escrow blocks release() until the arbitrator resolves it.
 *   - resolveDispute(eventId, true, tokens) — event happened: clears dispute, organiser can release.
 *   - resolveDispute(eventId, false, tokens) — fraud: confiscates funds to feeRecipient (WoCo
 *     distributes refunds off-chain). Can be decentralised to a DAO later via setArbitrator().
 *
 * Fees:
 *   - 1.5% of released funds go to feeRecipient on every successful release().
 *   - Fee is taken from the organiser's proceeds; attendees pay the ticket price exactly.
 *
 * Design:
 *   - One escrow per event (keyed by keccak256 of eventId string)
 *   - Pull-payment pattern: organiser withdraws, contract never pushes
 *   - Supports ETH + any ERC-20 (designed for USDC)
 */

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract WoCoEscrow is ReentrancyGuard {
    struct Escrow {
        address organiser;
        uint256 releaseTime;
        uint256 ethBalance;
        bool exists;
        bool disputed;
        uint32 flagCount;
    }

    address public arbitrator;
    address public feeRecipient;

    uint256 public constant FEE_BASIS_POINTS = 150;       // 1.5%
    uint256 public constant BASIS_DENOMINATOR = 10_000;
    uint256 public constant MAX_TOKENS = 20;

    // eventId (keccak256 of string) => Escrow
    mapping(bytes32 => Escrow) public escrows;

    // eventId => token address => balance
    mapping(bytes32 => mapping(address => uint256)) public tokenBalances;

    // eventId => flagger address => has flagged (one flag per address)
    mapping(bytes32 => mapping(address => bool)) public hasFlagged;

    // eventId => payer address => ETH deposited
    mapping(bytes32 => mapping(address => uint256)) public ethDeposits;

    // eventId => payer address => token address => amount deposited
    mapping(bytes32 => mapping(address => mapping(address => uint256))) public tokenDeposits;

    // ── Events ────────────────────────────────────────────────────────────────

    event EscrowCreated(
        bytes32 indexed eventId,
        address indexed organiser,
        uint256 releaseTime
    );

    event PaymentReceived(
        bytes32 indexed eventId,
        address indexed payer,
        uint256 amount,
        address token  // address(0) for ETH
    );

    event FundsReleased(
        bytes32 indexed eventId,
        address indexed organiser,
        uint256 organiserAmount,
        uint256 feeAmount
    );

    event TokenReleased(
        bytes32 indexed eventId,
        address indexed organiser,
        address indexed token,
        uint256 organiserAmount,
        uint256 feeAmount
    );

    event EventFlagged(
        bytes32 indexed eventId,
        address indexed flagger,
        uint32 flagCount
    );

    event DisputeResolved(
        bytes32 indexed eventId,
        bool releasedToOrganiser
    );

    event ArbitratorChanged(
        address indexed oldArbitrator,
        address indexed newArbitrator
    );

    // ── Modifiers ─────────────────────────────────────────────────────────────

    modifier onlyOrganiser(bytes32 eventId) {
        require(escrows[eventId].organiser == msg.sender, "Not organiser");
        _;
    }

    modifier onlyArbitrator() {
        require(msg.sender == arbitrator, "Not arbitrator");
        _;
    }

    modifier escrowExists(bytes32 eventId) {
        require(escrows[eventId].exists, "Escrow does not exist");
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _arbitrator, address _feeRecipient) {
        require(_arbitrator != address(0), "Invalid arbitrator");
        require(_feeRecipient != address(0), "Invalid fee recipient");
        arbitrator = _arbitrator;
        feeRecipient = _feeRecipient;
    }

    // ── Payments ──────────────────────────────────────────────────────────────

    /**
     * @notice Pay ETH into an event's escrow.
     *         Auto-creates the escrow on the first payment.
     * @param eventId      keccak256 hash of the event ID string
     * @param organiser    Organiser address — only used if escrow doesn't exist yet
     * @param releaseTime  Unlock timestamp — only used if escrow doesn't exist yet
     */
    function payETH(
        bytes32 eventId,
        address organiser,
        uint256 releaseTime
    ) external payable {
        require(msg.value > 0, "Must send ETH");

        if (!escrows[eventId].exists) {
            require(organiser != address(0), "Organiser required on first payment");
            require(releaseTime > block.timestamp, "Release time must be in the future");
            escrows[eventId] = Escrow({
                organiser: organiser,
                releaseTime: releaseTime,
                ethBalance: 0,
                exists: true,
                disputed: false,
                flagCount: 0
            });
            emit EscrowCreated(eventId, organiser, releaseTime);
        }

        escrows[eventId].ethBalance += msg.value;
        ethDeposits[eventId][msg.sender] += msg.value;
        emit PaymentReceived(eventId, msg.sender, msg.value, address(0));
    }

    /**
     * @notice Pay an ERC-20 token (e.g. USDC) into an event's escrow.
     *         Auto-creates the escrow on the first payment.
     *         Caller must have approved this contract for `amount` tokens first.
     */
    function payToken(
        bytes32 eventId,
        address token,
        uint256 amount,
        address organiser,
        uint256 releaseTime
    ) external {
        require(amount > 0, "Amount must be > 0");
        require(token != address(0), "Use payETH for native ETH");

        if (!escrows[eventId].exists) {
            require(organiser != address(0), "Organiser required on first payment");
            require(releaseTime > block.timestamp, "Release time must be in the future");
            escrows[eventId] = Escrow({
                organiser: organiser,
                releaseTime: releaseTime,
                ethBalance: 0,
                exists: true,
                disputed: false,
                flagCount: 0
            });
            emit EscrowCreated(eventId, organiser, releaseTime);
        }

        bool ok = IERC20(token).transferFrom(msg.sender, address(this), amount);
        require(ok, "Token transfer failed");

        tokenBalances[eventId][token] += amount;
        tokenDeposits[eventId][msg.sender][token] += amount;
        emit PaymentReceived(eventId, msg.sender, amount, token);
    }

    // ── Dispute / flagging ────────────────────────────────────────────────────

    /**
     * @notice Flag an event as potentially fraudulent (event didn't happen).
     *         One flag per address. Any flag marks the escrow as disputed, blocking release.
     *         Can only be raised before the release window opens (i.e. before releaseTime).
     */
    function flagEvent(bytes32 eventId) external escrowExists(eventId) {
        require(block.timestamp < escrows[eventId].releaseTime, "Flag window has closed");
        require(!hasFlagged[eventId][msg.sender], "Already flagged");

        hasFlagged[eventId][msg.sender] = true;
        escrows[eventId].flagCount += 1;
        escrows[eventId].disputed = true;

        emit EventFlagged(eventId, msg.sender, escrows[eventId].flagCount);
    }

    /**
     * @notice Arbitrator resolves a dispute.
     * @param eventId        The disputed event
     * @param releaseFunds   true  = event happened, clear dispute so organiser can release normally.
     *                       false = fraud confirmed, confiscate all funds to feeRecipient.
     *                               WoCo distributes refunds to attendees off-chain.
     * @param tokens         ERC-20 token addresses to handle (empty for ETH-only events)
     */
    function resolveDispute(
        bytes32 eventId,
        bool releaseFunds,
        address[] calldata tokens
    ) external onlyArbitrator escrowExists(eventId) nonReentrant {
        require(escrows[eventId].disputed, "Not disputed");
        require(tokens.length <= MAX_TOKENS, "Too many tokens");

        escrows[eventId].disputed = false;
        escrows[eventId].flagCount = 0;

        if (releaseFunds) {
            // Event verified — organiser can now call release() normally
            emit DisputeResolved(eventId, true);
        } else {
            // Fraud — confiscate all funds to feeRecipient for off-chain distribution
            uint256 ethAmount = escrows[eventId].ethBalance;
            if (ethAmount > 0) {
                escrows[eventId].ethBalance = 0;
                (bool sent, ) = payable(feeRecipient).call{value: ethAmount}("");
                require(sent, "ETH confiscation failed");
            }
            for (uint256 i = 0; i < tokens.length; i++) {
                uint256 tokenAmount = tokenBalances[eventId][tokens[i]];
                if (tokenAmount > 0) {
                    tokenBalances[eventId][tokens[i]] = 0;
                    bool ok = IERC20(tokens[i]).transfer(feeRecipient, tokenAmount);
                    require(ok, "Token confiscation failed");
                }
            }
            emit DisputeResolved(eventId, false);
        }
    }

    // ── Release ───────────────────────────────────────────────────────────────

    /**
     * @notice Release all funds to the organiser.
     *         1.5% fee is deducted and sent to feeRecipient.
     * @param eventId  The event escrow to release
     * @param tokens   ERC-20 token addresses to release (pass empty for ETH only)
     */
    function release(
        bytes32 eventId,
        address[] calldata tokens
    ) external onlyOrganiser(eventId) escrowExists(eventId) nonReentrant {
        require(
            block.timestamp >= escrows[eventId].releaseTime,
            "Funds are still locked"
        );
        require(
            !escrows[eventId].disputed,
            "Escrow is disputed - awaiting arbitration"
        );
        require(tokens.length <= MAX_TOKENS, "Too many tokens");

        // Release ETH
        uint256 ethAmount = escrows[eventId].ethBalance;
        if (ethAmount > 0) {
            escrows[eventId].ethBalance = 0;
            uint256 feeAmount = (ethAmount * FEE_BASIS_POINTS) / BASIS_DENOMINATOR;
            uint256 organiserAmount = ethAmount - feeAmount;
            if (feeAmount > 0) {
                (bool feeSent, ) = payable(feeRecipient).call{value: feeAmount}("");
                require(feeSent, "Fee transfer failed");
            }
            (bool sent, ) = payable(msg.sender).call{value: organiserAmount}("");
            require(sent, "ETH transfer failed");
            emit FundsReleased(eventId, msg.sender, organiserAmount, feeAmount);
        }

        // Release ERC-20 tokens
        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 tokenAmount = tokenBalances[eventId][tokens[i]];
            if (tokenAmount > 0) {
                tokenBalances[eventId][tokens[i]] = 0;
                uint256 feeAmount = (tokenAmount * FEE_BASIS_POINTS) / BASIS_DENOMINATOR;
                uint256 organiserAmount = tokenAmount - feeAmount;
                if (feeAmount > 0) {
                    bool feeSent = IERC20(tokens[i]).transfer(feeRecipient, feeAmount);
                    require(feeSent, "Fee token transfer failed");
                }
                bool ok = IERC20(tokens[i]).transfer(msg.sender, organiserAmount);
                require(ok, "Token release failed");
                emit TokenReleased(eventId, msg.sender, tokens[i], organiserAmount, feeAmount);
            }
        }
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    /**
     * @notice Transfer arbitrator role to a new address (e.g. a DAO multisig).
     */
    function setArbitrator(address newArbitrator) external onlyArbitrator {
        require(newArbitrator != address(0), "Invalid arbitrator");
        emit ArbitratorChanged(arbitrator, newArbitrator);
        arbitrator = newArbitrator;
    }

    // ── View ──────────────────────────────────────────────────────────────────

    function getETHBalance(bytes32 eventId) external view returns (uint256) {
        return escrows[eventId].ethBalance;
    }

    function getTokenBalance(
        bytes32 eventId,
        address token
    ) external view returns (uint256) {
        return tokenBalances[eventId][token];
    }

    function getEscrowInfo(bytes32 eventId) external view returns (
        address organiser,
        uint256 releaseTime,
        uint256 ethBalance,
        bool exists,
        bool disputed,
        uint32 flagCount
    ) {
        Escrow storage e = escrows[eventId];
        return (e.organiser, e.releaseTime, e.ethBalance, e.exists, e.disputed, e.flagCount);
    }

    function getETHDeposit(bytes32 eventId, address payer) external view returns (uint256) {
        return ethDeposits[eventId][payer];
    }

    function getTokenDeposit(bytes32 eventId, address payer, address token) external view returns (uint256) {
        return tokenDeposits[eventId][payer][token];
    }
}
