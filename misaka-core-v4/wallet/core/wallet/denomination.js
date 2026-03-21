// ============================================================
// core/wallet/denomination.js — Confidential Transaction Builder (ZKP v4)
//
// ARCHITECTURE CHANGE (v4):
// Same-amount ring logic has been completely removed. In the ZKP
// architecture, amounts are hidden inside BDLOP commitments, so there
// is NO need for denomination splitting or same-amount matching.
//
// The wallet now constructs transactions by:
// 1. Selecting UTXOs to cover the desired amount (coin selection)
// 2. Creating confidential outputs with BDLOP commitments
// 3. Generating a ZKP (UnifiedMembershipProof) for each input
//
// No decoy selection happens here — that's handled server-side
// via the global anonymity set (Merkle tree over all UTXOs).
// ============================================================
'use strict';

const ConfidentialTxBuilder = (() => {

  // ─── Coin Selection (replaces denomination decomposition) ─────
  /**
   * Select UTXOs to cover a target amount + fee.
   *
   * Uses a simple largest-first strategy. In the ZKP model, there is
   * NO constraint that UTXOs must match specific denominations —
   * any combination that covers the total is valid.
   *
   * @param {number} targetAmount - Amount to send
   * @param {number} fee - Transaction fee
   * @param {Array<{amount: number, txHash: string, outputIndex: number, spent: boolean}>} utxos
   * @returns {{selected: Array, totalInput: number, change: number} | {error: string}}
   */
  function selectCoins(targetAmount, fee, utxos) {
    if (targetAmount <= 0) {
      return { error: 'Amount must be positive' };
    }

    const needed = targetAmount + fee;
    const available = utxos
      .filter(u => !u.spent)
      .sort((a, b) => b.amount - a.amount); // Largest first

    const selected = [];
    let accumulated = 0;

    for (const utxo of available) {
      if (accumulated >= needed) break;
      selected.push(utxo);
      accumulated += utxo.amount;
    }

    if (accumulated < needed) {
      return {
        error: `Insufficient funds: have ${accumulated}, need ${needed}`,
      };
    }

    return {
      selected,
      totalInput: accumulated,
      change: accumulated - needed,
    };
  }

  // ─── Build Confidential Outputs ─────────────────────────
  /**
   * Create output descriptors for a confidential transaction.
   *
   * In the ZKP model, each output carries:
   * - A BDLOP commitment to the amount (opaque to verifiers)
   * - A blinding factor (encrypted to recipient via CT stealth)
   * - A range proof (proves amount ∈ [0, 2^64))
   *
   * Actual commitment/proof generation happens in Rust (misaka-pqc).
   * This function only prepares the high-level structure.
   *
   * @param {number} sendAmount - Amount to send to recipient
   * @param {string} recipientAddress - Recipient's stealth address
   * @param {number} change - Change amount (back to sender)
   * @param {string} changeAddress - Sender's change address
   * @returns {Array<{address: string, amount: number, isChange: boolean}>}
   */
  function buildOutputs(sendAmount, recipientAddress, change, changeAddress) {
    const outputs = [
      { address: recipientAddress, amount: sendAmount, isChange: false },
    ];

    if (change > 0) {
      outputs.push({
        address: changeAddress,
        amount: change,
        isChange: true,
      });
    }

    return outputs;
  }

  // ─── Generate Secure Random Index ──────────────────────
  /**
   * Generate a cryptographically secure random integer in [0, max).
   *
   * SECURITY FIX (Task 3.1): Replaced Math.random() with Web Crypto API.
   *
   * @param {number} max - Exclusive upper bound
   * @returns {number}
   */
  function secureRandomIndex(max) {
    if (max <= 0) return 0;
    if (max === 1) return 0;

    // Use Web Crypto API (browser) or Node.js crypto
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const arr = new Uint32Array(1);
      crypto.getRandomValues(arr);
      return arr[0] % max;
    }

    // Node.js fallback
    if (typeof require !== 'undefined') {
      try {
        const nodeCrypto = require('crypto');
        return nodeCrypto.randomInt(0, max);
      } catch (_) {
        // Fall through to error
      }
    }

    throw new Error(
      'CSPRNG unavailable: neither Web Crypto API nor Node.js crypto found'
    );
  }

  // ─── Plan a Confidential Send ──────────────────────────
  /**
   * High-level function: plan a confidential transaction.
   *
   * @param {number} amount - Amount to send
   * @param {string} recipient - Recipient stealth address
   * @param {string} changeAddress - Sender's change address
   * @param {Array} myUtxos - Wallet's UTXOs
   * @param {number} fee - Transaction fee
   * @returns {object} Transaction plan
   */
  function planSend(amount, recipient, changeAddress, myUtxos, fee = 10) {
    const coinSelection = selectCoins(amount, fee, myUtxos);

    if (coinSelection.error) {
      return { success: false, error: coinSelection.error };
    }

    const outputs = buildOutputs(
      amount,
      recipient,
      coinSelection.change,
      changeAddress
    );

    return {
      success: true,
      // No pre-split needed — ZKP model handles arbitrary amounts
      needsPresplit: false,
      presplitTx: null,
      sendTx: {
        inputs: coinSelection.selected.map(utxo => ({
          txHash: utxo.txHash,
          outputIndex: utxo.outputIndex,
          amount: utxo.amount,
          // Anonymity set selection is done server-side via global Merkle tree
          // The wallet requests the anonymity set from the node RPC
        })),
        outputs,
        fee,
        totalInput: coinSelection.totalInput,
      },
      summary: `Send ${amount} MISAKA → ${recipient} (${coinSelection.selected.length} inputs, ${outputs.length} outputs, fee=${fee})`,
    };
  }

  return Object.freeze({
    selectCoins,
    buildOutputs,
    secureRandomIndex,
    planSend,
  });
})();

if (typeof self !== 'undefined') self.ConfidentialTxBuilder = ConfidentialTxBuilder;
