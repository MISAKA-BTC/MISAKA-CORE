// ============================================================
// core/wallet/denomination.js — Auto-Denomination for Same-Amount Rings
//
// The consensus layer enforces same-amount rings: all UTXO members
// in a ring must have identical amounts. This module transparently
// splits arbitrary user amounts into standard denominations and
// constructs multi-input/output transactions.
//
// Users see: "Send 15.5 MISAKA" → single action
// Protocol sees: multiple same-amount-ring inputs/outputs
// ============================================================
'use strict';

const DenominationEngine = (() => {

  // ─── Standard Denominations (descending) ────────────
  // These are the "bills" of the MISAKA economy.
  // Each denomination has a large anonymity set (many UTXOs of same amount).
  const DENOMINATIONS = Object.freeze([
    1_000_000,  // 1M
    500_000,    // 500K
    100_000,    // 100K
    50_000,     // 50K
    10_000,     // 10K
    5_000,      // 5K
    1_000,      // 1K
    500,        // 500
    100,        // 100
    50,         // 50
    10,         // 10
    5,          // 5
    1,          // 1
  ]);

  // ─── Decompose: Split amount into denominations ─────
  /**
   * Decompose an arbitrary amount into standard denominations.
   *
   * @param {number} amount - Total amount to decompose
   * @returns {Array<{denomination: number, count: number}>}
   *
   * Example: decompose(15500) → [{1000, 1}, {500, 1}, {100, 5}]
   *          wait no: 15500 = 10000 + 5000 + 500
   */
  function decompose(amount) {
    if (amount <= 0) return [];
    let remaining = Math.floor(amount);
    const result = [];

    for (const denom of DENOMINATIONS) {
      if (remaining <= 0) break;
      const count = Math.floor(remaining / denom);
      if (count > 0) {
        result.push({ denomination: denom, count });
        remaining -= count * denom;
      }
    }

    // If there's a remainder (shouldn't happen with denomination=1)
    if (remaining > 0) {
      result.push({ denomination: 1, count: remaining });
    }

    return result;
  }

  // ─── Find Matching UTXOs ────────────────────────────
  /**
   * Find available UTXOs that match required denominations.
   *
   * @param {Array<{denomination, count}>} needed - Required denominations
   * @param {Array<{amount, txHash, outputIndex, ...}>} utxos - Available UTXOs
   * @returns {{matched: Array, missing: Array, change: Array}}
   */
  function matchUtxos(needed, utxos) {
    const available = [...utxos].filter(u => !u.spent);
    const matched = [];
    const missing = [];

    for (const { denomination, count } of needed) {
      // Find UTXOs of exactly this denomination
      let found = 0;
      for (let i = 0; i < available.length && found < count; i++) {
        if (available[i].amount === denomination) {
          matched.push({
            utxo: available[i],
            denomination,
          });
          available.splice(i, 1); // Remove from available
          i--;
          found++;
        }
      }

      if (found < count) {
        missing.push({ denomination, shortfall: count - found });
      }
    }

    return { matched, missing };
  }

  // ─── Pre-split: Create denomination UTXOs ───────────
  /**
   * When the user doesn't have exact denominations, create a
   * "pre-split" transaction that converts larger UTXOs into
   * the needed denominations.
   *
   * @param {number} amount - Desired send amount
   * @param {Array} utxos - Available UTXOs
   * @returns {{
   *   needsPresplit: boolean,
   *   presplitTx: object|null,
   *   sendPlan: Array<{denomination, count}>,
   * }}
   */
  function planTransaction(amount, utxos, fee = 10) {
    const needed = decompose(amount);
    const { matched, missing } = matchUtxos(needed, utxos);

    if (missing.length === 0) {
      // We have exact denominations — no pre-split needed
      return {
        needsPresplit: false,
        presplitTx: null,
        sendInputs: matched,
        sendPlan: needed,
        totalInputAmount: matched.reduce((s, m) => s + m.denomination, 0),
      };
    }

    // Need to pre-split: find a larger UTXO and break it down
    const totalNeeded = missing.reduce((s, m) => s + m.denomination * m.shortfall, 0);
    const availableForSplit = utxos
      .filter(u => !u.spent && !matched.some(m => m.utxo === u))
      .sort((a, b) => b.amount - a.amount); // Largest first

    // Find a UTXO large enough to cover the missing denominations + fee
    const splitSource = availableForSplit.find(u => u.amount >= totalNeeded + fee);

    if (!splitSource) {
      // Insufficient funds
      return {
        needsPresplit: false,
        presplitTx: null,
        sendInputs: matched,
        sendPlan: needed,
        error: `Insufficient funds: need ${totalNeeded + fee} more in matching denominations`,
        totalInputAmount: matched.reduce((s, m) => s + m.denomination, 0),
      };
    }

    // Build pre-split outputs
    const presplitOutputs = [];
    for (const { denomination, shortfall } of missing) {
      for (let i = 0; i < shortfall; i++) {
        presplitOutputs.push({ amount: denomination });
      }
    }

    // Change from the split
    const presplitTotal = presplitOutputs.reduce((s, o) => s + o.amount, 0);
    const change = splitSource.amount - presplitTotal - fee;
    if (change > 0) {
      // Find the best denomination for change
      const changeDenoms = decompose(change);
      for (const { denomination, count } of changeDenoms) {
        for (let i = 0; i < count; i++) {
          presplitOutputs.push({ amount: denomination });
        }
      }
    }

    return {
      needsPresplit: true,
      presplitTx: {
        inputs: [{ utxo: splitSource }],
        outputs: presplitOutputs,
        fee,
        description: `Pre-split: ${splitSource.amount} → [${presplitOutputs.map(o => o.amount).join(', ')}]`,
      },
      sendInputs: matched,
      sendPlan: needed,
      totalInputAmount: matched.reduce((s, m) => s + m.denomination, 0) + totalNeeded,
    };
  }

  // ─── Build Same-Amount Ring Inputs ──────────────────
  /**
   * For each input, find decoy UTXOs of the same denomination.
   *
   * @param {Array<{utxo, denomination}>} inputs - Real inputs
   * @param {Array} allUtxos - All known UTXOs (for decoys)
   * @param {number} ringSize - Desired ring size (default 4)
   * @returns {Array<{realInput, ringMembers}>}
   */
  function buildRings(inputs, allUtxos, ringSize = 4) {
    return inputs.map(({ utxo, denomination }) => {
      // Find decoys: same amount, different UTXO
      const decoys = allUtxos
        .filter(u => u.amount === denomination
          && u.txHash !== utxo.txHash
          && !u.spent)
        .slice(0, ringSize - 1);

      // Build ring: real input at random position
      const members = [...decoys];
      const realIndex = Math.floor(Math.random() * (members.length + 1));
      members.splice(realIndex, 0, utxo);

      return {
        realInput: utxo,
        realIndex,
        ringMembers: members.map(m => ({
          txHash: m.txHash,
          outputIndex: m.outputIndex,
          amount: m.amount,
        })),
        denomination,
        ringSize: members.length,
      };
    });
  }

  // ─── User-Facing: Plan a Send ──────────────────────
  /**
   * High-level function: plan a send transaction with auto-denomination.
   *
   * @param {number} amount - Amount to send
   * @param {string} recipient - Recipient address
   * @param {Array} myUtxos - Wallet's UTXOs
   * @param {Array} networkUtxos - Known network UTXOs (for decoys)
   * @param {number} fee - Transaction fee
   * @returns {object} Transaction plan
   */
  function planSend(amount, recipient, myUtxos, networkUtxos = [], fee = 10) {
    const plan = planTransaction(amount, myUtxos, fee);

    if (plan.error) {
      return { success: false, error: plan.error };
    }

    const rings = buildRings(plan.sendInputs, [...myUtxos, ...networkUtxos]);

    return {
      success: true,
      needsPresplit: plan.needsPresplit,
      presplitTx: plan.presplitTx,
      sendTx: {
        inputs: rings,
        outputs: [
          { address: recipient, amount },
        ],
        fee,
        totalInput: plan.totalInputAmount,
      },
      denominations: plan.sendPlan,
      summary: `Send ${amount} MISAKA → ${recipient} (${plan.sendPlan.map(d => `${d.count}×${d.denomination}`).join(' + ')})`,
    };
  }

  return Object.freeze({
    DENOMINATIONS,
    decompose,
    matchUtxos,
    planTransaction,
    buildRings,
    planSend,
  });
})();

if (typeof self !== 'undefined') self.DenominationEngine = DenominationEngine;
