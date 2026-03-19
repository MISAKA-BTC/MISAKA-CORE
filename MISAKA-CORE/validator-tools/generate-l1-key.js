#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
//  MISAKA Network — L1 Validator Key Generator
//  
//  ML-DSA-65 (FIPS 204 / Dilithium3) keypair generation.
//  Post-quantum secure. No ECC (Ed25519/secp256k1).
//
//  Usage:
//    node generate-l1-key.js
//    node generate-l1-key.js --name my-validator
//    node generate-l1-key.js --output ./keys
//
//  Output:
//    l1-secret-key.json  — SECRET. Keep on VPS only. Never share.
//    l1-public-key.json  — Safe to share. Submit to misakastake.com.
//
//  Flow:
//    1. Run this script on your VPS
//    2. Copy the "L1 Public Key" (64 hex chars)
//    3. Paste into misakastake.com → Register Validator
//    4. Start node: node start-validator.js --key ./l1-secret-key.json
// ═══════════════════════════════════════════════════════════════

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';

// ─── CLI引数パース ──────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(name, defaultVal) {
  const idx = args.indexOf(`--${name}`);
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1];
  return defaultVal;
}

const nodeName = getArg('name', `misaka-validator-${Date.now().toString(36)}`);
const outputDir = resolve(getArg('output', '.'));

// ─── バナー ─────────────────────────────────────────────────

console.log('');
console.log('╔═══════════════════════════════════════════════════════════╗');
console.log('║  MISAKA Network — L1 Validator Key Generator             ║');
console.log('║  Algorithm: ML-DSA-65 (FIPS 204 / Post-Quantum)         ║');
console.log('╚═══════════════════════════════════════════════════════════╝');
console.log('');

// ─── 鍵生成 ─────────────────────────────────────────────────

console.log('[1/4] Generating ML-DSA-65 keypair...');
const startTime = performance.now();

const keypair = ml_dsa65.keygen();
const publicKey = keypair.publicKey;   // 1952 bytes
const secretKey = keypair.secretKey;   // 4032 bytes

const elapsed = (performance.now() - startTime).toFixed(0);
console.log(`       Done (${elapsed}ms)`);
console.log(`       Public key:  ${publicKey.length} bytes (ML-DSA-65)`);
console.log(`       Secret key:  ${secretKey.length} bytes (ML-DSA-65)`);
console.log('');

// ─── 鍵導出 ─────────────────────────────────────────────────

console.log('[2/4] Deriving validator identity...');

// L1 Public Key = SHA3-256(full_public_key) → 32 bytes → 64 hex chars
// This is what you paste into misakastake.com
const publicKeyHash = sha3_256(publicKey);
const l1PublicKey = bytesToHex(publicKeyHash);

// Validator ID = SHA3-256(full_public_key)[0..20] → 20 bytes → 40 hex chars
// Used internally by the chain for consensus
const validatorId = l1PublicKey.slice(0, 40);

// MISAKA address (for block reward payouts)
const addrHash = sha3_256(
  new Uint8Array([
    ...Buffer.from('MISAKA:validator_address:v1:'),
    ...publicKey
  ])
);
const misakaAddress = 'msk1' + bytesToHex(addrHash).slice(0, 40);

console.log(`       Validator ID:  ${validatorId}`);
console.log(`       Payout addr:   ${misakaAddress}`);
console.log('');

// ─── 署名テスト（整合性検証） ────────────────────────────────

console.log('[3/4] Verifying key integrity (sign + verify test)...');

const testMessage = new Uint8Array(Buffer.from('MISAKA:keygen_self_test:v1'));
const testSig = ml_dsa65.sign(secretKey, testMessage);
const verified = ml_dsa65.verify(publicKey, testMessage, testSig);

if (!verified) {
  console.error('');
  console.error('❌ FATAL: Key integrity check FAILED.');
  console.error('   Generated keypair cannot sign/verify correctly.');
  console.error('   DO NOT use these keys. Try regenerating.');
  process.exit(1);
}
console.log('       ✅ Sign/verify test passed');
console.log('');

// ─── Proof-of-Possession 署名生成 ────────────────────────────

// misakastake.com に登録する際に使用する所有証明
// Rust側の ValidatorRegistration.signing_bytes() と同じフォーマット
const popMessage = new Uint8Array([
  ...Buffer.from('MISAKA:validator_registration:v1:'),
  ...new Uint8Array(new Uint32Array([2]).buffer),  // chain_id = 2 (testnet)
  ...new Uint8Array(new BigUint64Array([BigInt(0)]).buffer),  // epoch = 0
  ...publicKey,
  ...new Uint8Array(new BigUint64Array([BigInt(0)]).buffer).slice(0, 16),  // stake placeholder
  ...new Uint8Array(new Uint16Array([0]).buffer),  // commission = 0
  ...Buffer.from(nodeName),
  ...addrHash.slice(0, 20),
]);
const proofOfPossession = ml_dsa65.sign(secretKey, popMessage);

// ─── ファイル出力 ────────────────────────────────────────────

console.log('[4/4] Writing key files...');

if (!existsSync(outputDir)) {
  mkdirSync(outputDir, { recursive: true });
}

const now = new Date().toISOString();

// Secret key file — NEVER share this
const secretKeyFile = {
  _warning: 'SECRET KEY — DO NOT SHARE. Keep on VPS only.',
  version: 1,
  algorithm: 'ML-DSA-65',
  name: nodeName,
  created_at: now,
  chain_id: 2,
  validator_id: validatorId,
  l1_public_key: l1PublicKey,
  misaka_address: misakaAddress,
  // Full keys (hex-encoded)
  public_key_hex: bytesToHex(publicKey),
  secret_key_hex: bytesToHex(secretKey),
  // Proof-of-possession for registration
  proof_of_possession_hex: bytesToHex(proofOfPossession),
  // Key sizes for verification
  _meta: {
    pk_bytes: publicKey.length,
    sk_bytes: secretKey.length,
    pop_bytes: proofOfPossession.length,
  }
};

const secretPath = join(outputDir, 'l1-secret-key.json');
writeFileSync(secretPath, JSON.stringify(secretKeyFile, null, 2), 'utf-8');

// Public key file — safe to share, submit to misakastake.com
const publicKeyFile = {
  version: 1,
  algorithm: 'ML-DSA-65',
  name: nodeName,
  created_at: now,
  chain_id: 2,
  // ─── misakastake.com に入力する値 ───
  l1_public_key: l1PublicKey,
  validator_id: validatorId,
  misaka_address: misakaAddress,
  // Full public key (for on-chain verification)
  public_key_hex: bytesToHex(publicKey),
  // Proof-of-possession (for registration transaction)
  proof_of_possession_hex: bytesToHex(proofOfPossession),
};

const publicPath = join(outputDir, 'l1-public-key.json');
writeFileSync(publicPath, JSON.stringify(publicKeyFile, null, 2), 'utf-8');

console.log(`       Secret key: ${secretPath}`);
console.log(`       Public key: ${publicPath}`);

// ─── 完了 ────────────────────────────────────────────────────

console.log('');
console.log('═══════════════════════════════════════════════════════════');
console.log('');
console.log('  ✅ Validator key generated successfully!');
console.log('');
console.log('  ┌─────────────────────────────────────────────────────┐');
console.log(`  │  L1 Public Key (misakastake.com に入力):            │`);
console.log(`  │  ${l1PublicKey}  │`);
console.log('  └─────────────────────────────────────────────────────┘');
console.log('');
console.log(`  Node Name:       ${nodeName}`);
console.log(`  Validator ID:    ${validatorId}`);
console.log(`  Payout Address:  ${misakaAddress}`);
console.log('');
console.log('  ─── Next Steps ───');
console.log('');
console.log('  1. Copy the L1 Public Key above');
console.log('  2. Go to misakastake.com → Register Validator');
console.log('  3. Paste the L1 Public Key');
console.log(`  4. Enter Node Name: ${nodeName}`);
console.log('  5. Submit registration');
console.log('  6. Start your validator:');
console.log('');
console.log(`     node start-validator.js --key ${secretPath}`);
console.log('');
console.log('  ⚠  IMPORTANT:');
console.log(`  ・${secretPath} は絶対に外部に公開しないでください`);
console.log('  ・Solanaの秘密鍵はVPSに不要です');
console.log('  ・バックアップは安全な場所に保管してください');
console.log('');
