#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
//  MISAKA Network — L1 Validator Starter
//
//  Loads validator secret key, verifies integrity, and starts
//  the MISAKA node in validator mode.
//
//  Usage:
//    node start-validator.js --key ./l1-secret-key.json
//    node start-validator.js --key ./l1-secret-key.json --rpc-port 3001
//    node start-validator.js --key ./l1-secret-key.json --p2p-port 6690
//
//  Prerequisites:
//    1. Generated key via: node generate-l1-key.js
//    2. Registered at misakastake.com
//    3. misaka-node binary built and in PATH (or ./target/release/)
// ═══════════════════════════════════════════════════════════════

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { spawn } from 'child_process';

// ─── CLI引数パース ──────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(name, defaultVal) {
  const idx = args.indexOf(`--${name}`);
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1];
  return defaultVal;
}
function hasFlag(name) {
  return args.includes(`--${name}`);
}

const keyPath = getArg('key', './l1-secret-key.json');
const rpcPort = getArg('rpc-port', '3001');
const p2pPort = getArg('p2p-port', '6690');
const chainId = getArg('chain-id', '2');
const blockTime = getArg('block-time', '60');
const logLevel = getArg('log-level', 'info');
const peers = getArg('peers', '');
const seeds = getArg('seeds', '');
const advertiseAddr = getArg('advertise-addr', '');
const dryRun = hasFlag('dry-run');

// ─── バナー ─────────────────────────────────────────────────

console.log('');
console.log('╔═══════════════════════════════════════════════════════════╗');
console.log('║  MISAKA Network — L1 Validator Starter                   ║');
console.log('║  Pure PoS • Post-Quantum • ML-DSA-65                     ║');
console.log('╚═══════════════════════════════════════════════════════════╝');
console.log('');

// ─── 鍵ファイル読み込み ──────────────────────────────────────

const resolvedKeyPath = resolve(keyPath);

if (!existsSync(resolvedKeyPath)) {
  console.error(`❌ Secret key file not found: ${resolvedKeyPath}`);
  console.error('');
  console.error('   Generate a key first:');
  console.error('     node generate-l1-key.js');
  console.error('');
  process.exit(1);
}

console.log(`[1/5] Loading secret key from: ${resolvedKeyPath}`);

let keyFile;
try {
  const raw = readFileSync(resolvedKeyPath, 'utf-8');
  keyFile = JSON.parse(raw);
} catch (e) {
  console.error(`❌ Failed to read key file: ${e.message}`);
  process.exit(1);
}

// ─── 鍵ファイル検証 ──────────────────────────────────────────

console.log('[2/5] Validating key file structure...');

const requiredFields = [
  'version', 'algorithm', 'validator_id', 'l1_public_key',
  'public_key_hex', 'secret_key_hex'
];
const missing = requiredFields.filter(f => !keyFile[f]);
if (missing.length > 0) {
  console.error(`❌ Key file missing required fields: ${missing.join(', ')}`);
  process.exit(1);
}

if (keyFile.algorithm !== 'ML-DSA-65') {
  console.error(`❌ Unsupported algorithm: ${keyFile.algorithm} (expected ML-DSA-65)`);
  process.exit(1);
}

if (keyFile.version !== 1) {
  console.error(`❌ Unsupported key file version: ${keyFile.version}`);
  process.exit(1);
}

console.log('       ✅ Structure OK');

// ─── 鍵の整合性検証 ──────────────────────────────────────────

console.log('[3/5] Verifying key integrity (cryptographic self-test)...');

let publicKey, secretKey;
try {
  publicKey = hexToBytes(keyFile.public_key_hex);
  secretKey = hexToBytes(keyFile.secret_key_hex);
} catch (e) {
  console.error(`❌ Failed to decode keys: ${e.message}`);
  process.exit(1);
}

if (publicKey.length !== 1952) {
  console.error(`❌ Invalid public key length: ${publicKey.length} (expected 1952)`);
  process.exit(1);
}
if (secretKey.length !== 4032) {
  console.error(`❌ Invalid secret key length: ${secretKey.length} (expected 4032)`);
  process.exit(1);
}

// Verify L1 public key derivation
const computedHash = bytesToHex(sha3_256(publicKey));
if (computedHash !== keyFile.l1_public_key) {
  console.error('❌ L1 public key mismatch — key file may be corrupted');
  console.error(`   Expected: ${keyFile.l1_public_key}`);
  console.error(`   Computed: ${computedHash}`);
  process.exit(1);
}

// Sign/verify self-test
const testMsg = new Uint8Array(Buffer.from('MISAKA:validator_startup_test:v1'));
try {
  const testSig = ml_dsa65.sign(secretKey, testMsg);
  const ok = ml_dsa65.verify(publicKey, testMsg, testSig);
  if (!ok) throw new Error('verification returned false');
} catch (e) {
  console.error(`❌ Key integrity test FAILED: ${e.message}`);
  console.error('   Keys may be corrupted. Regenerate with: node generate-l1-key.js');
  process.exit(1);
}

console.log('       ✅ ML-DSA-65 sign/verify test passed');

// Verify validator_id derivation
const computedVid = computedHash.slice(0, 40);
if (computedVid !== keyFile.validator_id) {
  console.error('❌ Validator ID mismatch — key file may be corrupted');
  process.exit(1);
}
console.log('       ✅ Validator ID derivation verified');

// ─── Activity Log 表示 ───────────────────────────────────────

console.log('[4/5] Preparing validator configuration...');
console.log('');

const timestamp = () => {
  const d = new Date();
  return `[${d.toTimeString().split(' ')[0]}]`;
};

console.log(`${timestamp()} MISAKA Staking`);
console.log(`${timestamp()} Validator ID:     ${keyFile.validator_id}`);
console.log(`${timestamp()} L1 Public Key:    ${keyFile.l1_public_key}`);
console.log(`${timestamp()} Node Name:        ${keyFile.name || 'unknown'}`);
console.log(`${timestamp()} Payout Address:   ${keyFile.misaka_address || 'unknown'}`);
console.log(`${timestamp()} Chain ID:         ${chainId}`);
console.log(`${timestamp()} RPC Port:         ${rpcPort}`);
console.log(`${timestamp()} P2P Port:         ${p2pPort}`);
console.log(`${timestamp()} Block Time:       ${blockTime}s`);
console.log('');

// ─── misaka-node 起動 ────────────────────────────────────────

console.log('[5/5] Starting MISAKA validator node...');
console.log('');

// Find misaka-node binary
const binaryPaths = [
  './target/release/misaka-node',
  './target/debug/misaka-node',
  '../target/release/misaka-node',
  '../target/debug/misaka-node',
  'misaka-node',
];
let binaryPath = null;
for (const p of binaryPaths) {
  if (existsSync(p)) {
    binaryPath = p;
    break;
  }
}

if (!binaryPath) {
  console.log('');
  console.log('⚠  misaka-node binary not found.');
  console.log('   Build it first:');
  console.log('     cargo build --release -p misaka-node');
  console.log('');
  console.log('   Or run manually:');
  console.log('');
  const cmd = buildNodeCommand();
  console.log(`     ${cmd}`);
  console.log('');
  console.log(`${timestamp()} Ready (binary not found — manual start required)`);
  process.exit(0);
}

if (dryRun) {
  console.log('   [DRY RUN] Would execute:');
  console.log(`   ${buildNodeCommand(binaryPath)}`);
  console.log('');
  console.log(`${timestamp()} Ready (dry run)`);
  process.exit(0);
}

// Launch the node
const nodeArgs = buildNodeArgs();
console.log(`${timestamp()} Launching: ${binaryPath}`);
console.log(`${timestamp()} Args: ${nodeArgs.join(' ')}`);
console.log('');
console.log('═══════════════════════════════════════════════════════════');
console.log('');

const child = spawn(binaryPath, nodeArgs, {
  stdio: 'inherit',
  env: {
    ...process.env,
    MISAKA_VALIDATOR_SK: keyFile.secret_key_hex,
    MISAKA_VALIDATOR_PK: keyFile.public_key_hex,
    MISAKA_VALIDATOR_ID: keyFile.validator_id,
  }
});

child.on('error', (err) => {
  console.error(`❌ Failed to start misaka-node: ${err.message}`);
  process.exit(1);
});

child.on('exit', (code) => {
  console.log(`\n${timestamp()} misaka-node exited with code ${code}`);
  process.exit(code || 0);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log(`\n${timestamp()} Shutting down validator...`);
  child.kill('SIGINT');
});
process.on('SIGTERM', () => {
  child.kill('SIGTERM');
});

// ─── Helper ──────────────────────────────────────────────────

function buildNodeArgs() {
  const nodeArgs = [
    '--name', keyFile.name || 'misaka-validator',
    '--mode', 'public',
    '--validator',
    '--rpc-port', rpcPort,
    '--p2p-port', p2pPort,
    '--chain-id', chainId,
    '--block-time', blockTime,
    '--log-level', logLevel,
    '--validator-index', '0',
    '--validators', '1',
  ];

  if (peers) {
    nodeArgs.push('--peers', peers);
  }
  if (seeds) {
    nodeArgs.push('--seeds', seeds);
  }
  if (advertiseAddr) {
    nodeArgs.push('--advertise-addr', advertiseAddr);
  }

  return nodeArgs;
}

function buildNodeCommand(bin = 'misaka-node') {
  return `${bin} ${buildNodeArgs().join(' ')}`;
}
