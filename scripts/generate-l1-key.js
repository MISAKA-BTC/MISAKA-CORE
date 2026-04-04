#!/usr/bin/env node
/**
 * MISAKA Network — L1 Validator Key Generator
 *
 * Generates an ML-DSA-65 (post-quantum) validator keypair on your VPS.
 * The L1 Public Key is used to register at misakastake.com.
 *
 * Usage:
 *   node generate-l1-key.js [--name NODE_NAME] [--chain-id 2] [--data-dir ./data]
 *
 * Output:
 *   ./data/l1-secret-key.json  — SECRET: never share this file
 *   ./data/l1-public-key.json  — safe to share
 *
 * Next steps:
 *   1. Copy the L1 Public Key (hex 64 chars)
 *   2. Go to https://misakastake.com
 *   3. Stake tokens (testnet: 1M / mainnet: 10M MISAKA)
 *   4. Start validator: node start-validator.js --key ./data/l1-secret-key.json
 *
 * ⚠  Solana private keys are NOT needed on this VPS.
 */

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

// ── Parse args ──
const args = process.argv.slice(2);
function getArg(name, defaultVal) {
  const idx = args.indexOf(`--${name}`);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return defaultVal;
}

const nodeName = getArg("name", `misaka-validator-${Date.now() % 10000}`);
const chainId = getArg("chain-id", "2");
const dataDir = getArg("data-dir", "./data");

// ── Find the misaka-node binary ──
const binaryPaths = [
  path.join(__dirname, "..", "target", "release", "misaka-node"),
  path.join(__dirname, "..", "target", "debug", "misaka-node"),
  "misaka-node", // PATH
];

let binaryPath = null;
for (const p of binaryPaths) {
  try {
    execFileSync(p, ["--version"], { stdio: "pipe" });
    binaryPath = p;
    break;
  } catch (_) {}
}

if (!binaryPath) {
  console.error("");
  console.error("  ❌ misaka-node binary not found.");
  console.error("");
  console.error("  Build it first:");
  console.error("    cargo build --release --features dag");
  console.error("");
  console.error("  Or ensure 'misaka-node' is in your PATH.");
  console.error("");
  process.exit(1);
}

// ── Check if key already exists ──
const secretKeyPath = path.join(dataDir, "l1-secret-key.json");
if (fs.existsSync(secretKeyPath)) {
  try {
    const existing = JSON.parse(fs.readFileSync(secretKeyPath, "utf-8"));
    console.log("");
    console.log("══════════════════════════════════════════════════");
    console.log("  L1 Key already exists");
    console.log("══════════════════════════════════════════════════");
    console.log("");
    console.log(`  L1 Public Key:  ${existing.l1PublicKey}`);
    console.log(`  Node Name:      ${existing.nodeName}`);
    console.log(`  Key File:       ${secretKeyPath}`);
    console.log("");
    console.log(`  To regenerate, delete ${secretKeyPath} first.`);
    console.log("");
    process.exit(0);
  } catch (_) {}
}

// ── Generate key via misaka-node --keygen-only ──
console.log("");
console.log("  🔑 Generating L1 validator key...");
console.log("");

try {
  // SEC-FIX: Use execFileSync to prevent command injection via --name or --data-dir.
  const args = [
    "--keygen-only",
    "--name",
    nodeName,
    "--chain-id",
    String(chainId),
    "--data-dir",
    dataDir,
  ];

  const output = execFileSync(binaryPath, args, {
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
  });

  // Print the output from the binary
  console.log(output);
} catch (err) {
  // The binary prints its own output even on "error" exit codes
  if (err.stdout) console.log(err.stdout);
  if (err.stderr) console.error(err.stderr);

  // Check if key was actually generated despite exit code
  if (fs.existsSync(secretKeyPath)) {
    console.log("  ✅ Key generated successfully.");
  } else {
    console.error("  ❌ Key generation failed.");
    process.exit(1);
  }
}
