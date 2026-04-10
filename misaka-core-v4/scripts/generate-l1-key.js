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

const { execSync } = require("child_process");
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
    execSync(`${p} --version`, { stdio: "pipe" });
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
// Audit R8 #25: Never fall through on parse error — refuse to overwrite
const secretKeyPath = path.join(dataDir, "l1-secret-key.json");
if (fs.existsSync(secretKeyPath)) {
  let fileContent;
  try {
    fileContent = fs.readFileSync(secretKeyPath, "utf-8");
  } catch (readErr) {
    console.error("");
    console.error("  ❌ Cannot read existing key file: " + readErr.message);
    console.error("     Refusing to overwrite. Check file permissions.");
    console.error(`     Path: ${secretKeyPath}`);
    console.error("");
    process.exit(1);
  }
  try {
    const existing = JSON.parse(fileContent);
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
  } catch (parseErr) {
    // Audit R8 #25: Do NOT fall through to key generation on parse error
    console.error("");
    console.error("  ❌ Existing key file is corrupted or invalid JSON:");
    console.error(`     ${parseErr.message}`);
    console.error("");
    console.error("  Refusing to overwrite. Please inspect manually:");
    console.error(`     ${secretKeyPath}`);
    console.error("");
    process.exit(1);
  }
}

// ── Generate key via misaka-node --keygen-only ──
console.log("");
console.log("  🔑 Generating L1 validator key...");
console.log("");

try {
  const cmd = [
    binaryPath,
    "--keygen-only",
    "--name",
    nodeName,
    "--chain-id",
    chainId,
    "--data-dir",
    dataDir,
  ].join(" ");

  const output = execSync(cmd, {
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

// ── Audit R8 #24: Set restrictive permissions on secret key file ──
if (fs.existsSync(secretKeyPath)) {
  try {
    fs.chmodSync(secretKeyPath, 0o600);
    console.log(`  🔒 Set permissions 600 on ${secretKeyPath}`);
  } catch (chmodErr) {
    console.warn(`  ⚠  Failed to set permissions on ${secretKeyPath}: ${chmodErr.message}`);
    console.warn("     Manually run: chmod 600 " + secretKeyPath);
  }
}
