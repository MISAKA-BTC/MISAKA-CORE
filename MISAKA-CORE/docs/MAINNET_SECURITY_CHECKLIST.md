# MISAKA Mainnet Security Checklist

Pre-mainnet operator checklist. Complete ALL items before launching a mainnet validator.

## 1. Validator Key Setup

- [ ] Generate validator keypair using `misaka-cli keygen`
- [ ] Store keypair in encrypted keystore (never plain text on disk)
- [ ] Back up keypair to offline cold storage (USB, air-gapped machine)
- [ ] Verify keypair loads correctly with `misaka-cli key-verify`
- [ ] Set `MISAKA_VALIDATOR_PASSPHRASE` in a secure environment file (not in shell history)

## 2. Passphrase Strength

- [ ] Passphrase is at least 12 characters long
- [ ] Passphrase uses a mix of uppercase, lowercase, digits, and symbols
- [ ] Passphrase is not reused from another service
- [ ] Passphrase is stored in a password manager or hardware security module
- [ ] Rotation policy: rotate every 90 days at minimum

## 3. Admin Listener Configuration

- [ ] Admin RPC binds to `127.0.0.1` only (not `0.0.0.0`)
- [ ] Admin port (default 3002) is not exposed to the internet
- [ ] If remote admin is needed, use SSH tunnel only
- [ ] Enable mTLS for admin endpoints if multiple operators share access
- [ ] Verify with `ss -tlnp | grep 3002` that admin port is localhost-only

## 4. Bridge Committee Setup

- [ ] Committee members are registered with ML-DSA-65 public keys
- [ ] Quorum threshold is set (recommend 2-of-3 minimum)
- [ ] Bridge verifier is set to `CommitteeVerifier` (not `MockVerifier`)
- [ ] Rate limits configured: per-tx limit, hourly limit, daily global limit
- [ ] Circuit breaker enabled with appropriate thresholds

## 5. TLS Certificates

- [ ] Valid TLS certificates installed for public RPC endpoints
- [ ] Certificate chain is complete (includes intermediates)
- [ ] Certificate is not self-signed for production
- [ ] Auto-renewal configured (certbot or equivalent)
- [ ] HSTS headers enabled on public endpoints

## 6. Rate Limits

- [ ] RPC rate limiting enabled (default: 100 req/s per IP)
- [ ] Admin endpoint rate limiting enabled (stricter: 10 req/s)
- [ ] WebSocket connection limits configured
- [ ] P2P peer connection limits set appropriately
- [ ] DDoS mitigation (cloud provider or reverse proxy) in place

## 7. Monitoring and Alerting

- [ ] Prometheus metrics endpoint enabled
- [ ] Alerts configured for: node offline, block production stalled, bridge paused
- [ ] Log aggregation configured (structured JSON logs recommended)
- [ ] Disk usage monitoring (alert at 80% capacity)
- [ ] Memory and CPU usage alerts

## 8. Backup Procedures

- [ ] Daily automated backup of chain data directory
- [ ] Bridge nullifier file included in backups
- [ ] Backup integrity verified (test restore quarterly)
- [ ] Off-site backup replication configured
- [ ] Recovery time objective (RTO) documented and tested

## 9. Startup Checks

- [ ] Run `misaka-node --startup-check` before first mainnet launch
- [ ] All startup checks pass (data dir writable, passphrase set, etc.)
- [ ] BUILD_MANIFEST.json present for release builds
- [ ] Genesis hash matches expected mainnet genesis

## 10. Network Security

- [ ] Firewall configured: only required ports open (P2P, RPC)
- [ ] SSH key-based auth only (password auth disabled)
- [ ] Automatic security updates enabled for OS
- [ ] Node runs as non-root user with minimal privileges
- [ ] SELinux or AppArmor profile configured
