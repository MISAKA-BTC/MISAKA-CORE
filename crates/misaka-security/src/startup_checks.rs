//! Startup self-checks — fail-closed validation before node starts.

use std::path::Path;

/// Results of startup validation.
#[derive(Debug)]
pub struct StartupCheckResult {
    pub checks_passed: usize,
    pub checks_failed: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl StartupCheckResult {
    pub fn is_ok(&self) -> bool { self.checks_failed == 0 }
}

/// Run all startup checks. Fail-closed: if ANY critical check fails, node must not start.
pub fn run_startup_checks(
    data_dir: &Path,
    is_mainnet: bool,
    _chain_id: u32,
) -> StartupCheckResult {
    let mut result = StartupCheckResult {
        checks_passed: 0, checks_failed: 0,
        errors: Vec::new(), warnings: Vec::new(),
    };

    // 1. Data directory writable
    check(&mut result, "data_dir_writable", || {
        if !data_dir.exists() {
            std::fs::create_dir_all(data_dir).map_err(|e| format!("cannot create: {}", e))?;
        }
        let test_file = data_dir.join(".startup_check");
        std::fs::write(&test_file, b"ok").map_err(|e| format!("not writable: {}", e))?;
        std::fs::remove_file(&test_file).ok();
        Ok(())
    });

    // 2. Validator passphrase (mainnet only)
    if is_mainnet {
        check(&mut result, "validator_passphrase", || {
            let val = std::env::var("MISAKA_VALIDATOR_PASSPHRASE").unwrap_or_default();
            if val.is_empty() {
                return Err("MISAKA_VALIDATOR_PASSPHRASE required on mainnet".into());
            }
            if val.len() < 12 {
                return Err("passphrase too short (min 12 chars)".into());
            }
            Ok(())
        });
    }

    // 3. Bridge persistence (if bridge data dir exists)
    let bridge_dir = data_dir.join("bridge");
    if bridge_dir.exists() {
        check(&mut result, "bridge_nullifier_integrity", || {
            let nf = bridge_dir.join("bridge_nullifiers.dat");
            if nf.exists() {
                let meta = std::fs::metadata(&nf).map_err(|e| e.to_string())?;
                if meta.len() % 32 != 0 {
                    return Err(format!("nullifier file corrupted: {} bytes (not 32-aligned)", meta.len()));
                }
            }
            Ok(())
        });
    }

    // 4. Release manifest (packaged builds)
    if data_dir.join("BUILD_MANIFEST.json").exists() || is_mainnet {
        check(&mut result, "release_manifest", || {
            if is_mainnet && !data_dir.join("BUILD_MANIFEST.json").exists() {
                return Err("BUILD_MANIFEST.json required for mainnet".into());
            }
            Ok(())
        });
    }

    result
}

fn check(result: &mut StartupCheckResult, name: &str, f: impl FnOnce() -> Result<(), String>) {
    match f() {
        Ok(()) => {
            result.checks_passed += 1;
            tracing::info!("startup check '{}': PASS", name);
        }
        Err(e) => {
            result.checks_failed += 1;
            result.errors.push(format!("{}: {}", name, e));
            tracing::error!("startup check '{}': FAIL — {}", name, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startup_checks_pass_on_tempdir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = run_startup_checks(dir.path(), false, 2);
        assert!(result.is_ok(), "errors: {:?}", result.errors);
    }

    #[test]
    fn test_startup_checks_mainnet_requires_passphrase() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::remove_var("MISAKA_VALIDATOR_PASSPHRASE");
        let result = run_startup_checks(dir.path(), true, 1);
        assert!(!result.is_ok());
    }
}
