//! Structural validation for v2 transactions (E1 scope).
//!
//! This validates the STRUCTURE of a v2 tx without resolving UTXOs
//! or executing scripts. Full Phase 1/2 validation is in E4.

use super::auxiliary::MAX_AUXILIARY_DATA_SIZE;
use super::collateral::MAX_COLLATERAL_INPUTS;
use super::datum::MAX_DATUM_SIZE;
use super::redeemer::MAX_REDEEMER_SIZE;
use super::script::MAX_SCRIPT_SIZE;
use super::tx_v2::*;
use super::value::{MAX_ASSETS_PER_VALUE, MAX_ASSET_NAME_LEN};
use super::witness::WitnessKindV2;

/// Structural validation errors (no UTXO resolution needed).
#[derive(Debug, Clone, thiserror::Error)]
pub enum EutxoStructuralError {
    #[error("version mismatch: expected 2, got {0}")]
    VersionMismatch(u8),
    #[error("reserved field populated in E1: {0}")]
    ReservedFieldPopulated(&'static str),
    #[error("too many inputs: {0} > {MAX_INPUTS_PER_TX}")]
    TooManyInputs(usize),
    #[error("too many outputs: {0} > {MAX_OUTPUTS_PER_TX}")]
    TooManyOutputs(usize),
    #[error("too many reference inputs: {0} > {MAX_REFERENCE_INPUTS_PER_TX}")]
    TooManyReferenceInputs(usize),
    #[error("too many collateral inputs: {0} > {MAX_COLLATERAL_INPUTS}")]
    TooManyCollateralInputs(usize),
    #[error("too many required signers: {0}")]
    TooManyRequiredSigners(usize),
    #[error("too many assets in output: {0} > {MAX_ASSETS_PER_VALUE}")]
    TooManyAssetsInOutput(usize),
    #[error("too many redeemers: {0} > {MAX_REDEEMERS_PER_TX}")]
    TooManyRedeemers(usize),
    #[error("too many mint entries: {0} > {MAX_MINT_ENTRIES_PER_TX}")]
    TooManyMintEntries(usize),
    #[error("missing collateral for script tx")]
    MissingCollateralForScriptTx,
    #[error("collateral provided without scripts")]
    CollateralProvidedWithoutScripts,
    #[error("collateral overflow")]
    CollateralOverflow,
    #[error("invalid validity interval: valid_from >= valid_to")]
    InvalidValidityInterval,
    #[error("aux data hash mismatch")]
    AuxDataHashMismatch,
    #[error("datum too large: {0} > {MAX_DATUM_SIZE}")]
    DatumTooLarge(usize),
    #[error("script too large: {0} > {MAX_SCRIPT_SIZE}")]
    ScriptTooLarge(usize),
    #[error("redeemer too large: {0} > {MAX_REDEEMER_SIZE}")]
    RedeemerTooLarge(usize),
    #[error("asset name too long: {0} > {MAX_ASSET_NAME_LEN}")]
    AssetNameTooLong(usize),
    #[error("auxiliary data too large: {0} > {MAX_AUXILIARY_DATA_SIZE}")]
    AuxDataTooLarge(usize),
}

/// Validate the structure of a v2 transaction (E1 scope, no UTXO resolution).
pub fn validate_structural(tx: &UtxoTransactionV2) -> Result<(), EutxoStructuralError> {
    // Version
    if tx.version != EUTXO_TX_VERSION {
        return Err(EutxoStructuralError::VersionMismatch(tx.version));
    }

    // E1 reserved fields must be empty
    if !tx.mint.is_empty() {
        return Err(EutxoStructuralError::ReservedFieldPopulated("mint"));
    }

    // Size limits
    if tx.inputs.len() > MAX_INPUTS_PER_TX {
        return Err(EutxoStructuralError::TooManyInputs(tx.inputs.len()));
    }
    if tx.outputs.len() > MAX_OUTPUTS_PER_TX {
        return Err(EutxoStructuralError::TooManyOutputs(tx.outputs.len()));
    }
    if tx.reference_inputs.len() > MAX_REFERENCE_INPUTS_PER_TX {
        return Err(EutxoStructuralError::TooManyReferenceInputs(
            tx.reference_inputs.len(),
        ));
    }
    if tx.collateral_inputs.len() > MAX_COLLATERAL_INPUTS {
        return Err(EutxoStructuralError::TooManyCollateralInputs(
            tx.collateral_inputs.len(),
        ));
    }
    if tx.required_signers.len() > super::auxiliary::MAX_REQUIRED_SIGNERS {
        return Err(EutxoStructuralError::TooManyRequiredSigners(
            tx.required_signers.len(),
        ));
    }
    if tx.extra_redeemers.len() > MAX_REDEEMERS_PER_TX {
        return Err(EutxoStructuralError::TooManyRedeemers(
            tx.extra_redeemers.len(),
        ));
    }

    // Collateral structural rules
    let has_scripts = tx.has_scripts();
    if has_scripts && tx.collateral_inputs.is_empty() {
        return Err(EutxoStructuralError::MissingCollateralForScriptTx);
    }
    if !has_scripts && !tx.collateral_inputs.is_empty() {
        return Err(EutxoStructuralError::CollateralProvidedWithoutScripts);
    }

    // Collateral return consistency
    if let (Some(ret), Some(total)) = (&tx.collateral_return, tx.total_collateral) {
        if ret.value.mlp == u64::MAX || total == u64::MAX {
            return Err(EutxoStructuralError::CollateralOverflow);
        }
    }

    // Per-output asset limits
    for output in &tx.outputs {
        if output.value.native_assets.len() > MAX_ASSETS_PER_VALUE {
            return Err(EutxoStructuralError::TooManyAssetsInOutput(
                output.value.native_assets.len(),
            ));
        }
        // Asset name length
        for asset_id in output.value.native_assets.keys() {
            if !asset_id.asset_name.is_valid() {
                return Err(EutxoStructuralError::AssetNameTooLong(
                    asset_id.asset_name.0.len(),
                ));
            }
        }
        // Datum size
        if let Some(super::datum::DatumOrHash::Inline(ref d)) = output.datum {
            if !d.is_valid_size() {
                return Err(EutxoStructuralError::DatumTooLarge(d.0.len()));
            }
        }
        // Script ref size
        if let Some(ref s) = output.script_ref {
            if !s.is_valid_size() {
                return Err(EutxoStructuralError::ScriptTooLarge(s.bytecode.0.len()));
            }
        }
    }

    // Redeemer size
    for input in &tx.inputs {
        if let WitnessKindV2::Script { ref redeemer, .. } = input.witness {
            if redeemer.data.len() > MAX_REDEEMER_SIZE {
                return Err(EutxoStructuralError::RedeemerTooLarge(redeemer.data.len()));
            }
        }
    }
    for r in &tx.extra_redeemers {
        if r.data.len() > MAX_REDEEMER_SIZE {
            return Err(EutxoStructuralError::RedeemerTooLarge(r.data.len()));
        }
    }

    // Validity interval sanity
    if let (Some(from), Some(to)) = (
        tx.validity_interval.valid_from,
        tx.validity_interval.valid_to,
    ) {
        if from >= to {
            return Err(EutxoStructuralError::InvalidValidityInterval);
        }
    }

    // Auxiliary data hash consistency
    if let (Some(aux), Some(declared_hash)) = (&tx.auxiliary_data, tx.aux_data_hash) {
        let computed = aux.hash();
        if computed != declared_hash {
            return Err(EutxoStructuralError::AuxDataHashMismatch);
        }
    }

    // Auxiliary data size
    if let Some(ref aux) = tx.auxiliary_data {
        if aux.total_size() > MAX_AUXILIARY_DATA_SIZE {
            return Err(EutxoStructuralError::AuxDataTooLarge(aux.total_size()));
        }
    }

    Ok(())
}
