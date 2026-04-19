//! Fluent TxBuilder API for v2 (eUTXO) transactions.
//!
//! ```no_run
//! use misaka_sdk::TxBuilder;
//! use misaka_types::eutxo::value::AssetValue;
//! use misaka_types::utxo::{OutputRef, TxType};
//!
//! let tx = TxBuilder::new(0, TxType::TransparentTransfer)
//!     .add_input(OutputRef { tx_hash: [1u8; 32], output_index: 0 }, vec![0xAA; 64])
//!     .add_output([2u8; 32], AssetValue::mlp_only(900_000))
//!     .set_fee(100_000)
//!     .build()
//!     .expect("valid tx");
//! ```

pub mod collateral;
pub mod fee;
pub mod signing;

use crate::error::SdkError;
use misaka_types::eutxo::auxiliary::AuxiliaryData;
use misaka_types::eutxo::collateral::{CollateralInput, CollateralReturn};
use misaka_types::eutxo::cost_model::ExUnits;
use misaka_types::eutxo::datum::{DatumOrHash, InlineDatum};
use misaka_types::eutxo::mint::MintEntry;
use misaka_types::eutxo::redeemer::{Redeemer, RedeemerPurpose};
use misaka_types::eutxo::reference::ReferenceInput;
use misaka_types::eutxo::script::{ScriptSource, VersionedScript};
use misaka_types::eutxo::tx_v2::{TxInputV2, TxOutputV2, UtxoTransactionV2};
use misaka_types::eutxo::validate::validate_structural;
use misaka_types::eutxo::validity::ValidityInterval;
use misaka_types::eutxo::value::AssetValue;
use misaka_types::eutxo::witness::WitnessKindV2;
use misaka_types::utxo::{OutputRef, TxType};

#[derive(Clone, Debug)]
pub struct TxBuilder {
    network_id: u8,
    tx_type: TxType,
    inputs: Vec<TxInputV2>,
    outputs: Vec<TxOutputV2>,
    reference_inputs: Vec<ReferenceInput>,
    collateral_inputs: Vec<CollateralInput>,
    collateral_return: Option<CollateralReturn>,
    total_collateral: Option<u64>,
    fee: Option<u64>,
    validity: ValidityInterval,
    required_signers: Vec<[u8; 32]>,
    extra_redeemers: Vec<Redeemer>,
    mint: Vec<MintEntry>,
    aux_data_hash: Option<[u8; 32]>,
    auxiliary_data: Option<AuxiliaryData>,
}

impl TxBuilder {
    pub fn new(network_id: u8, tx_type: TxType) -> Self {
        Self {
            network_id,
            tx_type,
            inputs: Vec::new(),
            outputs: Vec::new(),
            reference_inputs: Vec::new(),
            collateral_inputs: Vec::new(),
            collateral_return: None,
            total_collateral: None,
            fee: None,
            validity: ValidityInterval::default(),
            required_signers: Vec::new(),
            extra_redeemers: Vec::new(),
            mint: Vec::new(),
            aux_data_hash: None,
            auxiliary_data: None,
        }
    }

    pub fn add_input(mut self, outref: OutputRef, signature: Vec<u8>) -> Self {
        self.inputs.push(TxInputV2 {
            outref,
            witness: WitnessKindV2::Signature(signature),
        });
        self
    }

    pub fn add_script_input(
        mut self,
        outref: OutputRef,
        source: ScriptSource,
        redeemer_data: Vec<u8>,
        datum: Option<Vec<u8>>,
        ex_units: ExUnits,
    ) -> Self {
        let idx = self.inputs.len() as u32;
        self.inputs.push(TxInputV2 {
            outref,
            witness: WitnessKindV2::Script {
                script: source,
                redeemer: Redeemer {
                    purpose: RedeemerPurpose::Spend(idx),
                    data: redeemer_data,
                    ex_units,
                },
                datum,
            },
        });
        self
    }

    pub fn add_output(mut self, address: [u8; 32], value: AssetValue) -> Self {
        self.outputs.push(TxOutputV2 {
            address,
            value,
            spending_pubkey: None,
            datum: None,
            script_ref: None,
        });
        self
    }

    pub fn add_script_output(
        mut self,
        address: [u8; 32],
        value: AssetValue,
        datum: Option<DatumOrHash>,
        script_ref: Option<VersionedScript>,
    ) -> Self {
        self.outputs.push(TxOutputV2 {
            address,
            value,
            spending_pubkey: None,
            datum,
            script_ref,
        });
        self
    }

    pub fn add_reference_input(mut self, outref: OutputRef) -> Self {
        self.reference_inputs.push(ReferenceInput { outref });
        self
    }

    pub fn add_collateral(mut self, outref: OutputRef) -> Self {
        self.collateral_inputs.push(CollateralInput { outref });
        self
    }

    pub fn set_collateral_return(mut self, address: [u8; 32], value: AssetValue) -> Self {
        self.collateral_return = Some(CollateralReturn { address, value });
        self
    }

    pub fn set_total_collateral(mut self, amount: u64) -> Self {
        self.total_collateral = Some(amount);
        self
    }

    pub fn set_fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    pub fn set_validity(mut self, valid_from: Option<u64>, valid_to: Option<u64>) -> Self {
        self.validity = ValidityInterval {
            valid_from,
            valid_to,
        };
        self
    }

    pub fn add_required_signer(mut self, pkh: [u8; 32]) -> Self {
        self.required_signers.push(pkh);
        self
    }

    pub fn add_extra_redeemer(mut self, redeemer: Redeemer) -> Self {
        self.extra_redeemers.push(redeemer);
        self
    }

    /// Build without validation (for fee estimation 2-pass).
    pub fn build_unchecked(&self) -> Result<UtxoTransactionV2, SdkError> {
        let fee = self.fee.ok_or(SdkError::FeeNotSet)?;
        Ok(UtxoTransactionV2 {
            version: 2,
            network_id: self.network_id,
            tx_type: self.tx_type,
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            fee,
            validity_interval: self.validity,
            mint: self.mint.clone(),
            required_signers: self.required_signers.clone(),
            reference_inputs: self.reference_inputs.clone(),
            collateral_inputs: self.collateral_inputs.clone(),
            collateral_return: self.collateral_return.clone(),
            total_collateral: self.total_collateral,
            network_params_hash: None,
            aux_data_hash: self.aux_data_hash,
            extra_redeemers: self.extra_redeemers.clone(),
            auxiliary_data: self.auxiliary_data.clone(),
        })
    }

    /// Build with structural validation.
    pub fn build(self) -> Result<UtxoTransactionV2, SdkError> {
        let tx = self.build_unchecked()?;
        validate_structural(&tx).map_err(|e| SdkError::ValidationFailed(format!("{}", e)))?;
        Ok(tx)
    }

    /// Two-pass fee estimation.
    /// Pass 1: build with fee=0 (unchecked), compute min_fee.
    /// Pass 2: rebuild with min_fee, recompute (converges in 2 passes).
    pub fn estimate_fee(&self) -> Result<u64, SdkError> {
        let mut b1 = self.clone();
        b1.fee = Some(0);
        let tx1 = b1.build_unchecked()?;
        let fee1 = fee::compute_min_fee(&tx1);

        let mut b2 = self.clone();
        b2.fee = Some(fee1);
        let tx2 = b2.build_unchecked()?;
        Ok(fee::compute_min_fee(&tx2))
    }
}
