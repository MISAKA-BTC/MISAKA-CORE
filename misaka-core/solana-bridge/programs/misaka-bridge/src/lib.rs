use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer, MintTo, Burn};

declare_id!("MBRDGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

pub const SEED_CONFIG: &[u8]     = b"misaka-bridge-config";
pub const SEED_VAULT_AUTH: &[u8] = b"misaka-bridge-vault-auth";
pub const SEED_VAULT: &[u8]     = b"misaka-bridge-vault";
pub const SEED_ASSET: &[u8]     = b"misaka-bridge-asset";
pub const SEED_RECEIPT: &[u8]   = b"misaka-bridge-receipt";
pub const SEED_NONCE: &[u8]     = b"misaka-bridge-nonce";
pub const SEED_COMMITTEE: &[u8] = b"misaka-bridge-committee";

pub const MAX_COMMITTEE_SIZE: usize = 10;
/// MISAKA chain_id for testnet (used in request_id derivation).
pub const MISAKA_CHAIN_ID: u32 = 2;

/// Ed25519 signature verification via Solana's Ed25519 precompile.
///
/// # Security (MAINNET)
///
/// Walks ALL instructions in the transaction and ALL signature entries
/// within each Ed25519 precompile instruction. Validates that:
/// - The signature data references the SAME instruction (ix_index == 0xFFFF)
/// - Offsets are within bounds
/// - Pubkey, message, and signature match the expected values
///
/// The Solana runtime has already cryptographically verified the Ed25519
/// signature — this function confirms the verified tuple matches our expected data.
fn verify_ed25519_sig_via_ixs(
    instructions_sysvar: &AccountInfo,
    pubkey: &Pubkey,
    message: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    use anchor_lang::solana_program::sysvar::instructions as ix_sysvar;
    use anchor_lang::solana_program::ed25519_program;

    // Size of one signature entry header in Ed25519 instruction data
    const SIG_ENTRY_SIZE: usize = 14; // 7 × u16

    let mut idx: u16 = 0;
    loop {
        let ix = match ix_sysvar::load_instruction_at_checked(idx as usize, instructions_sysvar) {
            Ok(ix) => ix,
            Err(_) => break,
        };

        if ix.program_id != ed25519_program::id() {
            idx += 1;
            continue;
        }

        if ix.data.len() < 2 {
            idx += 1;
            continue;
        }

        let num_sigs = ix.data[0] as usize;
        if num_sigs == 0 {
            idx += 1;
            continue;
        }

        // Minimum data: 2 (header) + num_sigs * 14 (entries) + at least one sig+pk+msg
        let min_header = 2 + num_sigs * SIG_ENTRY_SIZE;
        if ix.data.len() < min_header {
            idx += 1;
            continue;
        }

        // Iterate ALL signature entries in this Ed25519 instruction
        for sig_idx in 0..num_sigs {
            let entry_offset = 2 + sig_idx * SIG_ENTRY_SIZE;

            // Parse the 7 u16 fields for this signature entry
            let sig_data_offset = u16::from_le_bytes([
                ix.data[entry_offset], ix.data[entry_offset + 1]
            ]) as usize;
            let sig_ix_index = u16::from_le_bytes([
                ix.data[entry_offset + 2], ix.data[entry_offset + 3]
            ]);
            let pk_data_offset = u16::from_le_bytes([
                ix.data[entry_offset + 4], ix.data[entry_offset + 5]
            ]) as usize;
            let pk_ix_index = u16::from_le_bytes([
                ix.data[entry_offset + 6], ix.data[entry_offset + 7]
            ]);
            let msg_data_offset = u16::from_le_bytes([
                ix.data[entry_offset + 8], ix.data[entry_offset + 9]
            ]) as usize;
            let msg_data_size = u16::from_le_bytes([
                ix.data[entry_offset + 10], ix.data[entry_offset + 11]
            ]) as usize;
            let msg_ix_index = u16::from_le_bytes([
                ix.data[entry_offset + 12], ix.data[entry_offset + 13]
            ]);

            // Validate ix_index: 0xFFFF means data is in THIS instruction.
            // We only accept signatures whose data is embedded in the same
            // Ed25519 instruction, not references to other instructions.
            if sig_ix_index != 0xFFFF || pk_ix_index != 0xFFFF || msg_ix_index != 0xFFFF {
                continue;
            }

            // Message must be exactly 32 bytes (our request_id)
            if msg_data_size != 32 {
                continue;
            }

            // Bounds checks on all offsets
            if sig_data_offset + 64 > ix.data.len() { continue; }
            if pk_data_offset + 32 > ix.data.len() { continue; }
            if msg_data_offset + msg_data_size > ix.data.len() { continue; }

            // Extract and compare
            let ix_sig = &ix.data[sig_data_offset..sig_data_offset + 64];
            let ix_pk = &ix.data[pk_data_offset..pk_data_offset + 32];
            let ix_msg = &ix.data[msg_data_offset..msg_data_offset + msg_data_size];

            if ix_pk == pubkey.as_ref()
                && ix_msg == message.as_ref()
                && ix_sig == signature.as_ref()
            {
                return true;
            }
        }

        idx += 1;
    }
    false
}
#[program]
pub mod misaka_bridge {
    use super::*;

    pub fn initialize_bridge(
        ctx: Context<InitializeBridge>,
        admin: Pubkey,
        relayer: Pubkey,
        min_lock_amount: u64,
    ) -> Result<()> {
        let config = &mut ctx.accounts.bridge_config;
        config.admin = admin;
        config.relayer = relayer;
        config.paused = false;
        config.min_lock_amount = min_lock_amount;
        config.total_locked = 0;
        config.total_released = 0;
        config.nonce = 0;
        config.bump = ctx.bumps.bridge_config;
        config.vault_bump = ctx.bumps.vault_authority;
        emit!(BridgeInitialized { admin, relayer, min_lock_amount });
        Ok(())
    }

    pub fn initialize_committee(
        ctx: Context<InitCommittee>,
        threshold: u8,
        members: Vec<Pubkey>,
    ) -> Result<()> {
        require!(ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(), BridgeError::Unauthorized);
        require!(threshold > 0 && threshold as usize <= members.len(), BridgeError::InvalidThreshold);
        require!(members.len() <= MAX_COMMITTEE_SIZE, BridgeError::CommitteeTooLarge);
        let mut sorted = members.clone();
        sorted.sort();
        for i in 1..sorted.len() {
            require!(sorted[i] != sorted[i - 1], BridgeError::DuplicateCommitteeMember);
        }
        let committee = &mut ctx.accounts.committee;
        committee.threshold = threshold;
        committee.member_count = members.len() as u8;
        committee.members = [Pubkey::default(); MAX_COMMITTEE_SIZE];
        for (i, m) in members.iter().enumerate() { committee.members[i] = *m; }
        committee.bump = ctx.bumps.committee;
        emit!(CommitteeInitialized { threshold, member_count: members.len() as u8 });
        Ok(())
    }

    pub fn register_asset(
        ctx: Context<RegisterAsset>,
        misaka_asset_id: String,
    ) -> Result<()> {
        require!(!ctx.accounts.bridge_config.paused, BridgeError::BridgePaused);
        require!(ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(), BridgeError::Unauthorized);
        require!(misaka_asset_id.len() <= 32, BridgeError::InvalidAsset);
        let mapping = &mut ctx.accounts.asset_mapping;
        mapping.mint = ctx.accounts.mint.key();
        mapping.misaka_asset_id = misaka_asset_id.clone();
        mapping.is_active = true;
        mapping.total_locked = 0;
        mapping.bump = ctx.bumps.asset_mapping;
        emit!(AssetRegistered { mint: ctx.accounts.mint.key(), misaka_asset_id });
        Ok(())
    }

    pub fn lock_tokens(
        ctx: Context<LockTokens>,
        amount: u64,
        misaka_recipient: String,
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        require!(!config.paused, BridgeError::BridgePaused);
        require!(amount >= config.min_lock_amount, BridgeError::AmountTooSmall);
        let cpi = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi), amount)?;
        let config = &mut ctx.accounts.bridge_config;
        config.nonce += 1;
        config.total_locked = config.total_locked.checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        let mapping = &mut ctx.accounts.asset_mapping;
        mapping.total_locked = mapping.total_locked.checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;
        let receipt = &mut ctx.accounts.locked_receipt;
        receipt.user = ctx.accounts.user.key();
        receipt.mint = ctx.accounts.vault.mint;
        receipt.amount = amount;
        receipt.misaka_recipient = misaka_recipient.clone();
        receipt.nonce = config.nonce;
        receipt.timestamp = Clock::get()?.unix_timestamp;
        receipt.processed = false;
        receipt.bump = ctx.bumps.locked_receipt;
        emit!(TokensLocked {
            user: ctx.accounts.user.key(), mint: ctx.accounts.vault.mint,
            amount, misaka_recipient, nonce: config.nonce,
        });
        Ok(())
    }

    /// Unlock tokens — M-of-N committee + message-bound authorization.
    ///
    /// # Security (Mainnet P0)
    ///
    /// 1. Asset validation: asset_mapping.is_active, mint consistency
    /// 2. request_id recomputation: NOT blindly trusted from args
    /// 3. Committee threshold: M-of-N signers from remaining_accounts
    /// 4. Message-bound auth: committee signs the computed request_id
    /// 5. Replay protection: nonce_state prevents double-processing
    pub fn unlock_tokens(
        ctx: Context<UnlockTokens>,
        amount: u64,
        _request_id_arg: [u8; 32], // NOT trusted — recomputed below
        source_tx_hash: [u8; 32],
        unlock_nonce: u64,
        committee_signatures: Vec<[u8; 64]>, // Ed25519 sigs over computed_request_id
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        require!(!config.paused, BridgeError::BridgePaused);

        // ── 1. Asset validation ──
        let asset = &ctx.accounts.asset_mapping;
        require!(asset.is_active, BridgeError::AssetNotActive);
        require!(ctx.accounts.vault.mint == asset.mint, BridgeError::MintMismatch);
        require!(ctx.accounts.recipient_token_account.mint == asset.mint, BridgeError::MintMismatch);

        // ── 2. Recompute request_id (DO NOT blindly trust args) ──
        let computed_request_id = hashv(&[
            b"MISAKA_BRIDGE_UNLOCK_V2:",
            &MISAKA_CHAIN_ID.to_le_bytes(),
            &source_tx_hash,
            asset.misaka_asset_id.as_bytes(),
            &ctx.accounts.recipient_token_account.key().to_bytes(),
            &amount.to_le_bytes(),
            &unlock_nonce.to_le_bytes(),
        ]).to_bytes();

        // ── 3. Ed25519 message-bound committee verification ──
        // Each signature is verified against committee member pubkeys
        // and the computed_request_id (message). This is MESSAGE-BOUND.
        let committee = &ctx.accounts.committee;
        require!(
            committee_signatures.len() <= committee.member_count as usize,
            BridgeError::TooManySignatures
        );
        let mut valid_sigs: u8 = 0;
        let mut verified: Vec<Pubkey> = Vec::with_capacity(committee.member_count as usize);
        for sig in &committee_signatures {
            for pk in committee.members[..committee.member_count as usize].iter() {
                if verified.contains(pk) { continue; }
                if verify_ed25519_sig_via_ixs(
                    &ctx.accounts.instructions_sysvar,
                    pk, &computed_request_id, sig,
                ) {
                    verified.push(*pk);
                    valid_sigs += 1;
                    break;
                }
            }
        }
        require!(valid_sigs >= committee.threshold, BridgeError::InsufficientCommitteeSignatures);

        // ── 4. Replay protection with COMPUTED request_id ──
        let nonce_state = &mut ctx.accounts.nonce_state;
        require!(!nonce_state.processed, BridgeError::AlreadyProcessed);
        nonce_state.processed = true;
        nonce_state.request_id = computed_request_id;
        nonce_state.bump = ctx.bumps.nonce_state;

        // ── 5. Transfer ──
        let seeds = &[SEED_VAULT_AUTH, &[config.vault_bump]];
        let signer = &[&seeds[..]];
        let cpi = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.recipient_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };
        token::transfer(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(), cpi, signer,
        ), amount)?;

        let config = &mut ctx.accounts.bridge_config;
        config.total_released = config.total_released.checked_add(amount)
            .ok_or(BridgeError::ArithmeticOverflow)?;

        emit!(TokensUnlocked {
            recipient: ctx.accounts.recipient_token_account.key(),
            amount,
            request_id: computed_request_id,
            committee_sigs: valid_sigs,
            source_tx_hash,
            asset_id: asset.misaka_asset_id.clone(),
            unlock_nonce,
        });
        Ok(())
    }

    pub fn pause_bridge(ctx: Context<AdminAction>) -> Result<()> {
        require!(ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(), BridgeError::Unauthorized);
        ctx.accounts.bridge_config.paused = true;
        emit!(BridgePaused {});
        Ok(())
    }

    pub fn unpause_bridge(ctx: Context<AdminAction>) -> Result<()> {
        require!(ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(), BridgeError::Unauthorized);
        ctx.accounts.bridge_config.paused = false;
        emit!(BridgeUnpaused {});
        Ok(())
    }

    pub fn update_committee(
        ctx: Context<UpdateCommittee>,
        threshold: u8,
        members: Vec<Pubkey>,
    ) -> Result<()> {
        require!(ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(), BridgeError::Unauthorized);
        require!(threshold > 0 && threshold as usize <= members.len(), BridgeError::InvalidThreshold);
        require!(members.len() <= MAX_COMMITTEE_SIZE, BridgeError::CommitteeTooLarge);
        // Duplicate member check (same as initialize_committee)
        let mut sorted = members.clone();
        sorted.sort();
        for i in 1..sorted.len() {
            require!(sorted[i] != sorted[i - 1], BridgeError::DuplicateCommitteeMember);
        }
        let committee = &mut ctx.accounts.committee;
        committee.threshold = threshold;
        committee.member_count = members.len() as u8;
        committee.members = [Pubkey::default(); MAX_COMMITTEE_SIZE];
        for (i, m) in members.iter().enumerate() { committee.members[i] = *m; }
        emit!(CommitteeUpdated { threshold, member_count: members.len() as u8 });
        Ok(())
    }
}

// ── Accounts ──────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeBridge<'info> {
    #[account(init, payer = payer, space = 8 + BridgeConfig::LEN, seeds = [SEED_CONFIG], bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(seeds = [SEED_VAULT_AUTH], bump)]
    /// CHECK: PDA authority
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)] pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitCommittee<'info> {
    #[account(seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(init, payer = admin, space = 8 + Committee::LEN, seeds = [SEED_COMMITTEE], bump)]
    pub committee: Account<'info, Committee>,
    #[account(mut)] pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(misaka_asset_id: String)]
pub struct RegisterAsset<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(init, payer = admin, space = 8 + AssetMapping::LEN,
              seeds = [SEED_ASSET, misaka_asset_id.as_bytes()], bump)]
    pub asset_mapping: Account<'info, AssetMapping>,
    pub mint: Account<'info, Mint>,
    #[account(mut)] pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount: u64, misaka_recipient: String)]
pub struct LockTokens<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(mut, seeds = [SEED_ASSET, asset_mapping.misaka_asset_id.as_bytes()], bump = asset_mapping.bump)]
    pub asset_mapping: Account<'info, AssetMapping>,
    #[account(mut, constraint = user_token_account.mint == vault.mint)]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [SEED_VAULT, vault.mint.as_ref()], bump)]
    pub vault: Account<'info, TokenAccount>,
    #[account(init, payer = user, space = 8 + LockedReceipt::LEN,
              seeds = [SEED_RECEIPT, &bridge_config.nonce.to_le_bytes()], bump)]
    pub locked_receipt: Account<'info, LockedReceipt>,
    #[account(mut)] pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// UnlockTokens — committee auth + asset validation + request_id recomputation.
#[derive(Accounts)]
#[instruction(amount: u64, _request_id_arg: [u8; 32], source_tx_hash: [u8; 32], unlock_nonce: u64)]
pub struct UnlockTokens<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(seeds = [SEED_COMMITTEE], bump = committee.bump)]
    pub committee: Account<'info, Committee>,
    /// Asset mapping — MUST be active, mint MUST match vault.
    #[account(seeds = [SEED_ASSET, asset_mapping.misaka_asset_id.as_bytes()], bump = asset_mapping.bump)]
    pub asset_mapping: Account<'info, AssetMapping>,
    #[account(seeds = [SEED_VAULT_AUTH], bump = bridge_config.vault_bump)]
    /// CHECK: PDA vault authority
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,
    /// Nonce state seeded by COMPUTED request_id (not arg).
    #[account(init_if_needed, payer = payer, space = 8 + NonceState::LEN,
              seeds = [SEED_NONCE, &hashv(&[
                  b"MISAKA_BRIDGE_UNLOCK_V2:",
                  &MISAKA_CHAIN_ID.to_le_bytes(),
                  &source_tx_hash,
                  asset_mapping.misaka_asset_id.as_bytes(),
                  &recipient_token_account.key().to_bytes(),
                  &amount.to_le_bytes(),
                  &unlock_nonce.to_le_bytes(),
              ]).to_bytes()], bump)]
    pub nonce_state: Account<'info, NonceState>,
    /// Payer (transport only — NO authority).
    #[account(mut)] pub payer: Signer<'info>,
    /// Instructions sysvar — required for Ed25519 precompile verification.
    /// CHECK: validated by address constraint below
    #[account(address = anchor_lang::solana_program::sysvar::instructions::id())]
    pub instructions_sysvar: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateCommittee<'info> {
    #[account(seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(mut, seeds = [SEED_COMMITTEE], bump = committee.bump)]
    pub committee: Account<'info, Committee>,
    pub admin: Signer<'info>,
}

// ── State ─────────────────────────────────────────────────

#[account]
pub struct BridgeConfig {
    pub admin: Pubkey,
    pub relayer: Pubkey,
    pub paused: bool,
    pub min_lock_amount: u64,
    pub total_locked: u64,
    pub total_released: u64,
    pub nonce: u64,
    pub bump: u8,
    pub vault_bump: u8,
}
impl BridgeConfig { pub const LEN: usize = 32+32+1+8+8+8+8+1+1; }

#[account]
pub struct Committee {
    pub threshold: u8,
    pub member_count: u8,
    pub members: [Pubkey; MAX_COMMITTEE_SIZE],
    pub bump: u8,
}
impl Committee { pub const LEN: usize = 1+1+(32*MAX_COMMITTEE_SIZE)+1; }

#[account]
pub struct AssetMapping {
    pub mint: Pubkey,
    pub misaka_asset_id: String,
    pub is_active: bool,
    pub total_locked: u64,
    pub bump: u8,
}
impl AssetMapping { pub const LEN: usize = 32+4+32+1+8+1; }

#[account]
pub struct LockedReceipt {
    pub user: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    pub misaka_recipient: String,
    pub nonce: u64,
    pub timestamp: i64,
    pub processed: bool,
    pub bump: u8,
}
impl LockedReceipt { pub const LEN: usize = 32+32+8+4+64+8+8+1+1; }

#[account]
pub struct NonceState {
    pub processed: bool,
    pub request_id: [u8; 32],
    pub bump: u8,
}
impl NonceState { pub const LEN: usize = 1+32+1; }

// ── Events ────────────────────────────────────────────────

#[event] pub struct BridgeInitialized { pub admin: Pubkey, pub relayer: Pubkey, pub min_lock_amount: u64 }
#[event] pub struct CommitteeInitialized { pub threshold: u8, pub member_count: u8 }
#[event] pub struct CommitteeUpdated { pub threshold: u8, pub member_count: u8 }
#[event] pub struct AssetRegistered { pub mint: Pubkey, pub misaka_asset_id: String }
#[event] pub struct TokensLocked { pub user: Pubkey, pub mint: Pubkey, pub amount: u64, pub misaka_recipient: String, pub nonce: u64 }
#[event] pub struct TokensUnlocked {
    pub recipient: Pubkey,
    pub amount: u64,
    pub request_id: [u8; 32],
    pub committee_sigs: u8,
    pub source_tx_hash: [u8; 32],
    pub asset_id: String,
    pub unlock_nonce: u64,
}
#[event] pub struct BridgePaused {}
#[event] pub struct BridgeUnpaused {}

// ── Errors ────────────────────────────────────────────────

#[error_code]
pub enum BridgeError {
    #[msg("Bridge is paused")] BridgePaused,
    #[msg("Unauthorized")] Unauthorized,
    #[msg("Amount below minimum")] AmountTooSmall,
    #[msg("Already processed")] AlreadyProcessed,
    #[msg("Invalid asset")] InvalidAsset,
    #[msg("Asset not active")] AssetNotActive,
    #[msg("Mint mismatch between vault/recipient/asset")] MintMismatch,
    #[msg("Insufficient committee signatures")] InsufficientCommitteeSignatures,
    #[msg("Invalid threshold")] InvalidThreshold,
    #[msg("Committee too large")] CommitteeTooLarge,
    #[msg("Duplicate committee member")] DuplicateCommitteeMember,
    #[msg("Too many signatures")] TooManySignatures,
    #[msg("Arithmetic overflow")] ArithmeticOverflow,
}
