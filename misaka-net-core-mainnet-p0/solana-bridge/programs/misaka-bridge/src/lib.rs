use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer, MintTo, Burn};

declare_id!("MBRDGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

// ─── PDA Seed Constants ──────────────────────────────────────

pub const SEED_CONFIG: &[u8]     = b"misaka-bridge-config";
pub const SEED_VAULT_AUTH: &[u8] = b"misaka-bridge-vault-auth";
pub const SEED_VAULT: &[u8]     = b"misaka-bridge-vault";
pub const SEED_ASSET: &[u8]     = b"misaka-bridge-asset";
pub const SEED_RECEIPT: &[u8]   = b"misaka-bridge-receipt";
pub const SEED_NONCE: &[u8]     = b"misaka-bridge-nonce";
/// Committee PDA: stores M-of-N threshold committee members.
pub const SEED_COMMITTEE: &[u8] = b"misaka-bridge-committee";

/// Maximum committee size.
pub const MAX_COMMITTEE_SIZE: usize = 10;

/// MISAKA <-> Solana Bridge Program (Mainnet: Threshold Committee)
///
/// # Security Model (P0 Mainnet)
///
/// - `unlock_tokens` requires **M-of-N committee member signatures**
///   (NOT a single relayer).
/// - The relayer is downgraded to a **transport-only payer** — it cannot
///   unilaterally authorize any fund movement.
/// - Replay protection via on-chain nonce state (request_id).
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

    /// Initialize the validator committee for threshold unlock.
    ///
    /// Called by admin ONCE after bridge init. Sets the M-of-N committee.
    pub fn initialize_committee(
        ctx: Context<InitCommittee>,
        threshold: u8,
        members: Vec<Pubkey>,
    ) -> Result<()> {
        require!(
            ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(),
            BridgeError::Unauthorized
        );
        require!(threshold > 0, BridgeError::InvalidThreshold);
        require!(members.len() >= threshold as usize, BridgeError::InvalidThreshold);
        require!(members.len() <= MAX_COMMITTEE_SIZE, BridgeError::CommitteeTooLarge);

        // Check no duplicate members
        let mut sorted = members.clone();
        sorted.sort();
        for i in 1..sorted.len() {
            require!(sorted[i] != sorted[i - 1], BridgeError::DuplicateCommitteeMember);
        }

        let committee = &mut ctx.accounts.committee;
        committee.threshold = threshold;
        committee.member_count = members.len() as u8;
        committee.members = [Pubkey::default(); MAX_COMMITTEE_SIZE];
        for (i, m) in members.iter().enumerate() {
            committee.members[i] = *m;
        }
        committee.bump = ctx.bumps.committee;

        emit!(CommitteeInitialized {
            threshold,
            member_count: members.len() as u8,
        });
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

        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        let config = &mut ctx.accounts.bridge_config;
        config.nonce += 1;
        config.total_locked += amount;

        let mapping = &mut ctx.accounts.asset_mapping;
        mapping.total_locked += amount;

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
            user: ctx.accounts.user.key(),
            mint: ctx.accounts.vault.mint,
            amount,
            misaka_recipient,
            nonce: config.nonce,
        });
        Ok(())
    }

    /// Unlock tokens — requires M-of-N committee member signatures.
    ///
    /// # Security (Mainnet P0)
    ///
    /// - Committee members sign this instruction (passed as remaining_accounts)
    /// - At least `committee.threshold` members must be signers
    /// - The relayer is just the payer (transport) — NOT an authority
    /// - Each request_id can only be processed once (replay protection)
    ///
    /// # remaining_accounts
    ///
    /// Committee member signers are passed as remaining accounts.
    /// Each must be `is_signer = true` and be in the committee member list.
    pub fn unlock_tokens(
        ctx: Context<UnlockTokens>,
        amount: u64,
        request_id: [u8; 32],
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        require!(!config.paused, BridgeError::BridgePaused);

        // ═══ THRESHOLD COMMITTEE VERIFICATION ═══
        let committee = &ctx.accounts.committee;
        let mut valid_sigs: u8 = 0;
        let mut seen_signers: Vec<Pubkey> = Vec::new();

        for account_info in ctx.remaining_accounts.iter() {
            // Must be a signer
            if !account_info.is_signer {
                continue;
            }

            let signer_key = account_info.key();

            // Must be a committee member
            let is_member = committee.members[..committee.member_count as usize]
                .iter()
                .any(|m| m == signer_key);

            if !is_member {
                continue; // Unknown signer — skip
            }

            // Deduplicate
            if seen_signers.contains(signer_key) {
                continue;
            }
            seen_signers.push(*signer_key);

            valid_sigs += 1;
        }

        require!(
            valid_sigs >= committee.threshold,
            BridgeError::InsufficientCommitteeSignatures
        );

        // ═══ REPLAY PROTECTION ═══
        let nonce_state = &mut ctx.accounts.nonce_state;
        require!(!nonce_state.processed, BridgeError::AlreadyProcessed);
        nonce_state.processed = true;
        nonce_state.bump = ctx.bumps.nonce_state;

        // ═══ TRANSFER ═══
        let seeds = &[SEED_VAULT_AUTH, &[config.vault_bump]];
        let signer = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.recipient_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(), cpi_accounts, signer,
        );
        token::transfer(cpi_ctx, amount)?;

        let config = &mut ctx.accounts.bridge_config;
        config.total_released += amount;

        emit!(TokensUnlocked {
            recipient: ctx.accounts.recipient_token_account.key(),
            amount,
            request_id,
            committee_sigs: valid_sigs,
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

    /// Update committee members/threshold (admin only).
    pub fn update_committee(
        ctx: Context<UpdateCommittee>,
        threshold: u8,
        members: Vec<Pubkey>,
    ) -> Result<()> {
        require!(
            ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(),
            BridgeError::Unauthorized
        );
        require!(threshold > 0, BridgeError::InvalidThreshold);
        require!(members.len() >= threshold as usize, BridgeError::InvalidThreshold);
        require!(members.len() <= MAX_COMMITTEE_SIZE, BridgeError::CommitteeTooLarge);

        let committee = &mut ctx.accounts.committee;
        committee.threshold = threshold;
        committee.member_count = members.len() as u8;
        committee.members = [Pubkey::default(); MAX_COMMITTEE_SIZE];
        for (i, m) in members.iter().enumerate() {
            committee.members[i] = *m;
        }

        emit!(CommitteeUpdated { threshold, member_count: members.len() as u8 });
        Ok(())
    }
}

// ── Accounts ──────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeBridge<'info> {
    #[account(init, payer = payer, space = 8 + BridgeConfig::LEN, seeds = [SEED_CONFIG], bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    /// CHECK: PDA authority for vaults (no data)
    #[account(seeds = [SEED_VAULT_AUTH], bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitCommittee<'info> {
    #[account(seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(init, payer = admin, space = 8 + Committee::LEN, seeds = [SEED_COMMITTEE], bump)]
    pub committee: Account<'info, Committee>,
    #[account(mut)]
    pub admin: Signer<'info>,
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
    #[account(mut)]
    pub admin: Signer<'info>,
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
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// UnlockTokens: relayer is transport-only payer.
/// Committee members sign via remaining_accounts.
#[derive(Accounts)]
#[instruction(amount: u64, request_id: [u8; 32])]
pub struct UnlockTokens<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    /// Committee state for threshold verification.
    #[account(seeds = [SEED_COMMITTEE], bump = committee.bump)]
    pub committee: Account<'info, Committee>,
    /// CHECK: PDA vault authority
    #[account(seeds = [SEED_VAULT_AUTH], bump = bridge_config.vault_bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,
    #[account(init_if_needed, payer = payer, space = 8 + NonceState::LEN,
              seeds = [SEED_NONCE, &request_id], bump)]
    pub nonce_state: Account<'info, NonceState>,
    /// Payer (was "relayer") — transport only, no authority.
    #[account(mut)]
    pub payer: Signer<'info>,
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

// ── State Accounts ────────────────────────────────────────

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
impl BridgeConfig { pub const LEN: usize = 32 + 32 + 1 + 8 + 8 + 8 + 8 + 1 + 1; }

/// Validator committee for threshold unlock authorization.
#[account]
pub struct Committee {
    /// Minimum signatures required (M in M-of-N).
    pub threshold: u8,
    /// Number of active members (N in M-of-N).
    pub member_count: u8,
    /// Committee member public keys (max MAX_COMMITTEE_SIZE).
    pub members: [Pubkey; MAX_COMMITTEE_SIZE],
    pub bump: u8,
}
impl Committee {
    pub const LEN: usize = 1 + 1 + (32 * MAX_COMMITTEE_SIZE) + 1; // 323 bytes
}

#[account]
pub struct AssetMapping {
    pub mint: Pubkey,
    pub misaka_asset_id: String,
    pub is_active: bool,
    pub total_locked: u64,
    pub bump: u8,
}
impl AssetMapping { pub const LEN: usize = 32 + 4 + 32 + 1 + 8 + 1; }

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
impl LockedReceipt { pub const LEN: usize = 32 + 32 + 8 + 4 + 64 + 8 + 8 + 1 + 1; }

#[account]
pub struct NonceState {
    pub processed: bool,
    pub bump: u8,
}
impl NonceState { pub const LEN: usize = 1 + 1; }

// ── Events ────────────────────────────────────────────────

#[event]
pub struct BridgeInitialized { pub admin: Pubkey, pub relayer: Pubkey, pub min_lock_amount: u64 }
#[event]
pub struct CommitteeInitialized { pub threshold: u8, pub member_count: u8 }
#[event]
pub struct CommitteeUpdated { pub threshold: u8, pub member_count: u8 }
#[event]
pub struct AssetRegistered { pub mint: Pubkey, pub misaka_asset_id: String }
#[event]
pub struct TokensLocked { pub user: Pubkey, pub mint: Pubkey, pub amount: u64, pub misaka_recipient: String, pub nonce: u64 }
#[event]
pub struct TokensUnlocked { pub recipient: Pubkey, pub amount: u64, pub request_id: [u8; 32], pub committee_sigs: u8 }
#[event]
pub struct BridgePaused {}
#[event]
pub struct BridgeUnpaused {}

// ── Errors ────────────────────────────────────────────────

#[error_code]
pub enum BridgeError {
    #[msg("Bridge is paused")]
    BridgePaused,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Amount below minimum")]
    AmountTooSmall,
    #[msg("Request already processed")]
    AlreadyProcessed,
    #[msg("Invalid asset")]
    InvalidAsset,
    #[msg("Insufficient committee signatures for threshold")]
    InsufficientCommitteeSignatures,
    #[msg("Invalid threshold (must be > 0 and <= member count)")]
    InvalidThreshold,
    #[msg("Committee exceeds maximum size")]
    CommitteeTooLarge,
    #[msg("Duplicate committee member")]
    DuplicateCommitteeMember,
}
