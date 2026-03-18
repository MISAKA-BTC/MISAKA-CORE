use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer, MintTo, Burn};

declare_id!("MBRDGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

// ─── PDA Seed Constants (centralized) ────────────────────────
//
// All seeds prefixed with "misaka-bridge-" to prevent cross-program collision.
// Version byte 0x01 included in data-bearing PDAs for future migration.

/// Bridge config singleton.
pub const SEED_CONFIG: &[u8]          = b"misaka-bridge-config";
/// PDA authority that controls all vaults (no data account).
pub const SEED_VAULT_AUTH: &[u8]      = b"misaka-bridge-vault-auth";
/// Per-asset token vault: [SEED_VAULT, mint_pubkey].
pub const SEED_VAULT: &[u8]          = b"misaka-bridge-vault";
/// Per-asset mapping: [SEED_ASSET, misaka_asset_id_bytes].
pub const SEED_ASSET: &[u8]          = b"misaka-bridge-asset";
/// Lock receipt: [SEED_RECEIPT, nonce_le_bytes].
pub const SEED_RECEIPT: &[u8]        = b"misaka-bridge-receipt";
/// Replay nonce (unlock): [SEED_NONCE, request_id_32].
pub const SEED_NONCE: &[u8]          = b"misaka-bridge-nonce";

/// MISAKA <-> Solana Bridge Program
///
/// PDA Seed Reference:
///   config:         [SEED_CONFIG]
///   vault_auth:     [SEED_VAULT_AUTH]
///   vault:          [SEED_VAULT, mint.key()]
///   asset_mapping:  [SEED_ASSET, misaka_asset_id.as_bytes()]
///   locked_receipt: [SEED_RECEIPT, nonce.to_le_bytes()]
///   nonce_state:    [SEED_NONCE, request_id]
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

    pub fn unlock_tokens(
        ctx: Context<UnlockTokens>,
        amount: u64,
        request_id: [u8; 32],
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        require!(!config.paused, BridgeError::BridgePaused);
        require!(config.relayer == ctx.accounts.relayer.key(), BridgeError::Unauthorized);

        let nonce_state = &mut ctx.accounts.nonce_state;
        require!(!nonce_state.processed, BridgeError::AlreadyProcessed);
        nonce_state.processed = true;
        nonce_state.bump = ctx.bumps.nonce_state;

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

        emit!(TokensUnlocked { recipient: ctx.accounts.recipient_token_account.key(), amount, request_id });
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

    pub fn rotate_relayer(ctx: Context<AdminAction>, new_relayer: Pubkey) -> Result<()> {
        require!(ctx.accounts.bridge_config.admin == ctx.accounts.admin.key(), BridgeError::Unauthorized);
        let old = ctx.accounts.bridge_config.relayer;
        ctx.accounts.bridge_config.relayer = new_relayer;
        emit!(RelayerRotated { old_relayer: old, new_relayer });
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

#[derive(Accounts)]
#[instruction(amount: u64, request_id: [u8; 32])]
pub struct UnlockTokens<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    /// CHECK: PDA vault authority
    #[account(seeds = [SEED_VAULT_AUTH], bump = bridge_config.vault_bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,
    #[account(init_if_needed, payer = relayer, space = 8 + NonceState::LEN,
              seeds = [SEED_NONCE, &request_id], bump)]
    pub nonce_state: Account<'info, NonceState>,
    #[account(mut)]
    pub relayer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
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
pub struct AssetRegistered { pub mint: Pubkey, pub misaka_asset_id: String }
#[event]
pub struct TokensLocked { pub user: Pubkey, pub mint: Pubkey, pub amount: u64, pub misaka_recipient: String, pub nonce: u64 }
#[event]
pub struct TokensUnlocked { pub recipient: Pubkey, pub amount: u64, pub request_id: [u8; 32] }
#[event]
pub struct BridgePaused {}
#[event]
pub struct BridgeUnpaused {}
#[event]
pub struct RelayerRotated { pub old_relayer: Pubkey, pub new_relayer: Pubkey }

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
}
