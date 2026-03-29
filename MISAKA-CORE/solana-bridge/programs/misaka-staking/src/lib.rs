use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer};

declare_id!("MSKSTKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

pub const SEED_STAKING_CONFIG: &[u8] = b"misaka-staking-config";
pub const SEED_VAULT_AUTH: &[u8] = b"misaka-staking-vault-auth";
pub const SEED_VAULT: &[u8] = b"misaka-staking-vault";
pub const SEED_VALIDATOR_STAKE: &[u8] = b"misaka-validator-stake";

/// Maximum L1 public key length (hex-encoded, 64 chars = 32 bytes).
pub const L1_PUBKEY_MAX_LEN: usize = 64;

/// Default unbonding period: 7 days in slots (at ~400ms/slot).
pub const DEFAULT_UNBONDING_SLOTS: u64 = 1_512_000; // ~7 days

#[program]
pub mod misaka_staking {
    use super::*;

    /// Initialize the staking program. Called once by admin.
    ///
    /// Sets the minimum stake amounts for testnet and mainnet.
    /// MISAKA uses 9 decimals: 1 MISAKA = 1_000_000_000 base units.
    pub fn initialize(
        ctx: Context<Initialize>,
        admin: Pubkey,
        /// Minimum stake in base units (9 decimals).
        /// Testnet: 1_000_000_000_000_000 (1M MISAKA)
        /// Mainnet: 10_000_000_000_000_000 (10M MISAKA)
        min_stake: u64,
        /// Unbonding period in Solana slots.
        unbonding_slots: u64,
    ) -> Result<()> {
        let config = &mut ctx.accounts.staking_config;
        config.admin = admin;
        config.min_stake = min_stake;
        config.unbonding_slots = if unbonding_slots == 0 {
            DEFAULT_UNBONDING_SLOTS
        } else {
            unbonding_slots
        };
        config.total_staked = 0;
        config.total_validators = 0;
        config.paused = false;
        config.bump = ctx.bumps.staking_config;
        config.vault_bump = ctx.bumps.vault_authority;

        emit!(StakingInitialized {
            admin,
            min_stake,
            unbonding_slots: config.unbonding_slots,
        });
        Ok(())
    }

    /// Stake tokens to become an L1 validator.
    ///
    /// # On-Chain Enforcement
    ///
    /// - `amount >= config.min_stake` — enforced on-chain, cannot be bypassed
    /// - `l1_public_key` must be exactly 64 hex chars (32 bytes)
    /// - One L1 key can only be staked ONCE (PDA seed = l1_public_key)
    /// - Tokens are transferred to the program vault (user cannot access)
    ///
    /// # Events
    ///
    /// Emits `ValidatorStaked` which the L1 node parses via Solana RPC
    /// to verify stake amount, L1 key binding, and program ID.
    pub fn stake_validator(
        ctx: Context<StakeValidator>,
        amount: u64,
        l1_public_key: String,
        node_name: String,
    ) -> Result<()> {
        let config = &ctx.accounts.staking_config;
        require!(!config.paused, StakingError::StakingPaused);

        // ── Minimum stake enforcement (ON-CHAIN, cannot be bypassed) ──
        require!(
            amount >= config.min_stake,
            StakingError::BelowMinimumStake
        );

        // ── L1 public key validation ──
        require!(
            l1_public_key.len() == L1_PUBKEY_MAX_LEN,
            StakingError::InvalidL1PublicKey
        );
        // Verify it's valid hex
        for c in l1_public_key.chars() {
            require!(c.is_ascii_hexdigit(), StakingError::InvalidL1PublicKey);
        }

        // ── Node name validation ──
        require!(
            !node_name.is_empty() && node_name.len() <= 64,
            StakingError::InvalidNodeName
        );

        // ── Transfer tokens to vault ──
        let cpi = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        token::transfer(
            CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi),
            amount,
        )?;

        // ── Create validator stake account (PDA seeded by L1 key) ──
        let stake = &mut ctx.accounts.validator_stake;
        stake.user = ctx.accounts.user.key();
        stake.l1_public_key = l1_public_key.clone();
        stake.node_name = node_name.clone();
        stake.amount = amount;
        stake.staked_at = Clock::get()?.slot;
        stake.unstake_requested_at = None;
        stake.is_active = true;
        stake.bump = ctx.bumps.validator_stake;

        // ── Update global state ──
        let config = &mut ctx.accounts.staking_config;
        config.total_staked = config
            .total_staked
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        config.total_validators = config
            .total_validators
            .checked_add(1)
            .ok_or(StakingError::ArithmeticOverflow)?;

        emit!(ValidatorStaked {
            user: ctx.accounts.user.key(),
            l1_public_key,
            node_name,
            amount,
            mint: ctx.accounts.vault.mint,
            staked_at: stake.staked_at,
        });

        Ok(())
    }

    /// Request unstaking. Starts the unbonding period.
    ///
    /// Tokens remain locked until `complete_unstake` is called
    /// after the unbonding period has elapsed.
    pub fn unstake_validator(ctx: Context<UnstakeValidator>) -> Result<()> {
        let stake = &mut ctx.accounts.validator_stake;
        require!(stake.is_active, StakingError::AlreadyUnstaking);
        require!(
            stake.user == ctx.accounts.user.key(),
            StakingError::Unauthorized
        );

        let current_slot = Clock::get()?.slot;
        stake.unstake_requested_at = Some(current_slot);
        stake.is_active = false;

        emit!(UnstakeRequested {
            user: ctx.accounts.user.key(),
            l1_public_key: stake.l1_public_key.clone(),
            amount: stake.amount,
            unstake_slot: current_slot,
            unlock_slot: current_slot + ctx.accounts.staking_config.unbonding_slots,
        });

        Ok(())
    }

    /// Complete unstaking after unbonding period. Returns tokens to user.
    pub fn complete_unstake(ctx: Context<CompleteUnstake>) -> Result<()> {
        let stake = &ctx.accounts.validator_stake;
        require!(!stake.is_active, StakingError::StillActive);
        require!(
            stake.user == ctx.accounts.user.key(),
            StakingError::Unauthorized
        );

        let unstake_slot = stake
            .unstake_requested_at
            .ok_or(StakingError::UnstakeNotRequested)?;
        let current_slot = Clock::get()?.slot;
        let config = &ctx.accounts.staking_config;

        require!(
            current_slot >= unstake_slot + config.unbonding_slots,
            StakingError::UnbondingNotComplete
        );

        // ── Transfer tokens back to user ──
        let amount = stake.amount;
        let seeds = &[SEED_VAULT_AUTH, &[config.vault_bump]];
        let signer = &[&seeds[..]];
        let cpi = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi,
                signer,
            ),
            amount,
        )?;

        // ── Update global state ──
        let config = &mut ctx.accounts.staking_config;
        config.total_staked = config.total_staked.saturating_sub(amount);
        config.total_validators = config.total_validators.saturating_sub(1);

        emit!(UnstakeCompleted {
            user: ctx.accounts.user.key(),
            l1_public_key: stake.l1_public_key.clone(),
            amount,
        });

        Ok(())
    }

    /// Admin: pause/unpause staking.
    pub fn set_paused(ctx: Context<AdminAction>, paused: bool) -> Result<()> {
        require!(
            ctx.accounts.staking_config.admin == ctx.accounts.admin.key(),
            StakingError::Unauthorized
        );
        ctx.accounts.staking_config.paused = paused;
        Ok(())
    }

    /// Admin: update minimum stake.
    pub fn update_min_stake(ctx: Context<AdminAction>, new_min_stake: u64) -> Result<()> {
        require!(
            ctx.accounts.staking_config.admin == ctx.accounts.admin.key(),
            StakingError::Unauthorized
        );
        require!(new_min_stake > 0, StakingError::InvalidMinStake);
        ctx.accounts.staking_config.min_stake = new_min_stake;
        emit!(MinStakeUpdated {
            new_min_stake,
        });
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Accounts
// ═══════════════════════════════════════════════════════════════

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + StakingConfig::LEN,
        seeds = [SEED_STAKING_CONFIG],
        bump,
    )]
    pub staking_config: Account<'info, StakingConfig>,
    #[account(seeds = [SEED_VAULT_AUTH], bump)]
    /// CHECK: PDA authority for the vault
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount: u64, l1_public_key: String)]
pub struct StakeValidator<'info> {
    #[account(mut, seeds = [SEED_STAKING_CONFIG], bump = staking_config.bump)]
    pub staking_config: Account<'info, StakingConfig>,

    /// Validator stake account — PDA seeded by L1 public key.
    /// This ensures ONE L1 key = ONE stake. If the L1 key is already
    /// staked, Anchor will fail with "already initialized".
    #[account(
        init,
        payer = user,
        space = 8 + ValidatorStake::LEN,
        seeds = [SEED_VALIDATOR_STAKE, l1_public_key.as_bytes()],
        bump,
    )]
    pub validator_stake: Account<'info, ValidatorStake>,

    #[account(mut, constraint = user_token_account.mint == vault.mint)]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [SEED_VAULT, vault.mint.as_ref()],
        bump,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnstakeValidator<'info> {
    #[account(seeds = [SEED_STAKING_CONFIG], bump = staking_config.bump)]
    pub staking_config: Account<'info, StakingConfig>,
    #[account(
        mut,
        seeds = [SEED_VALIDATOR_STAKE, validator_stake.l1_public_key.as_bytes()],
        bump = validator_stake.bump,
    )]
    pub validator_stake: Account<'info, ValidatorStake>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct CompleteUnstake<'info> {
    #[account(mut, seeds = [SEED_STAKING_CONFIG], bump = staking_config.bump)]
    pub staking_config: Account<'info, StakingConfig>,
    #[account(
        mut,
        seeds = [SEED_VALIDATOR_STAKE, validator_stake.l1_public_key.as_bytes()],
        bump = validator_stake.bump,
        close = user,
    )]
    pub validator_stake: Account<'info, ValidatorStake>,
    #[account(seeds = [SEED_VAULT_AUTH], bump = staking_config.vault_bump)]
    /// CHECK: PDA vault authority
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(mut, seeds = [SEED_STAKING_CONFIG], bump = staking_config.bump)]
    pub staking_config: Account<'info, StakingConfig>,
    pub admin: Signer<'info>,
}

// ═══════════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════════

#[account]
pub struct StakingConfig {
    pub admin: Pubkey,
    pub min_stake: u64,
    pub unbonding_slots: u64,
    pub total_staked: u64,
    pub total_validators: u64,
    pub paused: bool,
    pub bump: u8,
    pub vault_bump: u8,
}

impl StakingConfig {
    // 32 + 8 + 8 + 8 + 8 + 1 + 1 + 1 = 67
    pub const LEN: usize = 32 + 8 + 8 + 8 + 8 + 1 + 1 + 1;
}

#[account]
pub struct ValidatorStake {
    /// Solana wallet that staked.
    pub user: Pubkey,
    /// L1 public key (hex, 64 chars). Binds this stake to ONE L1 validator.
    pub l1_public_key: String,
    /// Human-readable node name.
    pub node_name: String,
    /// Staked amount in base units (9 decimals).
    pub amount: u64,
    /// Slot at which the stake was created.
    pub staked_at: u64,
    /// Slot at which unstake was requested (None = still active).
    pub unstake_requested_at: Option<u64>,
    /// Whether the validator is actively staked.
    pub is_active: bool,
    /// PDA bump.
    pub bump: u8,
}

impl ValidatorStake {
    // 32 + (4+64) + (4+64) + 8 + 8 + (1+8) + 1 + 1 = 195
    pub const LEN: usize = 32 + (4 + 64) + (4 + 64) + 8 + 8 + (1 + 8) + 1 + 1;
}

// ═══════════════════════════════════════════════════════════════
//  Events — parsed by L1 node via Solana RPC
// ═══════════════════════════════════════════════════════════════

#[event]
pub struct StakingInitialized {
    pub admin: Pubkey,
    pub min_stake: u64,
    pub unbonding_slots: u64,
}

/// Emitted when a validator stakes tokens.
///
/// The L1 node verifies this event by:
/// 1. Fetching the TX via `getTransaction(signature, finalized)`
/// 2. Parsing `ValidatorStaked` from program logs
/// 3. Checking: amount >= min_stake, l1_public_key matches, program_id matches
#[event]
pub struct ValidatorStaked {
    pub user: Pubkey,
    pub l1_public_key: String,
    pub node_name: String,
    pub amount: u64,
    pub mint: Pubkey,
    pub staked_at: u64,
}

#[event]
pub struct UnstakeRequested {
    pub user: Pubkey,
    pub l1_public_key: String,
    pub amount: u64,
    pub unstake_slot: u64,
    pub unlock_slot: u64,
}

#[event]
pub struct UnstakeCompleted {
    pub user: Pubkey,
    pub l1_public_key: String,
    pub amount: u64,
}

#[event]
pub struct MinStakeUpdated {
    pub new_min_stake: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[error_code]
pub enum StakingError {
    #[msg("Staking is paused")]
    StakingPaused,
    #[msg("Amount below minimum stake")]
    BelowMinimumStake,
    #[msg("L1 public key must be exactly 64 hex characters")]
    InvalidL1PublicKey,
    #[msg("Node name must be 1-64 characters")]
    InvalidNodeName,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Validator is already unstaking")]
    AlreadyUnstaking,
    #[msg("Validator is still active — call unstake first")]
    StillActive,
    #[msg("Unstake not requested")]
    UnstakeNotRequested,
    #[msg("Unbonding period not complete")]
    UnbondingNotComplete,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Invalid minimum stake")]
    InvalidMinStake,
}
