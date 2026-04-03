use anchor_lang::prelude::*;
use solana_program::hash::hashv;
use solana_program::sysvar;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer};
use std::collections::HashSet;

declare_id!("9NNcZoLo5bqmByC2TFKTB8iXfFrp9Yf9h6speBRoVo3M");

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

pub const SEED_CONFIG: &[u8] = b"misaka-bridge-config";
pub const SEED_VAULT_AUTH: &[u8] = b"misaka-bridge-vault-auth";
pub const SEED_VAULT: &[u8] = b"misaka-bridge-vault";
pub const SEED_RECEIPT: &[u8] = b"misaka-bridge-receipt";
pub const SEED_NONCE: &[u8] = b"misaka-bridge-nonce";
pub const SEED_COMMITTEE: &[u8] = b"misaka-bridge-committee";
pub const SEED_CUMULATIVE: &[u8] = b"misaka-bridge-cumulative";

/// Maximum committee members the bridge program can handle.
/// Set to 21 to support future expansion (SR15 → SR18 → SR21).
/// Actual active committee size is stored in BridgeCommittee.member_count.
pub const MAX_COMMITTEE_SIZE: usize = 21;
/// BFT quorum threshold for SR15: ceil(2*15/3) = 10 (66.7% supermajority).
/// Updated via sync_sr_committee when committee size changes.
pub const COMMITTEE_THRESHOLD: u8 = 10;
pub const MISAKA_CHAIN_ID: u32 = 2;
pub const SOLANA_CHAIN_ID: u32 = 1;
pub const MISAKA_ASSET_ID: &str = "MISAKA";
pub const MISAKA_MINT_MAINNET: &str = "4e2DhohUAJ9EbrLey3rVVgFQzLCAeeBirSbdhqrh9snX";
pub const INITIAL_ADMIN: &str = "4pUZUUS732Xo72V4hsNRwg85miPzLKYeprpWwBuFV5BR";

pub const FEE_RATE_BPS: u64 = 50;
pub const BPS_DENOMINATOR: u64 = 10_000;
/// Max amount for fee calculation without overflow: u64::MAX / 50
pub const MAX_FEE_AMOUNT: u64 = u64::MAX / FEE_RATE_BPS;

pub const LIMIT_10M: u64 = 50_000_000_000_000_000;
pub const LIMIT_1H: u64 = 200_000_000_000_000_000;
pub const LIMIT_24H: u64 = 500_000_000_000_000_000;
pub const WINDOW_10M: i64 = 600;
pub const WINDOW_1H: i64 = 3600;
pub const WINDOW_24H: i64 = 86400;

pub const DOMAIN_MISAKA_TO_SOLANA: &[u8] = b"MISAKA->SOLANA:v1:";
pub const DOMAIN_SOLANA_TO_MISAKA: &[u8] = b"SOLANA->MISAKA:v1:";

/// Admin transfer timelock: 3 days in slots (~400ms/slot).
pub const ADMIN_TRANSFER_TIMELOCK_SLOTS: u64 = 648_000;

// ═══════════════════════════════════════════════════════════════
//  Ed25519 Precompile Verification — with consumed entry tracking
// ═══════════════════════════════════════════════════════════════

/// Verify Ed25519 signature via precompile, tracking consumed entries
/// to prevent the same precompile entry from being counted twice.
///
/// FIX [P0-1]: Each precompile entry is identified by (ix_index, sig_index).
/// Once matched, it is added to `consumed` and cannot be reused.
fn verify_ed25519_sig_tracked(
    instructions_sysvar: &AccountInfo,
    pubkey: &Pubkey,
    message: &[u8; 32],
    signature: &[u8; 64],
    consumed: &mut HashSet<(u16, u16)>,
) -> bool {
    use solana_program::sysvar::instructions as ix_sysvar;
    let ed25519_id: Pubkey = "Ed25519SigVerify111111111111111111111111111".parse().unwrap();
    const ENTRY_SIZE: usize = 14;
    let mut idx: u16 = 0;
    loop {
        let ix = match ix_sysvar::load_instruction_at_checked(idx as usize, instructions_sysvar) {
            Ok(ix) => ix,
            Err(_) => break,
        };
        if ix.program_id != ed25519_id { idx += 1; continue; }
        if ix.data.len() < 2 { idx += 1; continue; }
        let num_sigs = ix.data[0] as usize;
        let min_h = 2 + num_sigs * ENTRY_SIZE;
        if ix.data.len() < min_h { idx += 1; continue; }
        for s in 0..num_sigs {
            let entry_id = (idx, s as u16);
            // Skip already consumed entries
            if consumed.contains(&entry_id) { continue; }
            let o = 2 + s * ENTRY_SIZE;
            let sig_off = u16::from_le_bytes([ix.data[o], ix.data[o+1]]) as usize;
            let pk_off = u16::from_le_bytes([ix.data[o+4], ix.data[o+5]]) as usize;
            let msg_off = u16::from_le_bytes([ix.data[o+8], ix.data[o+9]]) as usize;
            let msg_sz = u16::from_le_bytes([ix.data[o+10], ix.data[o+11]]) as usize;
            if sig_off+64 > ix.data.len() || pk_off+32 > ix.data.len()
                || msg_off+msg_sz > ix.data.len() || msg_sz != 32 { continue; }
            if &ix.data[pk_off..pk_off+32] == pubkey.as_ref()
                && &ix.data[msg_off..msg_off+32] == message.as_ref()
                && &ix.data[sig_off..sig_off+64] == signature.as_ref()
            {
                consumed.insert(entry_id);
                return true;
            }
        }
        idx += 1;
    }
    false
}

// ═══════════════════════════════════════════════════════════════
//  Fee Calculation — FIX [P2]: error on overflow instead of 0
// ═══════════════════════════════════════════════════════════════

fn calc_fee(amount: u64) -> Result<u64> {
    require!(amount <= MAX_FEE_AMOUNT, BridgeError::AmountTooLargeForFee);
    Ok(amount * FEE_RATE_BPS / BPS_DENOMINATOR)
}

// ═══════════════════════════════════════════════════════════════
//  Committee signature verification helper
// ═══════════════════════════════════════════════════════════════

fn verify_committee_signatures(
    instructions_sysvar: &AccountInfo,
    committee: &BridgeCommittee,
    message: &[u8; 32],
    signatures: &[[u8; 64]],
    threshold: u8,
) -> Result<u8> {
    require!(signatures.len() <= committee.member_count as usize, BridgeError::TooManySignatures);
    let mut valid_sigs: u8 = 0;
    let mut verified_pks: HashSet<Pubkey> = HashSet::with_capacity(MAX_COMMITTEE_SIZE);
    let mut consumed_entries: HashSet<(u16, u16)> = HashSet::new();
    for sig in signatures {
        for pk in committee.members[..committee.member_count as usize].iter() {
            if *pk == Pubkey::default() { continue; }
            if verified_pks.contains(pk) { continue; }
            if verify_ed25519_sig_tracked(
                instructions_sysvar, pk, message, sig, &mut consumed_entries,
            ) {
                verified_pks.insert(*pk);
                valid_sigs += 1;
                break;
            }
        }
    }
    require!(valid_sigs >= threshold, BridgeError::InsufficientCommitteeSignatures);
    Ok(valid_sigs)
}

// ═══════════════════════════════════════════════════════════════
//  Program Instructions
// ═══════════════════════════════════════════════════════════════

#[program]
pub mod misaka_bridge {
    use super::*;

    /// Initialize bridge. Admin set from INITIAL_ADMIN constant.
    pub fn initialize_bridge(
        ctx: Context<InitializeBridge>,
        min_lock_amount: u64,
    ) -> Result<()> {
        let admin: Pubkey = INITIAL_ADMIN.parse().unwrap();
        let config = &mut ctx.accounts.bridge_config;
        config.admin = admin;
        config.pending_admin = Pubkey::default();
        config.admin_transfer_slot = 0;
        config.fee_treasury = admin;
        config.misaka_mint = ctx.accounts.misaka_mint.key();
        config.paused = false;
        config.held = false;
        config.min_lock_amount = min_lock_amount;
        config.total_locked = 0;
        config.total_released = 0;
        config.total_fees_collected = 0;
        config.nonce = 0;
        config.bump = ctx.bumps.bridge_config;
        config.vault_bump = ctx.bumps.vault_authority;
        emit!(BridgeInitialized { admin, misaka_mint: config.misaka_mint, min_lock_amount });
        Ok(())
    }

    /// Initialize cumulative state for withdrawal tracking.
    /// FIX [P0-2]: Must be called before first unlock_tokens.
    /// Initialize cumulative state for withdrawal tracking.
    /// CRIT-1 FIX: Sets initialized=true. unlock_tokens() will refuse
    /// to execute unless this flag is set.
    pub fn initialize_cumulative(ctx: Context<InitCumulative>) -> Result<()> {
        let admin: Pubkey = INITIAL_ADMIN.parse().unwrap();
        require!(ctx.accounts.admin.key() == admin || ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin, BridgeError::Unauthorized);
        let c = &mut ctx.accounts.cumulative_state;
        c.initialized = true; // CRIT-1: explicit init flag
        c.total_10m = 0;
        c.window_10m_start = 0;
        c.total_1h = 0;
        c.window_1h_start = 0;
        c.total_24h = 0;
        c.window_24h_start = 0;
        c.bump = ctx.bumps.cumulative_state;
        Ok(())
    }

    /// Initialize vault token account for the bridge.
    /// FIX [P1-5]: Explicit vault initialization.
    pub fn initialize_vault(ctx: Context<InitVault>) -> Result<()> {
        // Vault is initialized by Anchor via init constraint.
        // Token account is created with the vault_authority PDA as owner.
        Ok(())
    }

    /// Sync SR committee. Bootstrap: admin. Rotation: 15/21 current SR.
    pub fn sync_sr_committee(
        ctx: Context<SyncCommittee>,
        new_bridge_pubkeys: Vec<Pubkey>,
        l1_epoch: u64,
        rotation_signatures: Vec<[u8; 64]>,
    ) -> Result<()> {
        require!(new_bridge_pubkeys.len() == MAX_COMMITTEE_SIZE, BridgeError::InvalidCommitteeSize);
        let mut sorted = new_bridge_pubkeys.clone();
        sorted.sort();
        for i in 1..sorted.len() { require!(sorted[i] != sorted[i-1], BridgeError::DuplicateCommitteeMember); }

        let c = &mut ctx.accounts.committee;

        if c.member_count == 0 {
            // Bootstrap: admin only
            require!(ctx.accounts.signer.key() == ctx.accounts.bridge_config.admin, BridgeError::Unauthorized);
        } else {
            // SR rotation: 15/21 current committee signs
            require!(l1_epoch > c.l1_epoch, BridgeError::StaleEpoch);
            let rotation_msg = hashv(&[
                b"MISAKA:committee:rotate:v1:",
                &l1_epoch.to_le_bytes(),
                &(new_bridge_pubkeys.len() as u32).to_le_bytes(),
                &new_bridge_pubkeys.iter().flat_map(|pk| pk.to_bytes()).collect::<Vec<u8>>(),
            ]).to_bytes();
            // Use the CURRENT committee's threshold for rotation verification
            // (not the hardcoded constant — supports dynamic committee sizes).
            verify_committee_signatures(
                &ctx.accounts.instructions_sysvar.to_account_info(),
                c, &rotation_msg, &rotation_signatures, c.threshold,
            )?;
        }

        // M-1 FIX: Dynamically compute threshold from member count.
        // ceil(2*N/3) = (2*N + 2) / 3 — standard BFT 2/3 supermajority.
        // This automatically adjusts when committee size changes (SR15→SR18→SR21).
        let member_count = new_bridge_pubkeys.len() as u8;
        c.threshold = ((2 * member_count as u16 + 2) / 3) as u8;
        c.member_count = member_count;
        c.members = [Pubkey::default(); MAX_COMMITTEE_SIZE];
        for (i, m) in new_bridge_pubkeys.iter().enumerate() { c.members[i] = *m; }
        c.l1_epoch = l1_epoch;
        c.last_sync_slot = Clock::get()?.slot;
        if c.bump == 0 { c.bump = ctx.bumps.committee; }

        emit!(CommitteeSynced { threshold: COMMITTEE_THRESHOLD, member_count: new_bridge_pubkeys.len() as u8, l1_epoch });
        Ok(())
    }

    /// Lock MISAKA tokens (Solana → MISAKA). 0.5% fee.
    pub fn lock_tokens(
        ctx: Context<LockTokens>,
        amount: u64,
        misaka_recipient: [u8; 32],
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        require!(!config.paused, BridgeError::BridgePaused);
        require!(!config.held, BridgeError::BridgeHeld);
        require!(amount >= config.min_lock_amount, BridgeError::AmountTooSmall);

        let fee = calc_fee(amount)?;
        let net_amount = amount.checked_sub(fee).ok_or(BridgeError::ArithmeticOverflow)?;

        // Transfer gross amount to vault
        token::transfer(CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_token_account.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        ), amount)?;

        // Transfer fee from vault to treasury
        if fee > 0 {
            let seeds = &[SEED_VAULT_AUTH, &[config.vault_bump]];
            token::transfer(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.fee_treasury_account.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
                &[seeds],
            ), fee)?;
        }

        let config = &mut ctx.accounts.bridge_config;
        config.nonce += 1;
        config.total_locked = config.total_locked.checked_add(net_amount).ok_or(BridgeError::ArithmeticOverflow)?;
        config.total_fees_collected = config.total_fees_collected.checked_add(fee).ok_or(BridgeError::ArithmeticOverflow)?;

        let receipt = &mut ctx.accounts.locked_receipt;
        receipt.user = ctx.accounts.user.key();
        receipt.gross_amount = amount;
        receipt.fee = fee;
        receipt.net_amount = net_amount;
        receipt.misaka_recipient = misaka_recipient;
        receipt.nonce = config.nonce;
        receipt.timestamp = Clock::get()?.unix_timestamp;
        receipt.processed = false;
        receipt.bump = ctx.bumps.locked_receipt;

        emit!(TokensLocked { user: ctx.accounts.user.key(), gross_amount: amount, fee, net_amount, misaka_recipient, nonce: config.nonce, fee_treasury: config.fee_treasury });
        Ok(())
    }

    /// Unlock MISAKA tokens (MISAKA → Solana). 15/21 committee + 0.5% fee.
    pub fn unlock_tokens(
        ctx: Context<UnlockTokens>,
        gross_amount: u64,
        request_id_arg: [u8; 32],
        source_tx_hash: [u8; 32],
        unlock_nonce: u64,
        committee_signatures: Vec<[u8; 64]>,
    ) -> Result<()> {
        let config = &ctx.accounts.bridge_config;
        require!(!config.paused, BridgeError::BridgePaused);
        require!(!config.held, BridgeError::BridgeHeld);

        let fee = calc_fee(gross_amount)?;
        let net_amount = gross_amount.checked_sub(fee).ok_or(BridgeError::ArithmeticOverflow)?;

        // Recompute request_id
        let computed_request_id = hashv(&[
            DOMAIN_MISAKA_TO_SOLANA, &[1],
            &MISAKA_CHAIN_ID.to_le_bytes(), &SOLANA_CHAIN_ID.to_le_bytes(),
            MISAKA_ASSET_ID.as_bytes(),
            &ctx.accounts.recipient_token_account.key().to_bytes(),
            &gross_amount.to_le_bytes(), &fee.to_le_bytes(), &net_amount.to_le_bytes(),
            &unlock_nonce.to_le_bytes(), &source_tx_hash,
        ]).to_bytes();
        require!(computed_request_id == request_id_arg, BridgeError::RequestIdMismatch);

        // CRIT-1 FIX: Verify CumulativeState was properly initialized.
        // Without this, an attacker could bypass rate limits entirely.
        let cumul = &mut ctx.accounts.cumulative_state;
        require!(cumul.initialized, BridgeError::CumulativeNotInitialized);

        // Cumulative limits
        let now = Clock::get()?.unix_timestamp;
        cumul.prune_expired(now);
        cumul.add_withdrawal(net_amount, now);
        require!(cumul.total_10m <= LIMIT_10M, BridgeError::CumulativeLimit10m);
        require!(cumul.total_1h <= LIMIT_1H, BridgeError::CumulativeLimit1h);
        require!(cumul.total_24h <= LIMIT_24H, BridgeError::CumulativeLimit24h);

        // 15/21 committee verification with consumed entry tracking
        let valid_sigs = verify_committee_signatures(
            &ctx.accounts.instructions_sysvar.to_account_info(),
            &ctx.accounts.committee, &computed_request_id,
            &committee_signatures, ctx.accounts.committee.threshold,
        )?;

        // Replay protection
        let nonce_state = &mut ctx.accounts.nonce_state;
        require!(!nonce_state.processed, BridgeError::AlreadyProcessed);
        nonce_state.processed = true;
        nonce_state.request_id = computed_request_id;
        nonce_state.bump = ctx.bumps.nonce_state;

        // Transfer net to recipient + fee to treasury
        let seeds = &[SEED_VAULT_AUTH, &[config.vault_bump]];
        token::transfer(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer { from: ctx.accounts.vault.to_account_info(), to: ctx.accounts.recipient_token_account.to_account_info(), authority: ctx.accounts.vault_authority.to_account_info() },
            &[seeds],
        ), net_amount)?;
        if fee > 0 {
            token::transfer(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer { from: ctx.accounts.vault.to_account_info(), to: ctx.accounts.fee_treasury_account.to_account_info(), authority: ctx.accounts.vault_authority.to_account_info() },
                &[seeds],
            ), fee)?;
        }

        let config = &mut ctx.accounts.bridge_config;
        config.total_released = config.total_released.checked_add(net_amount).ok_or(BridgeError::ArithmeticOverflow)?;
        config.total_fees_collected = config.total_fees_collected.checked_add(fee).ok_or(BridgeError::ArithmeticOverflow)?;

        emit!(TokensUnlocked { recipient: ctx.accounts.recipient_token_account.key(), gross_amount, fee, net_amount, request_id: computed_request_id, committee_sigs: valid_sigs, source_tx_hash, unlock_nonce, fee_treasury: config.fee_treasury, timestamp: now });
        Ok(())
    }

    // ── Admin controls ──

    pub fn pause_bridge(ctx: Context<AdminAction>) -> Result<()> {
        require!(ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin, BridgeError::Unauthorized);
        ctx.accounts.bridge_config.paused = true;
        emit!(BridgePaused { by: ctx.accounts.admin.key(), timestamp: Clock::get()?.unix_timestamp });
        Ok(())
    }

    pub fn unpause_bridge(ctx: Context<AdminAction>) -> Result<()> {
        require!(ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin, BridgeError::Unauthorized);
        ctx.accounts.bridge_config.paused = false;
        emit!(BridgeUnpaused { by: ctx.accounts.admin.key(), timestamp: Clock::get()?.unix_timestamp });
        Ok(())
    }

    pub fn hold_bridge(ctx: Context<AdminAction>, reason: String) -> Result<()> {
        require!(reason.len() <= 256, BridgeError::ReasonTooLong);
        require!(ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin, BridgeError::Unauthorized);
        ctx.accounts.bridge_config.held = true;
        emit!(BridgeHoldApplied { by: ctx.accounts.admin.key(), reason, timestamp: Clock::get()?.unix_timestamp });
        Ok(())
    }

    pub fn release_hold(ctx: Context<AdminAction>) -> Result<()> {
        require!(ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin, BridgeError::Unauthorized);
        ctx.accounts.bridge_config.held = false;
        emit!(BridgeHoldReleased { by: ctx.accounts.admin.key(), timestamp: Clock::get()?.unix_timestamp });
        Ok(())
    }

    /// FIX [P1-4]: Two-phase admin transfer with timelock.
    /// Step 1: Current admin proposes new admin. Takes effect after timelock.
    pub fn propose_admin_transfer(ctx: Context<AdminAction>, new_admin: Pubkey) -> Result<()> {
        require!(ctx.accounts.admin.key() == ctx.accounts.bridge_config.admin, BridgeError::Unauthorized);
        let config = &mut ctx.accounts.bridge_config;
        config.pending_admin = new_admin;
        config.admin_transfer_slot = Clock::get()?.slot + ADMIN_TRANSFER_TIMELOCK_SLOTS;
        emit!(AdminTransferProposed { current: config.admin, proposed: new_admin, effective_slot: config.admin_transfer_slot });
        Ok(())
    }

    /// Step 2: New admin accepts after timelock. Must be called by pending_admin.
    pub fn accept_admin_transfer(ctx: Context<AcceptAdmin>) -> Result<()> {
        let config = &mut ctx.accounts.bridge_config;
        require!(config.pending_admin != Pubkey::default(), BridgeError::NoAdminTransferPending);
        require!(ctx.accounts.new_admin.key() == config.pending_admin, BridgeError::Unauthorized);
        require!(Clock::get()?.slot >= config.admin_transfer_slot, BridgeError::AdminTimelockNotExpired);
        let old = config.admin;
        config.admin = config.pending_admin;
        config.fee_treasury = config.pending_admin; // treasury follows admin
        config.pending_admin = Pubkey::default();
        config.admin_transfer_slot = 0;
        emit!(AdminTransferred { old_admin: old, new_admin: config.admin });
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Account Contexts
// ═══════════════════════════════════════════════════════════════

#[derive(Accounts)]
pub struct InitializeBridge<'info> {
    #[account(init, payer = payer, space = 8 + BridgeConfig::LEN, seeds = [SEED_CONFIG], bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(seeds = [SEED_VAULT_AUTH], bump)]
    /// CHECK: PDA authority
    pub vault_authority: UncheckedAccount<'info>,
    pub misaka_mint: Account<'info, Mint>,
    #[account(mut)] pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitCumulative<'info> {
    #[account(seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(init, payer = admin, space = 8 + CumulativeState::LEN, seeds = [SEED_CUMULATIVE], bump)]
    pub cumulative_state: Account<'info, CumulativeState>,
    #[account(mut)] pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(
        init, payer = payer,
        token::mint = misaka_mint,
        token::authority = vault_authority,
        seeds = [SEED_VAULT, misaka_mint.key().as_ref()], bump,
    )]
    pub vault: Account<'info, TokenAccount>,
    #[account(seeds = [SEED_VAULT_AUTH], bump = bridge_config.vault_bump)]
    /// CHECK: PDA authority
    pub vault_authority: UncheckedAccount<'info>,
    pub misaka_mint: Account<'info, Mint>,
    #[account(mut)] pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SyncCommittee<'info> {
    #[account(seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(init_if_needed, payer = signer, space = 8 + BridgeCommittee::LEN, seeds = [SEED_COMMITTEE], bump)]
    pub committee: Account<'info, BridgeCommittee>,
    #[account(mut)] pub signer: Signer<'info>,
    /// CHECK: instructions sysvar
    #[account(address = sysvar::instructions::id())]
    pub instructions_sysvar: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount: u64, misaka_recipient: [u8; 32])]
pub struct LockTokens<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(mut, constraint = user_token_account.mint == bridge_config.misaka_mint)]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [SEED_VAULT, bridge_config.misaka_mint.as_ref()], bump)]
    pub vault: Account<'info, TokenAccount>,
    #[account(seeds = [SEED_VAULT_AUTH], bump = bridge_config.vault_bump)]
    /// CHECK: PDA
    pub vault_authority: UncheckedAccount<'info>,
    /// FIX [P0-3]: Fee treasury must be owned by admin.
    #[account(mut,
        constraint = fee_treasury_account.mint == bridge_config.misaka_mint,
        constraint = fee_treasury_account.owner == bridge_config.fee_treasury @ BridgeError::InvalidFeeTreasury
    )]
    pub fee_treasury_account: Account<'info, TokenAccount>,
    #[account(init, payer = user, space = 8 + LockedReceipt::LEN,
              seeds = [SEED_RECEIPT, &bridge_config.nonce.to_le_bytes()], bump)]
    pub locked_receipt: Account<'info, LockedReceipt>,
    #[account(mut)] pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(gross_amount: u64, request_id_arg: [u8; 32], source_tx_hash: [u8; 32], unlock_nonce: u64)]
pub struct UnlockTokens<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    #[account(seeds = [SEED_COMMITTEE], bump = committee.bump)]
    pub committee: Account<'info, BridgeCommittee>,
    #[account(seeds = [SEED_VAULT_AUTH], bump = bridge_config.vault_bump)]
    /// CHECK: PDA
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_VAULT, bridge_config.misaka_mint.as_ref()], bump)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, constraint = recipient_token_account.mint == bridge_config.misaka_mint)]
    pub recipient_token_account: Account<'info, TokenAccount>,
    /// FIX [P0-3]: Fee treasury must be owned by admin.
    #[account(mut,
        constraint = fee_treasury_account.mint == bridge_config.misaka_mint,
        constraint = fee_treasury_account.owner == bridge_config.fee_treasury @ BridgeError::InvalidFeeTreasury
    )]
    pub fee_treasury_account: Account<'info, TokenAccount>,
    #[account(init_if_needed, payer = payer, space = 8 + NonceState::LEN,
              seeds = [SEED_NONCE, &request_id_arg], bump)]
    pub nonce_state: Account<'info, NonceState>,
    #[account(mut, seeds = [SEED_CUMULATIVE], bump = cumulative_state.bump)]
    pub cumulative_state: Account<'info, CumulativeState>,
    #[account(mut)] pub payer: Signer<'info>,
    /// CHECK: instructions sysvar
    #[account(address = sysvar::instructions::id())]
    pub instructions_sysvar: UncheckedAccount<'info>,
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
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = bridge_config.bump)]
    pub bridge_config: Account<'info, BridgeConfig>,
    pub new_admin: Signer<'info>,
}

// ═══════════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════════

#[account]
pub struct BridgeConfig {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub admin_transfer_slot: u64,
    pub fee_treasury: Pubkey,
    pub misaka_mint: Pubkey,
    pub paused: bool,
    pub held: bool,
    pub min_lock_amount: u64,
    pub total_locked: u64,
    pub total_released: u64,
    pub total_fees_collected: u64,
    pub nonce: u64,
    pub bump: u8,
    pub vault_bump: u8,
}
impl BridgeConfig { pub const LEN: usize = 32+32+8+32+32+1+1+8+8+8+8+8+1+1; }

#[account]
pub struct BridgeCommittee {
    pub threshold: u8,
    pub member_count: u8,
    pub members: [Pubkey; MAX_COMMITTEE_SIZE],
    pub l1_epoch: u64,
    pub last_sync_slot: u64,
    pub bump: u8,
}
impl BridgeCommittee { pub const LEN: usize = 1+1+(32*MAX_COMMITTEE_SIZE)+8+8+1; }

#[account]
pub struct LockedReceipt {
    pub user: Pubkey,
    pub gross_amount: u64,
    pub fee: u64,
    pub net_amount: u64,
    pub misaka_recipient: [u8; 32],
    pub nonce: u64,
    pub timestamp: i64,
    pub processed: bool,
    pub bump: u8,
}
impl LockedReceipt { pub const LEN: usize = 32+8+8+8+32+8+8+1+1; }

#[account]
pub struct NonceState {
    pub processed: bool,
    pub request_id: [u8; 32],
    pub bump: u8,
}
impl NonceState { pub const LEN: usize = 1+32+1; }

#[account]
pub struct CumulativeState {
    /// CRIT-1 FIX: Explicit initialization flag.
    /// Must be true for unlock_tokens() to proceed.
    /// Set to true ONLY by initialize_cumulative().
    pub initialized: bool,
    pub total_10m: u64,
    pub window_10m_start: i64,
    pub total_1h: u64,
    pub window_1h_start: i64,
    pub total_24h: u64,
    pub window_24h_start: i64,
    pub bump: u8,
}
impl CumulativeState {
    pub const LEN: usize = 1+8+8+8+8+8+8+1;
    pub fn add_withdrawal(&mut self, amount: u64, now: i64) {
        if now - self.window_10m_start >= WINDOW_10M { self.total_10m = 0; self.window_10m_start = now; }
        if now - self.window_1h_start >= WINDOW_1H { self.total_1h = 0; self.window_1h_start = now; }
        if now - self.window_24h_start >= WINDOW_24H { self.total_24h = 0; self.window_24h_start = now; }
        self.total_10m = self.total_10m.saturating_add(amount);
        self.total_1h = self.total_1h.saturating_add(amount);
        self.total_24h = self.total_24h.saturating_add(amount);
    }
    pub fn prune_expired(&mut self, now: i64) {
        if now - self.window_10m_start >= WINDOW_10M { self.total_10m = 0; self.window_10m_start = now; }
        if now - self.window_1h_start >= WINDOW_1H { self.total_1h = 0; self.window_1h_start = now; }
        if now - self.window_24h_start >= WINDOW_24H { self.total_24h = 0; self.window_24h_start = now; }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Events (all include timestamp)
// ═══════════════════════════════════════════════════════════════

#[event] pub struct BridgeInitialized { pub admin: Pubkey, pub misaka_mint: Pubkey, pub min_lock_amount: u64 }
#[event] pub struct CommitteeSynced { pub threshold: u8, pub member_count: u8, pub l1_epoch: u64 }
#[event] pub struct TokensLocked { pub user: Pubkey, pub gross_amount: u64, pub fee: u64, pub net_amount: u64, pub misaka_recipient: [u8; 32], pub nonce: u64, pub fee_treasury: Pubkey }
#[event] pub struct TokensUnlocked { pub recipient: Pubkey, pub gross_amount: u64, pub fee: u64, pub net_amount: u64, pub request_id: [u8; 32], pub committee_sigs: u8, pub source_tx_hash: [u8; 32], pub unlock_nonce: u64, pub fee_treasury: Pubkey, pub timestamp: i64 }
#[event] pub struct BridgePaused { pub by: Pubkey, pub timestamp: i64 }
#[event] pub struct BridgeUnpaused { pub by: Pubkey, pub timestamp: i64 }
#[event] pub struct BridgeHoldApplied { pub by: Pubkey, pub reason: String, pub timestamp: i64 }
#[event] pub struct BridgeHoldReleased { pub by: Pubkey, pub timestamp: i64 }
#[event] pub struct AdminTransferProposed { pub current: Pubkey, pub proposed: Pubkey, pub effective_slot: u64 }
#[event] pub struct AdminTransferred { pub old_admin: Pubkey, pub new_admin: Pubkey }

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[error_code]
pub enum BridgeError {
    #[msg("Bridge is paused")] BridgePaused,
    #[msg("Bridge is held")] BridgeHeld,
    #[msg("Unauthorized")] Unauthorized,
    #[msg("Amount below minimum")] AmountTooSmall,
    #[msg("Amount too large for fee calculation")] AmountTooLargeForFee,
    #[msg("Already processed")] AlreadyProcessed,
    #[msg("Mint mismatch")] MintMismatch,
    #[msg("Insufficient committee signatures (need 15/21)")] InsufficientCommitteeSignatures,
    #[msg("Committee must be exactly 21")] InvalidCommitteeSize,
    #[msg("Duplicate committee member")] DuplicateCommitteeMember,
    #[msg("Too many signatures")] TooManySignatures,
    #[msg("Arithmetic overflow")] ArithmeticOverflow,
    #[msg("Request ID mismatch")] RequestIdMismatch,
    #[msg("10-min limit exceeded")] CumulativeLimit10m,
    #[msg("1-hour limit exceeded")] CumulativeLimit1h,
    #[msg("24-hour limit exceeded")] CumulativeLimit24h,
    #[msg("Stale epoch")] StaleEpoch,
    #[msg("Fee treasury account not owned by admin")] InvalidFeeTreasury,
    #[msg("No admin transfer pending")] NoAdminTransferPending,
    #[msg("Admin timelock not expired")] AdminTimelockNotExpired,
    #[msg("Reason string too long (max 256)")] ReasonTooLong,
    #[msg("CumulativeState not initialized — call initialize_cumulative() first")] CumulativeNotInitialized,
}
