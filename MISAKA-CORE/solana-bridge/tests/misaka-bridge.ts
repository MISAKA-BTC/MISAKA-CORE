import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { MisakaBridge } from "../target/types/misaka_bridge";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import {
  createMint,
  createAssociatedTokenAccount,
  mintTo,
  getAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { assert } from "chai";

describe("misaka-bridge", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.MisakaBridge as Program<MisakaBridge>;
  const admin = provider.wallet as anchor.Wallet;

  let mint: PublicKey;
  let adminTokenAccount: PublicKey;
  let configPda: PublicKey;
  let vaultAuthPda: PublicKey;
  let vaultPda: PublicKey;
  let committeePda: PublicKey;

  const SEED_CONFIG = Buffer.from("misaka-bridge-config");
  const SEED_VAULT_AUTH = Buffer.from("misaka-bridge-vault-auth");
  const SEED_VAULT = Buffer.from("misaka-bridge-vault");
  const SEED_COMMITTEE = Buffer.from("misaka-bridge-committee");
  const SEED_ASSET = Buffer.from("misaka-bridge-asset");
  const SEED_NONCE = Buffer.from("misaka-bridge-nonce");

  before(async () => {
    // Create SPL token mint
    mint = await createMint(
      provider.connection,
      (admin as any).payer,
      admin.publicKey,
      null,
      9 // 9 decimals (MISAKA standard)
    );

    // Create admin token account and mint tokens
    adminTokenAccount = await createAssociatedTokenAccount(
      provider.connection,
      (admin as any).payer,
      mint,
      admin.publicKey
    );

    // Mint 100M tokens for testing
    await mintTo(
      provider.connection,
      (admin as any).payer,
      mint,
      adminTokenAccount,
      admin.publicKey,
      100_000_000_000_000_000n // 100M MISAKA
    );

    // Derive PDAs
    [configPda] = PublicKey.findProgramAddressSync(
      [SEED_CONFIG],
      program.programId
    );
    [vaultAuthPda] = PublicKey.findProgramAddressSync(
      [SEED_VAULT_AUTH],
      program.programId
    );
    [vaultPda] = PublicKey.findProgramAddressSync(
      [SEED_VAULT, mint.toBuffer()],
      program.programId
    );
    [committeePda] = PublicKey.findProgramAddressSync(
      [SEED_COMMITTEE],
      program.programId
    );
  });

  it("Initializes the bridge", async () => {
    const tx = await program.methods
      .initializeBridge(admin.publicKey)
      .accounts({
        bridgeConfig: configPda,
        vaultAuthority: vaultAuthPda,
        payer: admin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("Initialize bridge TX:", tx);

    const config = await program.account.bridgeConfig.fetch(configPda);
    assert.ok(config.admin.equals(admin.publicKey));
    assert.equal(config.paused, false);
    assert.equal(config.totalLocked.toNumber(), 0);
    assert.equal(config.totalReleased.toNumber(), 0);
  });

  it("Initializes committee", async () => {
    const member1 = Keypair.generate();
    const member2 = Keypair.generate();
    const member3 = Keypair.generate();

    const tx = await program.methods
      .initializeCommittee(
        [member1.publicKey, member2.publicKey, member3.publicKey],
        2 // threshold: 2 of 3
      )
      .accounts({
        bridgeConfig: configPda,
        committee: committeePda,
        admin: admin.publicKey,
        payer: admin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("Initialize committee TX:", tx);

    const committee = await program.account.bridgeCommittee.fetch(committeePda);
    assert.equal(committee.memberCount, 3);
    assert.equal(committee.threshold, 2);
  });

  it("Registers an asset mapping", async () => {
    const assetId = "MISAKA";
    const [assetPda] = PublicKey.findProgramAddressSync(
      [SEED_ASSET, Buffer.from(assetId)],
      program.programId
    );

    const tx = await program.methods
      .registerAsset(assetId, mint)
      .accounts({
        bridgeConfig: configPda,
        assetMapping: assetPda,
        admin: admin.publicKey,
        payer: admin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("Register asset TX:", tx);

    const asset = await program.account.assetMapping.fetch(assetPda);
    assert.ok(asset.mint.equals(mint));
    assert.equal(asset.misakaAssetId, assetId);
    assert.equal(asset.isActive, true);
  });

  it("Locks tokens (L1 → Solana deposit)", async () => {
    const amount = new anchor.BN(1_000_000_000_000); // 1000 MISAKA
    const l1Recipient = Buffer.alloc(32);
    l1Recipient.fill(0xaa);

    const assetId = "MISAKA";
    const [assetPda] = PublicKey.findProgramAddressSync(
      [SEED_ASSET, Buffer.from(assetId)],
      program.programId
    );

    const balanceBefore = (
      await getAccount(provider.connection, adminTokenAccount)
    ).amount;

    const tx = await program.methods
      .lockTokens(amount, [...l1Recipient])
      .accounts({
        bridgeConfig: configPda,
        assetMapping: assetPda,
        userTokenAccount: adminTokenAccount,
        vault: vaultPda,
        vaultAuthority: vaultAuthPda,
        user: admin.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("Lock tokens TX:", tx);

    const balanceAfter = (
      await getAccount(provider.connection, adminTokenAccount)
    ).amount;
    assert.equal(
      Number(balanceBefore) - Number(balanceAfter),
      amount.toNumber()
    );

    const config = await program.account.bridgeConfig.fetch(configPda);
    assert.equal(config.totalLocked.toNumber(), amount.toNumber());
  });

  it("Rejects lock when bridge is paused", async () => {
    // Pause
    await program.methods
      .pauseBridge()
      .accounts({
        bridgeConfig: configPda,
        admin: admin.publicKey,
      })
      .rpc();

    const amount = new anchor.BN(1_000_000_000);
    const l1Recipient = Buffer.alloc(32);

    const assetId = "MISAKA";
    const [assetPda] = PublicKey.findProgramAddressSync(
      [SEED_ASSET, Buffer.from(assetId)],
      program.programId
    );

    try {
      await program.methods
        .lockTokens(amount, [...l1Recipient])
        .accounts({
          bridgeConfig: configPda,
          assetMapping: assetPda,
          userTokenAccount: adminTokenAccount,
          vault: vaultPda,
          vaultAuthority: vaultAuthPda,
          user: admin.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      assert.fail("Should have failed — bridge is paused");
    } catch (err: any) {
      assert.include(err.toString(), "BridgePaused");
    }

    // Unpause for subsequent tests
    await program.methods
      .unpauseBridge()
      .accounts({
        bridgeConfig: configPda,
        admin: admin.publicKey,
      })
      .rpc();
  });

  it("Unauthorized admin is rejected", async () => {
    const fakeAdmin = Keypair.generate();

    try {
      await program.methods
        .pauseBridge()
        .accounts({
          bridgeConfig: configPda,
          admin: fakeAdmin.publicKey,
        })
        .signers([fakeAdmin])
        .rpc();
      assert.fail("Should have failed — unauthorized");
    } catch (err: any) {
      assert.include(err.toString(), "Unauthorized");
    }
  });
});
