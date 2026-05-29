use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod my_program {
    use super::*;

    pub fn unsafe_handler(ctx: Context<UnsafeHandler>, amount: u64) -> Result<()> {
        // BUG: reads ctx.accounts.config without ownership check.
        let cfg = &ctx.accounts.config;
        msg!("amount {}", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UnsafeHandler<'info> {
    /// CHECK: BUG — no owner = constraint, no has_one.
    pub config: AccountInfo<'info>,
}
