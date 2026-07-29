#![no_std]
//! Callora rescue contract — overflow-safe token recovery.
//!
//! Provides admin-gated entrypoints to recover tokens accidentally sent to
//! a Callora contract.  **All** arithmetic uses `checked_*` operations;
//! there are no raw `+`, `-`, or `*` in production paths.
//!
//! # Entrypoints
//! | Function | Auth | Description |
//! |----------|------|-------------|
//! | [`CalloraRescue::init`]           | admin | One-time initialisation |
//! | [`CalloraRescue::rescue`]         | admin | Transfer `amount` of any token to `to` |
//! | [`CalloraRescue::rescue_capped`]  | admin | Like `rescue` but enforces a per-call cap |
//! | [`CalloraRescue::total_rescued`]  | —     | View: cumulative rescued amount |
//! | [`CalloraRescue::get_admin`]      | —     | View: current admin address |
//!
//! # Security
//! - `require_auth` on every state-changing entrypoint.
//! - No `unwrap()` in production paths; all fallible ops return `Result`.
//! - Overflow-safe: `checked_add`, `checked_sub` with explicit error variants.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, token, Address, Env};

// ---------------------------------------------------------------------------
// Error catalogue
// ---------------------------------------------------------------------------

/// Errors returned by the rescue contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RescueError {
    /// Contract has not been initialised yet.
    NotInitialized = 1,
    /// `init` was already called.
    AlreadyInitialized = 2,
    /// Caller is not the stored admin.
    Unauthorized = 3,
    /// `amount` must be strictly positive.
    AmountNotPositive = 4,
    /// On-ledger balance is too low to satisfy the requested rescue.
    InsufficientBalance = 5,
    /// Arithmetic overflow detected in a checked operation.
    Overflow = 6,
    /// Requested amount exceeds the configured per-call rescue cap.
    ExceedsCap = 7,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

/// On-chain data keys for the rescue contract.
#[contracttype]
pub enum DataKey {
    /// Stored admin [`Address`] (instance storage).
    Admin,
    /// Running total of all tokens rescued across all calls (instance storage).
    TotalRescued,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

/// Callora rescue contract.
///
/// Admin-gated, overflow-safe token recovery surface.
#[contract]
pub struct CalloraRescue;

#[contractimpl]
impl CalloraRescue {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Initialise the rescue contract with `admin` as the sole authorised
    /// rescuer.
    ///
    /// # Errors
    /// - [`RescueError::AlreadyInitialized`] if called more than once.
    pub fn init(env: Env, admin: Address) -> Result<(), RescueError> {
        admin.require_auth();

        if env.storage().instance().has(&DataKey::Admin) {
            return Err(RescueError::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        // Initialise total rescued counter to zero (overflow-safe baseline).
        env.storage()
            .instance()
            .set(&DataKey::TotalRescued, &0_i128);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // State-changing entrypoints
    // -----------------------------------------------------------------------

    /// Transfer `amount` units of `token` from this contract to `to`.
    ///
    /// The on-ledger balance of `token` held by this contract must be at
    /// least `amount`.  The cumulative rescued counter is updated with
    /// overflow protection.
    ///
    /// # Auth
    /// Requires `admin.require_auth()`.
    ///
    /// # Errors
    /// - [`RescueError::NotInitialized`] if `init` was not called.
    /// - [`RescueError::Unauthorized`] if `admin` does not match stored admin.
    /// - [`RescueError::AmountNotPositive`] if `amount <= 0`.
    /// - [`RescueError::InsufficientBalance`] if on-ledger balance < amount.
    /// - [`RescueError::Overflow`] if cumulative counter would overflow i128.
    pub fn rescue(
        env: Env,
        admin: Address,
        token: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), RescueError> {
        admin.require_auth();

        Self::assert_admin(&env, &admin)?;

        if amount <= 0 {
            return Err(RescueError::AmountNotPositive);
        }

        let token_client = token::Client::new(&env, &token);
        let vault = env.current_contract_address();
        let on_ledger = token_client.balance(&vault);

        if on_ledger < amount {
            return Err(RescueError::InsufficientBalance);
        }

        // Overflow-safe transfer execution.
        token_client.transfer(&vault, &to, &amount);

        // Update running total with overflow-safe addition.
        let prev: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRescued)
            .unwrap_or(0_i128);
        let next = prev
            .checked_add(amount)
            .ok_or(RescueError::Overflow)?;
        env.storage().instance().set(&DataKey::TotalRescued, &next);

        Ok(())
    }

    /// Like [`rescue`] but also enforces that `amount <= cap`.
    ///
    /// Useful when the caller wants an extra on-chain guard against
    /// oversized individual rescue operations.
    ///
    /// # Auth
    /// Requires `admin.require_auth()`.
    ///
    /// # Errors
    /// All errors from [`rescue`], plus:
    /// - [`RescueError::ExceedsCap`] if `amount > cap`.
    pub fn rescue_capped(
        env: Env,
        admin: Address,
        token: Address,
        to: Address,
        amount: i128,
        cap: i128,
    ) -> Result<(), RescueError> {
        admin.require_auth();

        Self::assert_admin(&env, &admin)?;

        if amount <= 0 {
            return Err(RescueError::AmountNotPositive);
        }

        // cap must also be positive; use checked comparison.
        if cap <= 0 || amount > cap {
            return Err(RescueError::ExceedsCap);
        }

        let token_client = token::Client::new(&env, &token);
        let vault = env.current_contract_address();
        let on_ledger = token_client.balance(&vault);

        if on_ledger < amount {
            return Err(RescueError::InsufficientBalance);
        }

        token_client.transfer(&vault, &to, &amount);

        let prev: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRescued)
            .unwrap_or(0_i128);
        let next = prev
            .checked_add(amount)
            .ok_or(RescueError::Overflow)?;
        env.storage().instance().set(&DataKey::TotalRescued, &next);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read-only views (no auth required)
    // -----------------------------------------------------------------------

    /// Return the cumulative amount rescued across all calls.
    ///
    /// Returns `0` before `init` is called (no storage entry yet).
    pub fn total_rescued(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalRescued)
            .unwrap_or(0_i128)
    }

    /// Return the stored admin address.
    ///
    /// # Errors
    /// - [`RescueError::NotInitialized`] if `init` was not called.
    pub fn get_admin(env: Env) -> Result<Address, RescueError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RescueError::NotInitialized)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Assert that `caller` matches the stored admin.
    fn assert_admin(env: &Env, caller: &Address) -> Result<(), RescueError> {
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RescueError::NotInitialized)?;
        if caller != &stored {
            return Err(RescueError::Unauthorized);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(CalloraRescue, ());
        let admin = Address::generate(&env);
        (env, contract_id, admin)
    }

    fn client<'a>(env: &'a Env, contract_id: &'a Address) -> CalloraRescueClient<'a> {
        CalloraRescueClient::new(env, contract_id)
    }

    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    #[test]
    fn test_init_sets_admin() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        assert_eq!(c.get_admin(), admin);
    }

    #[test]
    fn test_double_init_returns_already_initialized() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        assert_eq!(
            c.try_init(&admin).unwrap_err().unwrap(),
            RescueError::AlreadyInitialized
        );
    }

    #[test]
    fn test_get_admin_before_init_returns_not_initialized() {
        let (env, cid, _admin) = setup();
        let c = client(&env, &cid);
        assert_eq!(
            c.try_get_admin().unwrap_err().unwrap(),
            RescueError::NotInitialized
        );
    }

    // -----------------------------------------------------------------------
    // total_rescued view
    // -----------------------------------------------------------------------

    #[test]
    fn test_total_rescued_starts_at_zero() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        assert_eq!(c.total_rescued(), 0);
    }

    // -----------------------------------------------------------------------
    // Validation: amount must be positive
    // -----------------------------------------------------------------------

    #[test]
    fn test_rescue_zero_amount_returns_amount_not_positive() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        let token = Address::generate(&env);
        let to = Address::generate(&env);
        assert_eq!(
            c.try_rescue(&admin, &token, &to, &0_i128)
                .unwrap_err()
                .unwrap(),
            RescueError::AmountNotPositive
        );
    }

    #[test]
    fn test_rescue_negative_amount_returns_amount_not_positive() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        let token = Address::generate(&env);
        let to = Address::generate(&env);
        assert_eq!(
            c.try_rescue(&admin, &token, &to, &-1_i128)
                .unwrap_err()
                .unwrap(),
            RescueError::AmountNotPositive
        );
    }

    // -----------------------------------------------------------------------
    // Validation: cap enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn test_rescue_capped_exceeds_cap_returns_error() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        let token = Address::generate(&env);
        let to = Address::generate(&env);
        assert_eq!(
            c.try_rescue_capped(&admin, &token, &to, &1001_i128, &1000_i128)
                .unwrap_err()
                .unwrap(),
            RescueError::ExceedsCap
        );
    }

    #[test]
    fn test_rescue_capped_zero_cap_returns_error() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        let token = Address::generate(&env);
        let to = Address::generate(&env);
        assert_eq!(
            c.try_rescue_capped(&admin, &token, &to, &1_i128, &0_i128)
                .unwrap_err()
                .unwrap(),
            RescueError::ExceedsCap
        );
    }

    // -----------------------------------------------------------------------
    // Unauthorised access
    // -----------------------------------------------------------------------

    #[test]
    fn test_rescue_wrong_admin_returns_unauthorized() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        c.init(&admin);
        let imposter = Address::generate(&env);
        let token = Address::generate(&env);
        let to = Address::generate(&env);
        assert_eq!(
            c.try_rescue(&imposter, &token, &to, &1_i128)
                .unwrap_err()
                .unwrap(),
            RescueError::Unauthorized
        );
    }

    // -----------------------------------------------------------------------
    // Not-initialized guard
    // -----------------------------------------------------------------------

    #[test]
    fn test_rescue_before_init_returns_not_initialized() {
        let (env, cid, admin) = setup();
        let c = client(&env, &cid);
        let token = Address::generate(&env);
        let to = Address::generate(&env);
        assert_eq!(
            c.try_rescue(&admin, &token, &to, &1_i128)
                .unwrap_err()
                .unwrap(),
            RescueError::NotInitialized
        );
    }
}
