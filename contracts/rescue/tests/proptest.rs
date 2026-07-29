//! Property-based invariant tests for the rescue contract (#867).
//!
//! # Invariants
//!
//! 1. **Balance sync** — After every operation, the sum of the cumulative
//!    `total_rescued` counter plus the on-ledger token balance held by the
//!    contract must equal the initial contract balance.  Rejected operations
//!    must leave both values unchanged.
//!
//! 2. **Counter monotonicity** — `total_rescued` is monotonically
//!    non-decreasing; it increases only by the exact `amount` of a successful
//!    rescue and never changes on failure.
//!
//! 3. **Admin gating** — Every state-changing entrypoint enforces
//!    `require_auth` and `assert_admin`.  Calling with a non-admin address
//!    always returns [`RescueError::Unauthorized`] and leaves state untouched.
//!
//! 4. **Amount validation** — Zero and negative amounts are always rejected
//!    with [`RescueError::AmountNotPositive`] regardless of the caller.
//!
//! 5. **Cap enforcement** — `rescue_capped` with `amount > cap` (or
//!    `cap <= 0`) always fails with [`RescueError::ExceedsCap`].
//!
//! # Generator
//!
//! A deterministic xorshift64 PRNG (no external `proptest`/`rand` dependency)
//! drives `SEED_COUNT` independent traces of `TRACE_LEN` randomly chosen
//! operations each, so any failure is fully reproducible from the printed
//! `seed` and `step`.

use callora_rescue::{CalloraRescue, CalloraRescueClient, RescueError};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env};

const SEED_COUNT: u64 = 32;
const TRACE_LEN: u32 = 48;

/// Initial token balance minted to the contract for each trace.
const INITIAL_BALANCE: i128 = 1_000_000;

/// Maximum single-rescue amount used in valid operations.
const MAX_RESCUE: i128 = 100_000;

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64) — fully reproducible, no external dep.
// ---------------------------------------------------------------------------

struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        // Ensure non-zero state (xorshift stalls on zero).
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform random value in `[lo, hi]` (inclusive).
    fn range_i128(&mut self, lo: i128, hi: i128) -> i128 {
        if lo >= hi {
            return lo;
        }
        let span = (hi - lo) as u64 + 1;
        lo + (self.next_u64() % span) as i128
    }
}

// ---------------------------------------------------------------------------
// Operation types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Op {
    /// Successful rescue: positive amount, sufficient balance, correct admin.
    Rescue,
    /// Rescue with amount > on-ledger balance — must be rejected.
    RescueInsufficient,
    /// Rescue with amount == 0 — must be rejected.
    RescueZero,
    /// Rescue with amount < 0 — must be rejected.
    RescueNegative,
    /// Successful rescue_capped: amount <= cap, sufficient balance.
    RescueCapped,
    /// rescue_capped with amount > cap — must be rejected.
    RescueCappedExceedsCap,
    /// rescue_capped with cap <= 0 — must be rejected.
    RescueCappedZeroCap,
    /// rescue / rescue_capped with a non-admin caller — must be rejected.
    RescueUnauthorized,
}

fn pick_op(rng: &mut Prng) -> Op {
    match rng.next_u64() % 9 {
        0 => Op::Rescue,
        1 => Op::RescueInsufficient,
        2 => Op::RescueZero,
        3 => Op::RescueNegative,
        4 => Op::RescueCapped,
        5 => Op::RescueCappedExceedsCap,
        6 => Op::RescueCappedZeroCap,
        _ => Op::RescueUnauthorized,
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Create a fresh environment with a registered rescue contract and a
/// Stellar asset contract pre-funded with `initial_balance` tokens.
fn setup(
    env: &Env,
    initial_balance: i128,
) -> (CalloraRescueClient<'_>, Address, token::Client<'_>, token::StellarAssetClient<'_>) {
    env.mock_all_auths();

    let admin = Address::generate(env);
    let contract_id = env.register(CalloraRescue, ());
    let client = CalloraRescueClient::new(env, &contract_id);

    let token_admin = Address::generate(env);
    let token_addr = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(env, &token_addr);
    let token_admin_client = token::StellarAssetClient::new(env, &token_addr);

    if initial_balance > 0 {
        token_admin_client.mint(&contract_id, &initial_balance);
    }

    // Mint some tokens to the to-address so we can attempt transfers later.
    token_admin_client.mint(&admin, &initial_balance);

    client.init(&admin);

    (client, admin, token_client, token_admin_client)
}

/// Assert the core invariant: `total_rescued` + on-ledger balance == initial
/// balance, and `total_rescued` is non-negative.
fn assert_invariant(
    client: &CalloraRescueClient<'_>,
    token_client: &token::Client<'_>,
    initial_balance: i128,
    expected_total: i128,
    seed: u64,
    step: u32,
) {
    let total = client.total_rescued();
    let on_ledger = token_client.balance(&client.address);

    // total_rescued must never exceed the initial balance
    assert!(
        total >= 0,
        "seed={seed} step={step}: total_rescued ({total}) went negative"
    );

    // total_rescued must equal what we expect
    assert_eq!(
        total, expected_total,
        "seed={seed} step={step}: total_rescued ({total}) != expected ({expected_total})"
    );

    // on-ledger balance must be exactly initial minus total_rescued
    let expected_on_ledger = initial_balance - total;
    assert_eq!(
        on_ledger, expected_on_ledger,
        "seed={seed} step={step}: on-ledger balance ({on_ledger}) != expected ({expected_on_ledger})",
    );
}

// ---------------------------------------------------------------------------
// Seeded property traces
// ---------------------------------------------------------------------------

fn run_trace(seed: u64) {
    let env = Env::default();
    let (client, admin, token_client, _token_admin) = setup(&env, INITIAL_BALANCE);

    let mut rng = Prng::new(seed);
    let mut expected_total: i128 = 0;
    let recovered: Address = Address::generate(&env);

    assert_invariant(&client, &token_client, INITIAL_BALANCE, 0, seed, 0);

    for step in 1..=TRACE_LEN {
        let total_before = client.total_rescued();
        let balance_before = token_client.balance(&client.address);

        match pick_op(&mut rng) {
            // --- Successful rescue -------------------------------------------------
            Op::Rescue => {
                // Pick amount that is guaranteed to be ≤ current balance
                let max_possible = balance_before.min(MAX_RESCUE);
                let amount = if max_possible > 0 {
                    rng.range_i128(1, max_possible)
                } else {
                    1_i128 // will fail with InsufficientBalance — that's fine
                };

                let result = client.try_rescue(&admin, &token_client.address, &recovered, &amount);

                if max_possible > 0 && amount <= max_possible {
                    assert!(
                        result.is_ok(),
                        "seed={seed} step={step}: valid rescue({amount}) unexpectedly failed"
                    );
                    expected_total += amount;
                } else {
                    assert!(
                        result.is_err(),
                        "seed={seed} step={step}: rescue({amount}) with insufficient balance must fail"
                    );
                }
            }

            // --- Insufficient balance ----------------------------------------------
            Op::RescueInsufficient => {
                let amount = rng.range_i128(balance_before + 1, balance_before + MAX_RESCUE);
                let result = client.try_rescue(&admin, &token_client.address, &recovered, &amount);
                assert!(
                    result.is_err(),
                    "seed={seed} step={step}: rescue({amount}) > balance({balance_before}) must fail"
                );
            }

            // --- Zero amount -------------------------------------------------------
            Op::RescueZero => {
                let result = client.try_rescue(&admin, &token_client.address, &recovered, &0);
                assert_eq!(
                    result.unwrap_err().unwrap(),
                    RescueError::AmountNotPositive,
                    "seed={seed} step={step}: rescue(0) must return AmountNotPositive"
                );
            }

            // --- Negative amount ---------------------------------------------------
            Op::RescueNegative => {
                let amount = rng.range_i128(-MAX_RESCUE, -1);
                let result = client.try_rescue(&admin, &token_client.address, &recovered, &amount);
                assert_eq!(
                    result.unwrap_err().unwrap(),
                    RescueError::AmountNotPositive,
                    "seed={seed} step={step}: rescue({amount}) must return AmountNotPositive"
                );
            }

            // --- Successful capped rescue ------------------------------------------
            Op::RescueCapped => {
                let max_possible = balance_before.min(MAX_RESCUE);
                let amount = if max_possible > 0 {
                    rng.range_i128(1, max_possible)
                } else {
                    1_i128
                };
                let cap = amount + rng.range_i128(0, MAX_RESCUE);
                let result = client.try_rescue_capped(
                    &admin,
                    &token_client.address,
                    &recovered,
                    &amount,
                    &cap,
                );

                if max_possible > 0 && amount <= max_possible {
                    assert!(
                        result.is_ok(),
                        "seed={seed} step={step}: valid rescue_capped({amount}, cap={cap}) unexpectedly failed"
                    );
                    expected_total += amount;
                } else {
                    assert!(
                        result.is_err(),
                        "seed={seed} step={step}: rescue_capped({amount}) with insufficient balance must fail"
                    );
                }
            }

            // --- Capped rescue exceeding cap ---------------------------------------
            Op::RescueCappedExceedsCap => {
                let amount = rng.range_i128(1, MAX_RESCUE);
                let cap = rng.range_i128(0, amount - 1);
                let result = client.try_rescue_capped(
                    &admin,
                    &token_client.address,
                    &recovered,
                    &amount,
                    &cap,
                );
                assert_eq!(
                    result.unwrap_err().unwrap(),
                    RescueError::ExceedsCap,
                    "seed={seed} step={step}: rescue_capped({amount}, cap={cap}) must return ExceedsCap"
                );
            }

            // --- Capped rescue with zero cap ---------------------------------------
            Op::RescueCappedZeroCap => {
                let amount = rng.range_i128(1, MAX_RESCUE);
                let result = client.try_rescue_capped(
                    &admin,
                    &token_client.address,
                    &recovered,
                    &amount,
                    &0,
                );
                assert_eq!(
                    result.unwrap_err().unwrap(),
                    RescueError::ExceedsCap,
                    "seed={seed} step={step}: rescue_capped({amount}, cap=0) must return ExceedsCap"
                );
            }

            // --- Unauthorized caller -----------------------------------------------
            Op::RescueUnauthorized => {
                let imposter = Address::generate(&env);
                env.set_auths(&[]); // clear all auths so imposter fails

                let amount = rng.range_i128(1, MAX_RESCUE);
                let result = client.try_rescue(&imposter, &token_client.address, &recovered, &amount);
                assert!(
                    result.is_err(),
                    "seed={seed} step={step}: rescue by imposter must fail"
                );

                // Restore mock auths for remaining operations in this trace.
                env.mock_all_auths();
            }
        }

        // **Invariant**: after every operation, state must be consistent.
        assert_invariant(&client, &token_client, INITIAL_BALANCE, expected_total, seed, step);

        // **Monotonicity**: total_rescued must not have decreased.
        let total_after = client.total_rescued();
        assert!(
            total_after >= total_before,
            "seed={seed} step={step}: total_rescued decreased from {total_before} to {total_after}"
        );
    }
}

// ---------------------------------------------------------------------------
// Top-level test entry point
// ---------------------------------------------------------------------------

/// Run all `SEED_COUNT` deterministic seeded traces (each `TRACE_LEN` steps).
#[test]
fn rescue_invariant_holds_across_seeded_traces() {
    for seed in 0..SEED_COUNT {
        run_trace(seed);
    }
}

// ---------------------------------------------------------------------------
// Dedicated edge-case invariant tests
// ---------------------------------------------------------------------------

/// Rescue with amount exactly equal to the on-ledger balance succeeds and
/// leaves the contract with zero tokens.
#[test]
fn rescue_exact_full_balance_succeeds_and_drains() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(CalloraRescue, ());
    let client = CalloraRescueClient::new(&env, &contract_id);
    let to = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_addr = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_addr);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_addr);

    token_admin_client.mint(&contract_id, &5000);
    client.init(&admin);

    // Rescue the entire balance
    client.rescue(&admin, &token_addr, &to, &5000);

    assert_eq!(client.total_rescued(), 5000);
    assert_eq!(token_client.balance(&contract_id), 0);
}

/// After a rejected operation (AmountNotPositive), total_rescued and
/// on-ledger balance must be unchanged.
#[test]
fn rejected_amount_not_positive_does_not_mutate_state() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(CalloraRescue, ());
    let client = CalloraRescueClient::new(&env, &contract_id);
    let to = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_addr = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_addr);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_addr);

    token_admin_client.mint(&contract_id, &1000);
    client.init(&admin);

    // Perform a successful rescue first to have non-zero state
    client.rescue(&admin, &token_addr, &to, &500);
    assert_eq!(client.total_rescued(), 500);

    // Now try zero amount
    let total_before = client.total_rescued();
    let balance_before = token_client.balance(&contract_id);

    let result = client.try_rescue(&admin, &token_addr, &to, &0);
    assert_eq!(
        result.unwrap_err().unwrap(),
        RescueError::AmountNotPositive
    );

    assert_eq!(
        client.total_rescued(),
        total_before,
        "total_rescued changed after rejected zero-amount rescue"
    );
    assert_eq!(
        token_client.balance(&contract_id),
        balance_before,
        "on-ledger balance changed after rejected zero-amount rescue"
    );
}

/// After a rejected Unauthorized operation, total_rescued and on-ledger
/// balance must be unchanged.
#[test]
fn rejected_unauthorized_does_not_mutate_state() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(CalloraRescue, ());
    let client = CalloraRescueClient::new(&env, &contract_id);
    let to = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_addr = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_addr);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_addr);

    token_admin_client.mint(&contract_id, &1000);
    client.init(&admin);

    // Perform a successful rescue first
    client.rescue(&admin, &token_addr, &to, &300);
    assert_eq!(client.total_rescued(), 300);

    let imposter = Address::generate(&env);
    env.set_auths(&[]);

    let total_before = client.total_rescued();
    let balance_before = token_client.balance(&contract_id);

    let result = client.try_rescue(&imposter, &token_addr, &to, &100);
    assert!(result.is_err());

    assert_eq!(
        client.total_rescued(),
        total_before,
        "total_rescued changed after rejected unauthorized rescue"
    );
    assert_eq!(
        token_client.balance(&contract_id),
        balance_before,
        "on-ledger balance changed after rejected unauthorized rescue"
    );
}

/// Multiple rescues from the same token accumulate correctly in
/// total_rescued and deplete the on-ledger balance accordingly.
#[test]
fn multiple_rescues_accumulate_correctly() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(CalloraRescue, ());
    let client = CalloraRescueClient::new(&env, &contract_id);
    let to = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_addr = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_addr);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_addr);

    token_admin_client.mint(&contract_id, &10_000);
    client.init(&admin);

    let amounts: [i128; 5] = [100, 200, 300, 400, 500];

    for (i, &amount) in amounts.iter().enumerate() {
        client.rescue(&admin, &token_addr, &to, &amount);

        let expected_total: i128 = amounts[..=i].iter().sum();
        let expected_balance: i128 = 10_000 - expected_total;

        assert_eq!(
            client.total_rescued(),
            expected_total,
            "total_rescued mismatch after rescue {}",
            i + 1
        );
        assert_eq!(
            token_client.balance(&contract_id),
            expected_balance,
            "on-ledger balance mismatch after rescue {}",
            i + 1
        );
    }
}

/// Rescue_capped correctly enforces the cap even when the current balance
/// would otherwise be sufficient.
#[test]
fn rescue_capped_enforces_cap_above_balance() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register(CalloraRescue, ());
    let client = CalloraRescueClient::new(&env, &contract_id);
    let to = Address::generate(&env);

    let token_admin = Address::generate(&env);
    let token_addr = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let token_client = token::Client::new(&env, &token_addr);
    let token_admin_client = token::StellarAssetClient::new(&env, &token_addr);

    token_admin_client.mint(&contract_id, &10_000);
    client.init(&admin);

    // amount (500) exceeds cap (100) -> ExceedsCap (balance is sufficient)
    let err = client
        .try_rescue_capped(&admin, &token_addr, &to, &500, &100)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, RescueError::ExceedsCap);

    // State must be unchanged
    assert_eq!(client.total_rescued(), 0);
    assert_eq!(token_client.balance(&contract_id), 10_000);
}
