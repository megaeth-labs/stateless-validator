//! Process-wide env lock for tests that touch environment variables.
//!
//! Rust 2024's `unsafe { std::env::set_var }` precondition is "no other thread touches the
//! environment" — process-wide, not per-variable — because glibc/musl/Darwin `setenv` may
//! realloc the `environ` array while another thread's `getenv` reads it. That "other thread"
//! includes anything clap does under `#[clap(env = ...)]`, since `try_parse_from` calls
//! `std::env::var` for every such field.
//!
//! Every env-touching test in a given test binary must hold [`env_lock`] for the duration
//! of its env access. [`with_env_var`] takes the guard as proof-of-ownership so one test
//! can perform several operations (some that set env, some that merely read it) under a
//! single uninterrupted lock hold.

use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquires the process-wide env lock. Unpoisons on poison (a panicking test that held
/// the lock shouldn't fail every subsequent test).
pub fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Sets `key` to `value`, runs `f`, then removes `key`. The `_guard` parameter is
/// compile-time proof that the caller holds [`env_lock`], so no other thread can
/// observe the variable set (or a torn `environ`) during `f`.
pub fn with_env_var<T>(
    _guard: &MutexGuard<'_, ()>,
    key: &str,
    value: &str,
    f: impl FnOnce() -> T,
) -> T {
    // SAFETY: `_guard` proves the caller holds `env_lock()`, which serializes all env
    // access in this binary, satisfying Rust 2024's no-concurrent-env-access rule.
    unsafe { std::env::set_var(key, value) };
    let result = f();
    // SAFETY: same as above — still holding the guard.
    unsafe { std::env::remove_var(key) };
    result
}
