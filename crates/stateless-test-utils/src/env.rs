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

/// Sets `key` to `value`, runs `f`, then removes `key`. The `guard` parameter is
/// compile-time proof that the caller holds [`env_lock`], so no other thread can
/// observe the variable set (or a torn `environ`) during `f`.
pub fn with_env_var<T>(
    guard: &MutexGuard<'_, ()>,
    key: &str,
    value: &str,
    f: impl FnOnce() -> T,
) -> T {
    with_env_vars(guard, &[(key, value)], f)
}

/// [`with_env_var`] for several variables at once: all are set before `f` runs and all
/// are removed after it, even when `f` panics — [`env_lock`] ignores poisoning, so a leaked
/// variable would otherwise reach every later test of the binary.
pub fn with_env_vars<T>(
    _guard: &MutexGuard<'_, ()>,
    vars: &[(&str, &str)],
    f: impl FnOnce() -> T,
) -> T {
    struct Unset<'a>(&'a [(&'a str, &'a str)]);
    impl Drop for Unset<'_> {
        fn drop(&mut self) {
            for (key, _) in self.0 {
                // SAFETY: the caller's guard outlives this frame, unwinding included, so
                // `env_lock()` is still held here.
                unsafe { std::env::remove_var(key) };
            }
        }
    }

    for (key, value) in vars {
        // SAFETY: `_guard` proves the caller holds `env_lock()`, which serializes all env
        // access in this binary, satisfying Rust 2024's no-concurrent-env-access rule.
        unsafe { std::env::set_var(key, value) };
    }
    let _unset = Unset(vars);
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panicking `f` still unsets its variables.
    #[test]
    fn variables_are_removed_even_when_f_panics() {
        let guard = env_lock();
        let key = "STATELESS_TEST_UTILS_WITH_ENV_VARS_PANIC";
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_env_vars(&guard, &[(key, "set")], || panic!("f panics"))
        }));
        assert!(caught.is_err());
        assert!(std::env::var(key).is_err(), "the variable outlived the panic");
    }
}
