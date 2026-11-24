use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dashmap::{DashMap, Entry};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

/// Minimum interval between on-demand expired-entry sweeps triggered when the
/// heartbeat store is at capacity.
const ON_DEMAND_SWEEP_COOLDOWN: Duration = Duration::from_secs(5);

/// 32-byte SHA-256 digest of a device's `pushkey`.
pub type PushkeyHash = [u8; 32];

#[derive(Debug, Error, PartialEq, Eq)]
#[error("pushkey_hash must be exactly 64 lowercase ASCII hex characters")]
pub struct InvalidHashError;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("heartbeat store is at capacity")]
pub struct HeartbeatCapacityError;

/// Computes `sha256(pushkey.as_bytes())` directly as a 32-byte key.
#[must_use]
pub fn hash_pushkey(pushkey: &str) -> PushkeyHash {
    Sha256::digest(pushkey.as_bytes()).into()
}

/// Parses and validates a 64-character lowercase ASCII hex SHA-256 string.
///
/// # Errors
/// Returns [`InvalidHashError`] if `raw` is not 64 lowercase ASCII hex characters.
pub fn parse_pushkey_hash(raw: &str) -> Result<PushkeyHash, InvalidHashError> {
    if raw.len() != 64 || !raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(InvalidHashError);
    }

    let mut out = [0u8; 32];
    hex::decode_to_slice(raw, &mut out).map_err(|_| InvalidHashError)?;
    Ok(out)
}

/// Bounded, sharded in-memory store for active-session heartbeat leases.
pub struct HeartbeatStore {
    entries: DashMap<PushkeyHash, Instant>,
    count: AtomicUsize,
    last_on_demand_sweep: Mutex<Option<Instant>>,
    ttl: Duration,
    max_entries: usize,
}

impl HeartbeatStore {
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            count: AtomicUsize::new(0),
            last_on_demand_sweep: Mutex::new(None),
            ttl,
            max_entries,
        }
    }

    /// Returns `true` if `hash` currently has an unexpired heartbeat lease.
    #[must_use]
    pub fn is_active(&self, hash: &PushkeyHash) -> bool {
        let now = Instant::now();
        self.entries
            .get(hash)
            .is_some_and(|expires_at| *expires_at > now)
    }

    /// Records or refreshes a heartbeat lease for `hash`.
    ///
    /// Updating an existing key always succeeds. Inserting a new key when at
    /// `max_entries` prunes expired entries (subject to a cooldown) and returns
    /// [`HeartbeatCapacityError`] if still full.
    ///
    /// # Errors
    /// Returns [`HeartbeatCapacityError`] if the store is still at `max_entries`
    /// after attempting to prune expired entries.
    pub fn record(&self, hash: PushkeyHash) -> Result<(), HeartbeatCapacityError> {
        let expires_at = Instant::now() + self.ttl;

        if let Some(mut existing) = self.entries.get_mut(&hash) {
            *existing = expires_at;
            return Ok(());
        }

        if !self.try_reserve_slot() {
            if self.try_on_demand_sweep() {
                if !self.try_reserve_slot() {
                    return Err(HeartbeatCapacityError);
                }
            } else {
                return Err(HeartbeatCapacityError);
            }
        }

        match self.entries.entry(hash) {
            Entry::Occupied(mut occupied) => {
                // Another concurrent task inserted this key while we reserved a slot.
                *occupied.get_mut() = expires_at;
                self.count.fetch_sub(1, Ordering::Release);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(expires_at);
            }
        }

        Ok(())
    }

    /// Removes a heartbeat lease if present.
    pub fn remove(&self, hash: &PushkeyHash) {
        if self.entries.remove(hash).is_some() {
            self.count.fetch_sub(1, Ordering::Release);
        }
    }

    /// Removes all expired entries shard-by-shard and returns the number of
    /// pruned entries.
    #[must_use]
    pub fn sweep_expired(&self) -> usize {
        let now = Instant::now();
        let mut pruned = 0usize;
        self.entries.retain(|_, expires_at| {
            if *expires_at > now {
                true
            } else {
                pruned += 1;
                false
            }
        });
        if pruned > 0 {
            self.count.fetch_sub(pruned, Ordering::Release);
        }
        pruned
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn try_reserve_slot(&self) -> bool {
        let mut current = self.count.load(Ordering::Acquire);
        loop {
            if current >= self.max_entries {
                return false;
            }
            match self.count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn try_on_demand_sweep(&self) -> bool {
        let now = Instant::now();
        {
            let mut guard = self
                .last_on_demand_sweep
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(last) = *guard
                && now.saturating_duration_since(last) < ON_DEMAND_SWEEP_COOLDOWN
            {
                return false;
            }
            *guard = Some(now);
        }

        let _ = self.sweep_expired();
        true
    }
}

/// Spawns a periodic background task to sweep expired heartbeat leases.
#[must_use]
pub fn spawn_sweeper(store: Arc<HeartbeatStore>, sweep_interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(sweep_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Skip the immediate first tick.
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let pruned = store.sweep_expired();
            if pruned > 0 {
                tracing::debug!(pruned, remaining = store.len(), "swept expired heartbeats");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_pushkey_hash_format() {
        let valid_hex = hex::encode(hash_pushkey("https://fcm.googleapis.com/fcm/send/abc"));
        let parsed = parse_pushkey_hash(&valid_hex).unwrap();
        assert_eq!(
            parsed,
            hash_pushkey("https://fcm.googleapis.com/fcm/send/abc")
        );

        // Uppercase rejected
        assert_eq!(
            parse_pushkey_hash(&valid_hex.to_ascii_uppercase()).unwrap_err(),
            InvalidHashError
        );
        // Wrong length rejected
        assert_eq!(parse_pushkey_hash("abcd").unwrap_err(), InvalidHashError);
        // Non-hex rejected
        assert_eq!(
            parse_pushkey_hash(&"g".repeat(64)).unwrap_err(),
            InvalidHashError
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lease_expires_after_ttl_and_can_be_cleared() {
        let store = HeartbeatStore::new(Duration::from_secs(90), 10);
        let h = hash_pushkey("https://fcm.googleapis.com/fcm/send/device1");

        assert!(!store.is_active(&h));
        store.record(h).unwrap();
        assert!(store.is_active(&h));

        tokio::time::advance(Duration::from_secs(89)).await;
        assert!(store.is_active(&h));

        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!store.is_active(&h));

        // Re-record and explicitly remove
        store.record(h).unwrap();
        assert!(store.is_active(&h));
        store.remove(&h);
        assert!(!store.is_active(&h));
    }

    #[tokio::test(start_paused = true)]
    async fn enforces_capacity_and_prunes_expired_before_rejecting() {
        let store = HeartbeatStore::new(Duration::from_secs(30), 2);
        let h1 = hash_pushkey("d1");
        let h2 = hash_pushkey("d2");
        let h3 = hash_pushkey("d3");

        store.record(h1).unwrap();
        store.record(h2).unwrap();

        // Updating an existing lease at capacity succeeds
        store.record(h1).unwrap();

        // New lease while both are unexpired is rejected
        assert_eq!(store.record(h3).unwrap_err(), HeartbeatCapacityError);

        // After TTL expires, new insert prunes expired entries and succeeds
        tokio::time::advance(Duration::from_secs(31)).await;
        store.record(h3).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.is_active(&h3));
    }

    #[tokio::test(start_paused = true)]
    async fn remove_and_cooldown_keep_capacity_accurate() {
        let store = HeartbeatStore::new(Duration::from_secs(2), 1);
        let h1 = hash_pushkey("d1");
        let h2 = hash_pushkey("d2");

        store.record(h1).unwrap();
        // Triggers initial on-demand sweep at t=0, still full
        assert_eq!(store.record(h2).unwrap_err(), HeartbeatCapacityError);

        // Removing h1 frees the slot immediately without needing a sweep
        store.remove(&h1);
        assert_eq!(store.len(), 0);
        store.record(h2).unwrap();
        assert_eq!(store.len(), 1);
    }
}
