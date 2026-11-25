use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::{DashMap, Entry};
use tokio::time::Instant;

use crate::heartbeat::PushkeyHash;
use crate::matrix::QuietHours;
use crate::ssrf::ValidatedPushUrl;

const ON_DEMAND_SWEEP_COOLDOWN: Duration = Duration::from_secs(5);

/// Grouping key for debounced notifications: `(sha256(pushkey), room_id)`.
pub type DebounceKey = (PushkeyHash, String);

/// Validated device credentials and delivery rules stored in a pending batch.
#[derive(Debug, Clone)]
pub struct PendingDevice {
    pub url: ValidatedPushUrl,
    pub pushkey: String,
    pub pushkey_hash: PushkeyHash,
    pub p256dh: String,
    pub auth: String,
    pub quiet_hours: Option<QuietHours>,
}

/// Coalesced notification batch waiting for its rolling-window deadline.
#[derive(Debug)]
pub struct PendingBatch {
    pub device: PendingDevice,
    pub room_id: String,
    pub latest_event_id: String,
    pub count: u32,
    pub first_seen: Instant,
    pub deadline: Instant,
    pub batch_id: u64,
}

/// Result of attempting to enqueue a notification into [`DebounceStore`].
#[derive(Debug, PartialEq, Eq)]
pub enum EnqueueResult {
    /// A new batch was created; the caller must spawn a flusher task for `batch_id`.
    SpawnFlusher { batch_id: u64 },
    /// An existing batch was updated in place; its existing flusher task will handle it.
    Updated,
    /// Store is at capacity; caller should fall back to immediate delivery.
    AtCapacity,
}

/// Result of polling a pending batch from its background flusher task.
#[derive(Debug)]
pub enum PollBatch {
    /// Deadline has not elapsed yet; sleep until this instant and poll again.
    SleepUntil(Instant),
    /// Deadline reached; batch has been atomically removed and is ready to send.
    Ready(Box<PendingBatch>),
    /// Batch was already removed or superseded by a newer `batch_id`.
    Gone,
}

/// Bounded in-memory store for rolling-window debounce batches and
/// asynchronously discovered expired push subscriptions (`404` / `410`).
pub struct DebounceStore {
    batches: DashMap<DebounceKey, PendingBatch>,
    batch_count: AtomicUsize,
    max_batches: usize,
    max_wait: Duration,
    next_batch_id: AtomicU64,

    rejected_hashes: DashMap<PushkeyHash, Instant>,
    rejected_count: AtomicUsize,
    max_rejected: usize,
    rejected_ttl: Duration,
    last_rejected_sweep: Mutex<Option<Instant>>,
}

impl DebounceStore {
    #[must_use]
    pub fn new(
        max_batches: usize,
        max_wait: Duration,
        rejected_ttl: Duration,
        max_rejected: usize,
    ) -> Self {
        Self {
            batches: DashMap::new(),
            batch_count: AtomicUsize::new(0),
            max_batches,
            max_wait,
            next_batch_id: AtomicU64::new(1),
            rejected_hashes: DashMap::new(),
            rejected_count: AtomicUsize::new(0),
            max_rejected,
            rejected_ttl,
            last_rejected_sweep: Mutex::new(None),
        }
    }

    /// Inserts or updates a pending batch for `(device.pushkey_hash, room_id)`.
    ///
    /// `window` is clamped to `self.max_wait`, and the rolling deadline is
    /// capped at `first_seen + self.max_wait`. Consecutive retries with the
    /// same `event_id` refresh device metadata without inflating `count` or
    /// extending the deadline.
    pub fn enqueue(
        &self,
        device: PendingDevice,
        room_id: String,
        event_id: String,
        window: Duration,
    ) -> EnqueueResult {
        let now = Instant::now();
        let clamped_window = window.min(self.max_wait);
        let key: DebounceKey = (device.pushkey_hash, room_id.clone());

        if let Some(mut existing) = self.batches.get_mut(&key) {
            update_batch(
                &mut existing,
                device,
                event_id,
                now,
                clamped_window,
                self.max_wait,
            );
            return EnqueueResult::Updated;
        }

        if !try_reserve_slot(&self.batch_count, self.max_batches) {
            return EnqueueResult::AtCapacity;
        }

        match self.batches.entry(key) {
            Entry::Occupied(mut occupied) => {
                // Another task inserted this key while we reserved a slot.
                self.batch_count.fetch_sub(1, Ordering::Release);
                update_batch(
                    occupied.get_mut(),
                    device,
                    event_id,
                    now,
                    clamped_window,
                    self.max_wait,
                );
                EnqueueResult::Updated
            }
            Entry::Vacant(vacant) => {
                let batch_id = self.next_batch_id.fetch_add(1, Ordering::Relaxed);
                vacant.insert(PendingBatch {
                    device,
                    room_id,
                    latest_event_id: event_id,
                    count: 1,
                    first_seen: now,
                    deadline: now + clamped_window,
                    batch_id,
                });
                EnqueueResult::SpawnFlusher { batch_id }
            }
        }
    }

    /// Checks whether the batch owned by `batch_id` is ready to flush.
    ///
    /// If the deadline has elapsed, atomically removes the batch and frees its slot.
    pub fn poll_ready(&self, key: &DebounceKey, batch_id: u64) -> PollBatch {
        let now = Instant::now();
        match self.batches.entry(key.clone()) {
            Entry::Occupied(occupied) => {
                let entry = occupied.get();
                if entry.batch_id != batch_id {
                    return PollBatch::Gone;
                }
                if entry.deadline > now {
                    return PollBatch::SleepUntil(entry.deadline);
                }
                let batch = occupied.remove();
                self.batch_count.fetch_sub(1, Ordering::Release);
                PollBatch::Ready(Box::new(batch))
            }
            Entry::Vacant(_) => PollBatch::Gone,
        }
    }

    /// Removes and returns any pending batch for `key` (e.g. when a highlight
    /// bypasses debouncing and coalesces previously queued events).
    pub fn take_pending(&self, key: &DebounceKey) -> Option<PendingBatch> {
        self.batches.remove(key).map(|(_, batch)| {
            self.batch_count.fetch_sub(1, Ordering::Release);
            batch
        })
    }

    /// Removes all pending batches for `pushkey_hash` (e.g. on a Matrix
    /// unread-reset notification with `counts.unread == 0`) and returns how
    /// many were cleared.
    pub fn clear_device_pending(&self, pushkey_hash: &PushkeyHash) -> usize {
        let mut removed = 0usize;
        self.batches.retain(|(hash, _), _| {
            if hash == pushkey_hash {
                removed += 1;
                false
            } else {
                true
            }
        });
        if removed > 0 {
            self.batch_count.fetch_sub(removed, Ordering::Release);
        }
        removed
    }

    /// Returns `true` if `hash` was recently marked expired (`404`/`410`) by a
    /// background flush.
    #[must_use]
    pub fn is_rejected(&self, hash: &PushkeyHash) -> bool {
        let now = Instant::now();
        self.rejected_hashes
            .get(hash)
            .is_some_and(|expires_at| *expires_at > now)
    }

    /// Records a `pushkey_hash` as rejected for `rejected_ttl`.
    pub fn record_rejected(&self, hash: PushkeyHash) {
        let expires_at = Instant::now() + self.rejected_ttl;

        if let Some(mut existing) = self.rejected_hashes.get_mut(&hash) {
            *existing = expires_at;
            return;
        }

        if !try_reserve_slot(&self.rejected_count, self.max_rejected)
            && (!self.try_on_demand_rejected_sweep()
                || !try_reserve_slot(&self.rejected_count, self.max_rejected))
        {
            tracing::warn!("rejected pushkey cache at capacity; skipping record");
            return;
        }

        match self.rejected_hashes.entry(hash) {
            Entry::Occupied(mut occupied) => {
                *occupied.get_mut() = expires_at;
                self.rejected_count.fetch_sub(1, Ordering::Release);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(expires_at);
            }
        }
    }

    /// Sweeps expired entries from `rejected_hashes` and returns the count pruned.
    #[must_use]
    pub fn sweep_expired_rejected(&self) -> usize {
        let now = Instant::now();
        let mut pruned = 0usize;
        self.rejected_hashes.retain(|_, expires_at| {
            if *expires_at > now {
                true
            } else {
                pruned += 1;
                false
            }
        });
        if pruned > 0 {
            self.rejected_count.fetch_sub(pruned, Ordering::Release);
        }
        pruned
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.batches.len()
    }

    #[must_use]
    pub fn rejected_len(&self) -> usize {
        self.rejected_hashes.len()
    }

    fn try_on_demand_rejected_sweep(&self) -> bool {
        let now = Instant::now();
        {
            let mut guard = self
                .last_rejected_sweep
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(last) = *guard
                && now.saturating_duration_since(last) < ON_DEMAND_SWEEP_COOLDOWN
            {
                return false;
            }
            *guard = Some(now);
        }

        let _ = self.sweep_expired_rejected();
        true
    }
}

fn try_reserve_slot(counter: &AtomicUsize, max_entries: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= max_entries {
            return false;
        }
        match counter.compare_exchange_weak(
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

fn update_batch(
    existing: &mut PendingBatch,
    device: PendingDevice,
    event_id: String,
    now: Instant,
    clamped_window: Duration,
    max_wait: Duration,
) {
    existing.device = device;
    if existing.latest_event_id != event_id {
        existing.latest_event_id = event_id;
        existing.count = existing.count.saturating_add(1);
        let max_deadline = existing.first_seen + max_wait;
        existing.deadline = (now + clamped_window).min(max_deadline);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::hash_pushkey;

    fn test_device(pushkey: &str) -> PendingDevice {
        PendingDevice {
            url: ValidatedPushUrl::parse(pushkey).unwrap(),
            pushkey: pushkey.to_owned(),
            pushkey_hash: hash_pushkey(pushkey),
            p256dh: "p256dh".into(),
            auth: "auth".into(),
            quiet_hours: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rolling_window_extends_and_respects_max_wait() {
        let store = DebounceStore::new(10, Duration::from_secs(10), Duration::from_secs(3600), 10);
        let pushkey = "https://fcm.googleapis.com/fcm/send/d1";
        let key = (hash_pushkey(pushkey), "!room:example.org".to_owned());

        let EnqueueResult::SpawnFlusher { batch_id } = store.enqueue(
            test_device(pushkey),
            "!room:example.org".into(),
            "$e1".into(),
            Duration::from_secs(3),
        ) else {
            panic!("expected SpawnFlusher");
        };

        // Advance 2s and enqueue a second message -> deadline moves from 3s to 5s.
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            store.enqueue(
                test_device(pushkey),
                "!room:example.org".into(),
                "$e2".into(),
                Duration::from_secs(3),
            ),
            EnqueueResult::Updated
        );

        // At t=3s, not ready yet.
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            store.poll_ready(&key, batch_id),
            PollBatch::SleepUntil(_)
        ));

        // Keep pushing every 2s until hitting the 10s max_wait cap.
        for i in 3..=6 {
            tokio::time::advance(Duration::from_secs(2)).await;
            let _ = store.enqueue(
                test_device(pushkey),
                "!room:example.org".into(),
                format!("$e{i}"),
                Duration::from_secs(3),
            );
        }
        // We are now at t=11s >= max_wait (10s), so it must flush immediately.
        let PollBatch::Ready(batch) = store.poll_ready(&key, batch_id) else {
            panic!("expected Ready after max_wait");
        };
        assert_eq!(batch.count, 6);
        assert_eq!(batch.latest_event_id, "$e6");
        assert_eq!(store.pending_len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_cache_expires_and_respects_capacity() {
        let store = DebounceStore::new(10, Duration::from_secs(10), Duration::from_secs(60), 2);
        let h1 = hash_pushkey("d1");
        let h2 = hash_pushkey("d2");
        let h3 = hash_pushkey("d3");

        store.record_rejected(h1);
        store.record_rejected(h2);
        assert!(store.is_rejected(&h1));
        assert!(store.is_rejected(&h2));

        // Full -> h3 is ignored while unexpired
        store.record_rejected(h3);
        assert!(!store.is_rejected(&h3));

        // After TTL expires, h3 succeeds via on-demand sweep
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(!store.is_rejected(&h1));
        store.record_rejected(h3);
        assert!(store.is_rejected(&h3));
        assert_eq!(store.rejected_len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn consecutive_duplicate_event_id_does_not_inflate_count_or_deadline() {
        let store = DebounceStore::new(10, Duration::from_secs(10), Duration::from_secs(60), 10);
        let pushkey = "https://fcm.googleapis.com/fcm/send/d1";
        let key = (hash_pushkey(pushkey), "!room:example.org".to_owned());

        let EnqueueResult::SpawnFlusher { batch_id } = store.enqueue(
            test_device(pushkey),
            "!room:example.org".into(),
            "$e1".into(),
            Duration::from_secs(3),
        ) else {
            panic!("expected SpawnFlusher");
        };

        // Retry of $e1 at t=2s must not increment count or push deadline past t=3s.
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            store.enqueue(
                test_device(pushkey),
                "!room:example.org".into(),
                "$e1".into(),
                Duration::from_secs(3),
            ),
            EnqueueResult::Updated
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        let PollBatch::Ready(batch) = store.poll_ready(&key, batch_id) else {
            panic!("expected Ready at original t=3s deadline");
        };
        assert_eq!(batch.count, 1);
        assert_eq!(batch.latest_event_id, "$e1");
    }

    #[tokio::test(start_paused = true)]
    async fn stale_batch_id_returns_gone_after_take_and_reenqueue() {
        let store = DebounceStore::new(10, Duration::from_secs(10), Duration::from_secs(60), 10);
        let pushkey = "https://fcm.googleapis.com/fcm/send/d1";
        let key = (hash_pushkey(pushkey), "!room:example.org".to_owned());

        // Batch 1 created at t=0, deadline t=3s
        let EnqueueResult::SpawnFlusher { batch_id: id1 } = store.enqueue(
            test_device(pushkey),
            "!room:example.org".into(),
            "$e1".into(),
            Duration::from_secs(3),
        ) else {
            panic!("expected SpawnFlusher");
        };

        // Highlight takes Batch 1 at t=1s
        tokio::time::advance(Duration::from_secs(1)).await;
        let taken = store.take_pending(&key).expect("batch 1 should be pending");
        assert_eq!(taken.batch_id, id1);
        assert_eq!(store.pending_len(), 0);

        // New Batch 2 enqueued at t=1.5s, deadline t=4.5s
        tokio::time::advance(Duration::from_millis(500)).await;
        let EnqueueResult::SpawnFlusher { batch_id: id2 } = store.enqueue(
            test_device(pushkey),
            "!room:example.org".into(),
            "$e3".into(),
            Duration::from_secs(3),
        ) else {
            panic!("expected SpawnFlusher for batch 2");
        };
        assert_ne!(id1, id2);

        // Stale flusher for Batch 1 wakes at t=3s -> must see Gone and leave Batch 2 intact
        tokio::time::advance(Duration::from_millis(1500)).await;
        assert!(matches!(store.poll_ready(&key, id1), PollBatch::Gone));
        assert!(matches!(
            store.poll_ready(&key, id2),
            PollBatch::SleepUntil(_)
        ));
        assert_eq!(store.pending_len(), 1);

        // Batch 2 flushes cleanly at t=4.5s
        tokio::time::advance(Duration::from_millis(1500)).await;
        let PollBatch::Ready(batch2) = store.poll_ready(&key, id2) else {
            panic!("expected Batch 2 Ready at t=4.5s");
        };
        assert_eq!(batch2.latest_event_id, "$e3");
        assert_eq!(batch2.count, 1);
        assert_eq!(store.pending_len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn enforces_batch_capacity_allows_updates_and_frees_slots() {
        let store = DebounceStore::new(2, Duration::from_secs(10), Duration::from_secs(60), 10);
        let pushkey = "https://fcm.googleapis.com/fcm/send/d1";
        let key1 = (hash_pushkey(pushkey), "!r1:example.org".to_owned());
        let key2 = (hash_pushkey(pushkey), "!r2:example.org".to_owned());

        let EnqueueResult::SpawnFlusher { batch_id: id1 } = store.enqueue(
            test_device(pushkey),
            "!r1:example.org".into(),
            "$e1".into(),
            Duration::from_secs(3),
        ) else {
            panic!("expected SpawnFlusher for r1");
        };

        assert!(matches!(
            store.enqueue(
                test_device(pushkey),
                "!r2:example.org".into(),
                "$e2".into(),
                Duration::from_secs(3),
            ),
            EnqueueResult::SpawnFlusher { .. }
        ));

        // Updating an existing key at capacity still succeeds
        assert_eq!(
            store.enqueue(
                test_device(pushkey),
                "!r1:example.org".into(),
                "$e1b".into(),
                Duration::from_secs(3),
            ),
            EnqueueResult::Updated
        );

        // New key at capacity returns AtCapacity
        assert_eq!(
            store.enqueue(
                test_device(pushkey),
                "!r3:example.org".into(),
                "$e3".into(),
                Duration::from_secs(3),
            ),
            EnqueueResult::AtCapacity
        );

        // Taking r2 frees 1 slot -> r3 can now be enqueued
        assert!(store.take_pending(&key2).is_some());
        assert!(matches!(
            store.enqueue(
                test_device(pushkey),
                "!r3:example.org".into(),
                "$e3".into(),
                Duration::from_secs(3),
            ),
            EnqueueResult::SpawnFlusher { .. }
        ));

        // Flushing r1 via poll_ready frees its slot as well
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(matches!(store.poll_ready(&key1, id1), PollBatch::Ready(_)));
        assert_eq!(store.pending_len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn clear_device_pending_only_clears_target_device_and_frees_slots() {
        let store = DebounceStore::new(3, Duration::from_secs(10), Duration::from_secs(60), 10);
        let d1 = "https://fcm.googleapis.com/fcm/send/d1";
        let d2 = "https://fcm.googleapis.com/fcm/send/d2";

        let _ = store.enqueue(
            test_device(d1),
            "!r1:example.org".into(),
            "$e1".into(),
            Duration::from_secs(3),
        );
        let _ = store.enqueue(
            test_device(d1),
            "!r2:example.org".into(),
            "$e2".into(),
            Duration::from_secs(3),
        );
        let _ = store.enqueue(
            test_device(d2),
            "!r1:example.org".into(),
            "$e3".into(),
            Duration::from_secs(3),
        );
        assert_eq!(store.pending_len(), 3);

        assert_eq!(store.clear_device_pending(&hash_pushkey(d1)), 2);
        assert_eq!(store.pending_len(), 1);

        // Slots were freed -> d2 can enqueue two more rooms up to max_batches = 3.
        assert!(matches!(
            store.enqueue(
                test_device(d2),
                "!r2:example.org".into(),
                "$e4".into(),
                Duration::from_secs(3)
            ),
            EnqueueResult::SpawnFlusher { .. }
        ));
        assert!(matches!(
            store.enqueue(
                test_device(d2),
                "!r3:example.org".into(),
                "$e5".into(),
                Duration::from_secs(3)
            ),
            EnqueueResult::SpawnFlusher { .. }
        ));
    }
}
