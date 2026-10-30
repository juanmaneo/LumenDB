//! Lamport logical clock (Lamport 1978): ordering of events in a distributed
//! system, independent of any wall clock. `tick()` on local events,
//! `observe(msg_time)` on message receipt implements happens-before:
//! if a -> b then L(a) < L(b).
//!
//! Invariants (for every `t < u64::MAX`, i.e. before the 2^64-th event):
//! - `tick()` returns `now_before + 1`, so time strictly increases;
//! - `observe(t)` returns `max(now_before, t) + 1`, which is strictly greater
//!   than both the local time and the observed time.
//!
//! At `u64::MAX` the clock saturates instead of wrapping or panicking, so it is
//! never observed to go backwards.

#[derive(Clone, Debug, Default)]
pub struct LamportClock {
    time: u64,
}

impl LamportClock {
    /// A clock at time 0.
    pub fn new() -> Self {
        LamportClock { time: 0 }
    }

    /// A clock starting at time `t`.
    pub fn with_time(t: u64) -> Self {
        LamportClock { time: t }
    }

    /// Current logical time; pure.
    pub fn now(&self) -> u64 {
        self.time
    }

    /// Local event: advances time by one and returns the new time.
    pub fn tick(&mut self) -> u64 {
        self.time = self.time.saturating_add(1);
        self.time
    }

    /// Message receipt carrying `msg_time`: sets time to
    /// `max(now, msg_time) + 1` and returns it.
    pub fn observe(&mut self, msg_time: u64) -> u64 {
        self.time = self.time.max(msg_time).saturating_add(1);
        self.time
    }

    /// Alias of [`LamportClock::tick`]: timestamp for an outgoing message.
    pub fn stamp(&mut self) -> u64 {
        self.tick()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causality() {
        let mut a = LamportClock::new();
        let mut b = LamportClock::new();
        let t1 = a.tick();
        let t2 = a.stamp();
        let _ = t1;
        let t3 = b.observe(t2);
        let t4 = b.tick();
        assert!(t2 < t3 && t3 < t4);
    }

    #[test]
    fn concurrent_and_monotonic() {
        let mut a = LamportClock::new();
        let mut b = LamportClock::new();
        assert_eq!(a.tick(), b.tick()); // concurrent
        let t = b.observe(a.now());
        assert!(a.now() < t);
        let mut c = LamportClock::with_time(100);
        assert_eq!(c.observe(50), 101);
        assert_eq!(c.observe(200), 201);
        assert_eq!(c.now(), 201);
        assert_eq!(c.tick(), 202);
        let d = LamportClock::default();
        assert_eq!(d.now(), 0);
    }

    #[test]
    fn saturates_instead_of_wrapping() {
        let mut c = LamportClock::with_time(u64::MAX - 1);
        assert_eq!(c.tick(), u64::MAX);
        assert_eq!(c.tick(), u64::MAX);
        assert_eq!(c.observe(3), u64::MAX);
        assert_eq!(LamportClock::new().observe(u64::MAX), u64::MAX);
    }
}
