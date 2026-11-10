//! Running the same work on many items, on scoped threads of std when that
//! pays: starting a thread costs tens of microseconds, and the work on an
//! item (a column of a query) may be a fraction of one.

use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// How long the items are worked on, one after the other, before it is
/// decided whether the rest is worth threads.
const PROBE: Duration = Duration::from_micros(150);

/// The time that the rest of the items must be estimated to take to be worth
/// a thread more.
const WORTH: Duration = Duration::from_micros(800);

/// The most threads to use when `limit` is the limit asked for (0: as many
/// as there are cores).
pub(crate) fn threads_for(limit: usize) -> usize {
    // (Asking is not free: it reads the limits of the cgroup.)
    static CORES: OnceLock<usize> = OnceLock::new();
    let cores = *CORES.get_or_init(|| thread::available_parallelism().map_or(1, usize::from));
    [limit, cores][usize::from(limit == 0)]
}

/// `f` of every item, in the order of the items. The first ones are done on
/// this thread, and measured; if the rest is going to take long enough, it is
/// shared between up to `threads` threads (this one is one of them), each
/// taking the next item when it is free.
pub(crate) fn map<T: Send, R: Send>(threads: usize, items: Vec<T>, f: impl Fn(T) -> R + Sync) -> Vec<R> {
    let mut items = items.into_iter().enumerate();
    let mut done = Vec::with_capacity(items.len());
    let start = Instant::now();
    while start.elapsed() < PROBE {
        let Some((i, item)) = items.next() else { break };
        done.push((i, f(item)));
    }
    let per_item = start.elapsed() / done.len().max(1) as u32;
    let workers = workers(per_item, items.len(), threads);
    if workers < 2 {
        done.extend(items.map(|(i, item)| (i, f(item))));
    } else {
        let queue = Mutex::new(items);
        let shared = Mutex::new(done);
        let work = || {
            let mut mine = Vec::new();
            loop {
                // (The lock is held to take an item, not to work on it.)
                let next = queue.lock().expect("a worker panicked").next();
                let Some((i, item)) = next else { break };
                mine.push((i, f(item)));
            }
            shared.lock().expect("a worker panicked").extend(mine);
        };
        thread::scope(|scope| {
            (1..workers).for_each(|_| {
                scope.spawn(work);
            });
            work();
        });
        done = shared.into_inner().expect("a worker panicked");
    }
    done.sort_unstable_by_key(|d| d.0);
    done.into_iter().map(|d| d.1).collect()
}

/// How many threads (this one included) should share `left` items that are
/// measured to take `per_item` each: one for every WORTH of work, at most
/// `threads`, and not more than there are items.
fn workers(per_item: Duration, left: usize, threads: usize) -> usize {
    let estimate = per_item.saturating_mul(left as u32);
    let workers = (estimate.as_micros() / WORTH.as_micros()) as usize;
    workers.min(threads).min(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::thread::ThreadId;

    /// `f` of `items` items that each take `work`: the results, and the
    /// threads that did the work.
    fn run(threads: usize, items: usize, work: Duration) -> (Vec<usize>, HashSet<ThreadId>) {
        let seen = Mutex::new(HashSet::new());
        let out = map(threads, (0..items).collect(), |i| {
            if !work.is_zero() {
                thread::sleep(work);
            }
            seen.lock().unwrap().insert(thread::current().id());
            i * 2
        });
        (out, seen.into_inner().unwrap())
    }

    #[test]
    fn results_come_in_the_order_of_the_items() {
        for (threads, items, work) in [
            (1, 100, 0),
            (8, 100, 0),
            (8, 40, 1500),
            (64, 40, 1500),
            (4, 0, 0),
            (4, 1, 3000),
        ] {
            let (out, _) = run(threads, items, Duration::from_micros(work));
            assert_eq!(out, (0..items).map(|i| i * 2).collect::<Vec<_>>(), "{threads} {items}");
        }
    }

    #[test]
    fn light_work_stays_on_this_thread_and_heavy_work_is_shared() {
        // (Decided on fixed measurements: a real one of light work depends
        // on how busy the machine is.)
        let us = Duration::from_micros;
        assert_eq!(workers(Duration::from_nanos(50), 500, 8), 0, "25 us of work");
        assert_eq!(workers(us(100), 20, 8), 2, "2 ms of work");
        assert_eq!(workers(us(1000), 39, 4), 4, "no more than allowed");
        assert_eq!(workers(us(1000), 39, 1), 1);
        assert_eq!(workers(us(5000), 3, 8), 3, "no more than there are items");
        // Items of a millisecond each, forty of them: slowness only adds to
        // the measurement, so the work is shared.
        let (_, threads) = run(4, 40, Duration::from_millis(1));
        assert!(threads.len() > 1, "{threads:?}");
        // Not more threads than are allowed, and not the first one alone.
        assert!(threads.len() <= 4, "{threads:?}");
        // One thread is no sharing at all.
        let (_, threads) = run(1, 40, Duration::from_millis(1));
        assert_eq!(threads.len(), 1);
    }

    #[test]
    fn thread_counts() {
        assert_eq!(threads_for(3), 3);
        assert!(threads_for(0) >= 1);
    }
}
