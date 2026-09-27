//! Clear generations of the connection, ticket and channel caches.
//!
//! Every cache key starts with `<isolation>|` (the workspace isolation). A
//! clear of everything (a vault lock) or of one isolation (a workspace
//! delete) starts a new generation. An attempt takes the current generation
//! before it acquires anything and may put something into the cache under a
//! key only while no clear since then covered that key, checked under the
//! same lock as the insert. A clear of one isolation leaves the attempts of
//! every other isolation alone.

use std::collections::HashMap;

#[derive(Debug, Default)]
pub(crate) struct Generations {
    current: u64,
    /// The generation the last clear of everything started.
    all: u64,
    /// The generation the last clear of each isolation started, since the
    /// last clear of everything (which covers them all).
    isolations: HashMap<String, u64>,
}

impl Generations {
    /// The current generation, taken when an attempt (or the execution it
    /// belongs to) begins.
    pub(crate) fn current(&self) -> u64 {
        self.current
    }

    /// Start a new generation that no earlier attempt may keep anything in.
    pub(crate) fn clear(&mut self) {
        self.current += 1;
        self.all = self.current;
        self.isolations.clear();
    }

    /// Start a new generation that no earlier attempt may keep anything of
    /// `isolation` in.
    pub(crate) fn clear_isolation(&mut self, isolation: &str) {
        self.current += 1;
        self.isolations.insert(isolation.to_string(), self.current);
    }

    /// Whether an attempt of `generation` may keep something under `key`.
    pub(crate) fn admits(&self, generation: u64, key: &str) -> bool {
        generation >= self.all && self.isolations.iter().all(|(isolation, &cleared)| generation >= cleared || !in_isolation(key, isolation))
    }
}

/// Whether a cache key belongs to `isolation` (it starts with `<isolation>|`).
pub(crate) fn in_isolation(key: &str, isolation: &str) -> bool {
    key.strip_prefix(isolation).is_some_and(|rest| rest.starts_with('|'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clear_fences_only_the_attempts_it_covers() {
        let mut g = Generations::default();
        let before = g.current();
        g.clear_isolation("ws-a");
        assert!(!g.admits(before, "ws-a|https://example.test:443"), "the deleted workspace's earlier attempt");
        assert!(g.admits(before, "ws-b|https://example.test:443"), "another workspace is not fenced");
        assert!(g.admits(before, "ws-ab|https://example.test:443"), "a workspace whose id only starts the same");
        assert!(g.admits(g.current(), "ws-a|https://example.test:443"), "an attempt that began after the delete");
        let after_delete = g.current();
        g.clear();
        for key in ["ws-a|x", "ws-b|x"] {
            assert!(!g.admits(before, key));
            assert!(!g.admits(after_delete, key));
            assert!(g.admits(g.current(), key));
        }
        assert!(g.isolations.is_empty(), "a clear of everything covers every isolation's clear");
    }
}
