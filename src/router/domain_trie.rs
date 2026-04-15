//! Domain Trie — O(label_count) domain suffix matching
//!
//! Only handles suffix matching (domain and all subdomains).
//! Exact matching is handled by a simple HashSet in DomainMatcher.

use std::collections::HashMap;

struct TrieNode {
    children: HashMap<Box<str>, TrieNode>,
    is_terminal: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self { children: HashMap::new(), is_terminal: false }
    }
}

/// A domain suffix set. "google.com" matches google.com AND *.google.com.
///
/// Internally stores reversed domain labels: "google.com" → ["com", "google"].
pub struct DomainTrie {
    root: TrieNode,
    size: usize,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self { root: TrieNode::new(), size: 0 }
    }

    /// Add a domain suffix. "google.com" will match google.com and all subdomains.
    pub fn insert(&mut self, domain: &str) {
        let mut node = &mut self.root;
        for label in domain.rsplit('.') {
            node = node.children.entry(Box::from(label)).or_insert_with(TrieNode::new);
        }
        if !node.is_terminal {
            node.is_terminal = true;
            self.size += 1;
        }
    }

    /// Test if a domain matches any inserted suffix.
    ///
    /// Walks reversed labels; returns true if any ancestor node is terminal.
    pub fn contains(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.contains_normalized(&domain_lower)
    }

    /// Test if a normalized (lowercased) domain matches any inserted suffix.
    ///
    /// This avoids per-call lowercase allocation in hot paths where callers
    /// already provide normalized domains.
    pub fn contains_normalized(&self, domain_lower: &str) -> bool {
        let mut node = &self.root;

        for label in domain_lower.rsplit('.') {
            match node.children.get(label) {
                Some(child) => {
                    node = child;
                    if node.is_terminal {
                        return true;
                    }
                }
                None => return false,
            }
        }

        false
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn len(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suffix_match() {
        let mut trie = DomainTrie::new();
        trie.insert("google.com");

        assert!(trie.contains("google.com"));
        assert!(trie.contains("www.google.com"));
        assert!(trie.contains("deep.sub.google.com"));
        assert!(!trie.contains("notgoogle.com"));
        assert!(!trie.contains("com"));
    }

    #[test]
    fn test_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("google.com");

        assert!(trie.contains("WWW.GOOGLE.COM"));
        assert!(trie.contains_normalized("www.google.com"));
    }

    #[test]
    fn test_no_match() {
        let mut trie = DomainTrie::new();
        trie.insert("google.com");

        assert!(!trie.contains("facebook.com"));
    }

    #[test]
    fn test_deeper_suffix() {
        let mut trie = DomainTrie::new();
        trie.insert("com");

        assert!(trie.contains("google.com"));
        assert!(trie.contains("facebook.com"));
    }

    #[test]
    fn test_len() {
        let mut trie = DomainTrie::new();
        assert_eq!(trie.len(), 0);

        trie.insert("google.com");
        trie.insert("facebook.com");
        assert_eq!(trie.len(), 2);

        trie.insert("google.com"); // duplicate
        assert_eq!(trie.len(), 2);
    }
}
