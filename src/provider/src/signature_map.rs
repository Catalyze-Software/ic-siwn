use ic_cdk::api::time;
use ic_certified_map::{leaf_hash, AsHashTree, Hash, HashTree, RbTree};
use std::borrow::Cow;
use std::collections::BinaryHeap;

const DELEGATION_SIGNATURE_EXPIRES_AT: u64 = 60 * 1_000_000_000; // 1 minute

#[derive(Default)]
struct Unit;

impl AsHashTree for Unit {
    fn root_hash(&self) -> Hash {
        leaf_hash(&b""[..])
    }
    fn as_hash_tree(&self) -> HashTree<'_> {
        HashTree::Leaf(Cow::from(&b""[..]))
    }
}

#[derive(PartialEq, Eq)]
struct SigExpiration {
    seed_hash: Hash,
    delegation_hash: Hash,
    signature_expires_at: u64,
}

impl Ord for SigExpiration {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap is a max heap, but we want expired entries
        // first, hence the inversed order.
        other.signature_expires_at.cmp(&self.signature_expires_at)
    }
}

impl PartialOrd for SigExpiration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The SignatureMap maintains the tree of delegation hashes required for authentication.
#[derive(Default)]
pub struct SignatureMap {
    certified_map: RbTree<Hash, RbTree<Hash, Unit>>,
    expiration_queue: BinaryHeap<SigExpiration>,
}

impl SignatureMap {
    pub fn put(&mut self, seed_hash: Hash, delegation_hash: Hash) {
        let signature_expires_at = time() + DELEGATION_SIGNATURE_EXPIRES_AT;

        if self.certified_map.get(&seed_hash[..]).is_none() {
            let mut submap = RbTree::new();
            submap.insert(delegation_hash, Unit);
            self.certified_map.insert(seed_hash, submap);
        } else {
            self.certified_map.modify(&seed_hash[..], |submap| {
                submap.insert(delegation_hash, Unit);
            });
        }
        self.expiration_queue.push(SigExpiration {
            seed_hash,
            delegation_hash,
            signature_expires_at,
        });
    }

    pub fn delete(&mut self, seed_hash: Hash, delegation_hash: Hash) {
        let mut is_empty = false;
        self.certified_map.modify(&seed_hash[..], |m| {
            m.delete(&delegation_hash[..]);
            is_empty = m.is_empty();
        });
        if is_empty {
            self.certified_map.delete(&seed_hash[..]);
        }
    }

    pub fn prune_expired(&mut self, now: u64, max_to_prune: usize) -> usize {
        let mut num_pruned = 0;

        // Never prune more than the size of the expiration queue.
        let max_to_prune = std::cmp::min(max_to_prune, self.expiration_queue.len());

        for _step in 0..max_to_prune {
            if let Some(expiration) = self.expiration_queue.peek() {
                if expiration.signature_expires_at > now {
                    return num_pruned;
                }
            }
            if let Some(expiration) = self.expiration_queue.pop() {
                self.delete(expiration.seed_hash, expiration.delegation_hash);
            }
            num_pruned += 1;
        }

        num_pruned
    }

    pub fn is_expired(&self, now: u64, seed_hash: Hash, delegation_hash: Hash) -> bool {
        let expiration = self
            .expiration_queue
            .iter()
            .find(|e| e.seed_hash == seed_hash && e.delegation_hash == delegation_hash);
        if let Some(expiration) = expiration {
            return now > expiration.signature_expires_at;
        }
        false
    }

    pub fn root_hash(&self) -> Hash {
        self.certified_map.root_hash()
    }

    pub fn witness(&self, seed_hash: Hash, delegation_hash: Hash) -> Option<HashTree<'_>> {
        self.certified_map
            .get(&seed_hash[..])?
            .get(&delegation_hash[..])?;
        let witness = self.certified_map.nested_witness(&seed_hash[..], |nested| {
            nested.witness(&delegation_hash[..])
        });
        Some(witness)
    }
}
