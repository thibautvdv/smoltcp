use crate::time::{Duration, Instant};
use crate::wire::Ipv6Address;

use super::{lollipop::SequenceCounter, rank::Rank};
use crate::config::RPL_PARENTS_BUFFER_COUNT;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Parent {
    pub dodag_id: Ipv6Address,
    pub rank: Rank,
    pub version_number: SequenceCounter,
    pub dtsn: SequenceCounter,
    pub last_heard: Instant,
}

impl Parent {
    /// Create a new parent.
    pub(crate) fn new(
        rank: Rank,
        version_number: SequenceCounter,
        dtsn: SequenceCounter,
        dodag_id: Ipv6Address,
        last_heard: Instant,
    ) -> Self {
        Self {
            rank,
            version_number,
            dtsn,
            dodag_id,
            last_heard,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ParentSet {
    parents: heapless::LinearMap<Ipv6Address, Parent, { RPL_PARENTS_BUFFER_COUNT }>,
}

impl ParentSet {
    /// Add a new parent to the parent set. The Rank of the new parent should be lower than the
    /// Rank of the node that holds this parent set.
    pub(crate) fn add(&mut self, address: Ipv6Address, parent: Parent) {
        if let Some(p) = self.parents.get_mut(&address) {
            *p = parent;
        } else if let Err(p) = self.parents.insert(address, parent) {
            if let Some((w_a, w_p)) = self.worst_parent() {
                if w_p.rank.dag_rank() > parent.rank.dag_rank() {
                    self.parents.remove(&w_a.clone()).unwrap();
                    self.parents.insert(address, parent).unwrap();
                } else {
                    net_debug!("could not add {} to parent set, buffer is full", address);
                }
            } else {
                unreachable!()
            }
        }
    }

    pub(crate) fn remove(&mut self, address: &Ipv6Address) {
        self.parents.remove(address);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.parents.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.parents.clear();
    }

    /// Find a parent based on its address.
    pub(crate) fn find(&self, address: &Ipv6Address) -> Option<&Parent> {
        self.parents.get(address)
    }

    /// Find a mutable parent based on its address.
    pub(crate) fn find_mut(&mut self, address: &Ipv6Address) -> Option<&mut Parent> {
        self.parents.get_mut(address)
    }

    /// Return a slice to the parent set.
    pub(crate) fn parents(&self) -> impl Iterator<Item = (&Ipv6Address, &Parent)> {
        self.parents.iter()
    }

    /// Find the worst parent that is currently in the parent set.
    fn worst_parent(&self) -> Option<(&Ipv6Address, &Parent)> {
        self.parents.iter().max_by_key(|(k, v)| v.rank.dag_rank())
    }

    pub(crate) fn purge(&mut self, now: Instant, expiration: Duration) {
        let mut keys = heapless::Vec::<Ipv6Address, RPL_PARENTS_BUFFER_COUNT>::new();
        for (k, v) in self.parents.iter() {
            if v.last_heard + expiration < now {
                keys.push(*k);
            }
        }

        for k in keys {
            net_trace!("removed {} from parent set", &k);
            self.parents.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_parent() {
        let now = Instant::now();
        let mut set = ParentSet::default();
        set.add(
            Default::default(),
            Parent::new(
                Rank::ROOT,
                Default::default(),
                Default::default(),
                Default::default(),
                now,
            ),
        );

        assert_eq!(
            set.find(&Default::default()),
            Some(&Parent::new(
                Rank::ROOT,
                Default::default(),
                Default::default(),
                Default::default(),
                now,
            ))
        );
    }

    #[test]
    fn add_more_parents() {
        let now = Instant::now();
        use super::super::consts::DEFAULT_MIN_HOP_RANK_INCREASE;
        let mut set = ParentSet::default();

        let mut last_address = Default::default();
        for i in 0..RPL_PARENTS_BUFFER_COUNT {
            let i = i as u16;
            let mut address = Ipv6Address::default();
            address.0[15] = i as u8;
            last_address = address;

            set.add(
                address,
                Parent::new(
                    Rank::new(256 * i, DEFAULT_MIN_HOP_RANK_INCREASE),
                    Default::default(),
                    Default::default(),
                    address,
                    now,
                ),
            );

            assert_eq!(
                set.find(&address),
                Some(&Parent::new(
                    Rank::new(256 * i, DEFAULT_MIN_HOP_RANK_INCREASE),
                    Default::default(),
                    Default::default(),
                    address,
                    now,
                ))
            );
        }

        // This one is not added to the set, because its Rank is worse than any other parent in the
        // set.
        let mut address = Ipv6Address::default();
        address.0[15] = 8;
        set.add(
            address,
            Parent::new(
                Rank::new(256 * 8, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                Default::default(),
                address,
                now,
            ),
        );
        assert_eq!(set.find(&address), None);

        /// This Parent has a better rank than the last one in the set.
        let mut address = Ipv6Address::default();
        address.0[15] = 9;
        set.add(
            address,
            Parent::new(
                Rank::new(0, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                Default::default(),
                address,
                now,
            ),
        );
        assert_eq!(
            set.find(&address),
            Some(&Parent::new(
                Rank::new(0, DEFAULT_MIN_HOP_RANK_INCREASE),
                Default::default(),
                Default::default(),
                address,
                now,
            ))
        );
        assert_eq!(set.find(&last_address), None);
    }
}
