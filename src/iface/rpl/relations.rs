use crate::time::Instant;
use crate::wire::Ipv6Address;

use super::lollipop::SequenceCounter;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct RelationInfo {
    pub(crate) next_hop: Ipv6Address,
    pub(crate) expires_at: Instant,
    pub(crate) dao_sequence: SequenceCounter,
}

impl core::fmt::Display for RelationInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.next_hop)
    }
}

impl RelationInfo {
    pub fn next_hop(&self) -> Ipv6Address {
        self.next_hop
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Relations {
    pub(crate) relations: heapless::FnvIndexMap<
        Ipv6Address,
        RelationInfo,
        { super::consts::DEFAULT_RPL_ROUTING_TABLE_SIZE },
    >,
}

impl Relations {
    /// Adds a new relation if it does not exist
    pub fn add_relation_checked(&mut self, child: &Ipv6Address, rel: RelationInfo) {
        if !self.relations.contains_key(child) {
            self.relations.insert(*child, rel).unwrap();
        }
    }

    /// Removes an existing relation.
    pub fn remove_relation(&mut self, child: &Ipv6Address) {
        self.relations.remove(child);
    }

    /// Returns the parent of a given child
    pub fn find_next_hop(&self, child: &Ipv6Address) -> Option<Ipv6Address> {
        self.relations.get(child).map(|r| r.next_hop)
    }

    /// Remove relations that expired.    
    pub fn purge(&mut self, now: Instant) {
        self.relations.retain(|_, r| r.expires_at > now)
    }
}

impl core::fmt::Display for Relations {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Routing table:")?;
        for (k, r) in &self.relations {
            writeln!(f, "{k} -> {r}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::*;

    fn addreses(count: usize) -> Vec<Ipv6Address> {
        let mut addreses = vec![];

        for i in 0..count {
            let mut ip_addr = Ipv6Address::default();
            ip_addr.0[0] = i as u8;
            addreses.push(ip_addr);
        }

        addreses
    }

    #[test]
    fn add_relation() {
        let addrs = addreses(2);

        let mut relations = Relations::default();
        let rel = RelationInfo {
            next_hop: addrs[1],
            expires_at: Instant::now(),
            dao_sequence: SequenceCounter::default(),
        };
        relations.add_relation_checked(&addrs[0], rel);
        assert!(relations.relations.contains_key(&addrs[0]));
        assert_eq!(relations.relations.get(&addrs[0]), Some(&rel));
        assert_eq!(
            relations.relations.get(&addrs[0]).unwrap().next_hop,
            addrs[1]
        );
        assert_eq!(
            relations.relations.get(&addrs[0]).unwrap().dao_sequence,
            SequenceCounter::default()
        );
        relations.add_relation_checked(&addrs[0], rel);
        assert_eq!(relations.relations.len(), 1);
    }

    #[test]
    fn remove_relation() {
        let addrs = addreses(3);

        let mut relations = Relations::default();
        let rel = RelationInfo {
            next_hop: addrs[1],
            expires_at: Instant::now(),
            dao_sequence: SequenceCounter::default(),
        };
        relations.add_relation_checked(&addrs[0], rel);

        // Tries to remove a non-existing relation, should not do anything
        relations.remove_relation(&addrs[2]);
        assert_eq!(relations.relations.len(), 1);
        assert_eq!(relations.relations.get(&addrs[0]), Some(&rel));

        relations.remove_relation(&addrs[0]);
        assert_eq!(relations.relations.len(), 0);
    }

    #[test]
    fn find_parent() {
        let addrs = addreses(5);

        let mut relations = Relations::default();

        let rel1 = RelationInfo {
            next_hop: addrs[2],
            expires_at: Instant::now(),
            dao_sequence: SequenceCounter::default(),
        };
        let rel2 = RelationInfo {
            next_hop: addrs[3],
            expires_at: Instant::now(),
            dao_sequence: SequenceCounter::default(),
        };
        relations.add_relation_checked(&addrs[0], rel1);
        relations.add_relation_checked(&addrs[1], rel2);

        assert_eq!(relations.find_next_hop(&addrs[0]), Some(addrs[2]));
        assert_eq!(relations.find_next_hop(&addrs[1]), Some(addrs[3]));
        assert_eq!(relations.find_next_hop(&addrs[4]), None);
    }

    #[test]
    fn purge() {
        let addrs = addreses(8);

        let mut relations = Relations::default();

        let rel1 = RelationInfo {
            next_hop: addrs[4],
            expires_at: Instant::now() + Duration::from_secs(100),
            dao_sequence: SequenceCounter::default(),
        };
        let rel2 = RelationInfo {
            next_hop: addrs[5],
            expires_at: Instant::now() + Duration::from_secs(100),
            dao_sequence: SequenceCounter::default(),
        };
        let rel3 = RelationInfo {
            next_hop: addrs[6],
            expires_at: Instant::now() + Duration::from_secs(100),
            dao_sequence: SequenceCounter::default(),
        };
        let rel4 = RelationInfo {
            next_hop: addrs[7],
            expires_at: Instant::now() - Duration::from_secs(100),
            dao_sequence: SequenceCounter::default(),
        };

        relations.add_relation_checked(&addrs[0], rel1);
        relations.add_relation_checked(&addrs[1], rel2);
        relations.add_relation_checked(&addrs[2], rel3);
        relations.add_relation_checked(&addrs[3], rel4);

        relations.purge(Instant::now());

        assert_eq!(relations.relations.len(), 3);
    }
}
