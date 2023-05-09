use super::rank::Rank;
use super::SequenceCounter;
use crate::time::{Duration, Instant};
use crate::wire::{HardwareAddress, Ipv6Address};

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ParentSet {
    pub(crate) parents: [ParentEntry; super::consts::DEFAULT_RPL_PARENT_SET_SIZE],
}

#[cfg(feature = "std")]
impl ToString for ParentSet {
    fn to_string(&self) -> String {
        let mut s = String::new();

        for n in self.parents.iter() {
            if let ParentEntry::Parent((Parent { rank, ip_addr, .. }, last_heard)) = n {
                s.push_str(&format!("IPv6={ip_addr} {rank} LH={last_heard}\n"));
            }
        }

        s
    }
}

impl ParentSet {
    /// Get the first free entry in the neighbor table.
    fn get_first_free_entry(&mut self) -> Option<&mut ParentEntry> {
        self.parents
            .iter_mut()
            .find(|parent| matches!(parent, ParentEntry::Empty))
    }

    /// Return a mutable reference to a neighbor matching the IPv6 address.
    pub(crate) fn get_parent(&mut self, addr: &Ipv6Address) -> Option<&mut (Parent, Instant)> {
        self.parents
            .iter_mut()
            .find(|parent| match parent {
                ParentEntry::Parent((Parent { ip_addr, .. }, _)) if ip_addr == addr => true,
                _ => false,
            })
            .map(|n| match n {
                ParentEntry::Parent(n) => n,
                ParentEntry::Empty => unreachable!(),
            })
    }

    pub(crate) fn remove_parent(&mut self, addr: &Ipv6Address) {
        if let Some(parent) = self.parents.iter_mut().find(|parent| match parent {
            ParentEntry::Parent((Parent { ip_addr, .. }, _)) if ip_addr == addr => true,
            _ => false,
        }) {
            *parent = ParentEntry::Empty;
        }
    }

    fn find_worst_parent(&mut self) -> Option<&mut Parent> {
        let mut worst_parent = None;

        for n in &mut self.parents {
            if let ParentEntry::Parent((parent, _)) = n {
                if worst_parent.is_none() {
                    worst_parent = Some(parent);
                } else if worst_parent.as_ref().unwrap().rank.dag_rank() < parent.rank.dag_rank() {
                    worst_parent = Some(parent)
                }
            } else {
                continue;
            }
        }

        worst_parent
    }

    /// Add a neighbor to the neighbor table.
    pub(crate) fn add_parent(&mut self, parent: Parent, instant: Instant) {
        // First look if there is place in the parent set.
        if let Some(entry) = self.get_first_free_entry() {
            *entry = ParentEntry::Parent((parent, instant));
            return;
        }

        // We didn't find the neighbor and there was no free space in the table.
        // We remove the neighbor with the highest rank.
        let entry = self.find_worst_parent().unwrap();
        if parent.rank.dag_rank() < entry.rank.dag_rank() {
            *entry = parent;
        }
    }

    pub fn count(&self) -> usize {
        self.parents
            .iter()
            .filter(|n| matches!(n, ParentEntry::Parent(_)))
            .count()
    }

    pub(crate) fn clear(&mut self) {
        self.parents
            .iter_mut()
            .for_each(|p| *p = ParentEntry::Empty);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.parents
            .iter()
            .filter(|p| matches!(p, ParentEntry::Parent(_)))
            .count()
            == 0
    }

    pub(crate) fn purge(&mut self, f: impl Fn(&(Parent, Instant)) -> bool) {
        self.parents
            .iter_mut()
            .filter(|p| match p {
                ParentEntry::Empty => false,
                ParentEntry::Parent(inner) => f(inner),
            })
            .for_each(|p| *p = ParentEntry::Empty);
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum ParentEntry {
    #[default]
    Empty,
    Parent((Parent, Instant)),
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Parent {
    pub(crate) rank: Rank,
    pub(crate) ip_addr: Ipv6Address,
    pub(crate) preference: u8,
    pub(crate) version_number: SequenceCounter,
}

impl Parent {
    pub fn new(
        ip_addr: Ipv6Address,
        rank: Rank,
        preference: Option<u8>,
        version_number: SequenceCounter,
    ) -> Self {
        Self {
            ip_addr,
            rank,
            preference: preference.unwrap_or(0),
            version_number,
        }
    }

    pub fn update_rank(&mut self, rank: Rank) {
        self.rank = rank;
    }

    pub fn update_preference(&mut self, preference: u8) {
        self.preference = preference;
    }

    pub fn update_version_number(&mut self, version_number: SequenceCounter) {
        self.version_number = version_number;
    }
}
