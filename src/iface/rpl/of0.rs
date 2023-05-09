use super::{neighbor_table::*, rank::Rank};

pub struct ObjectiveFunction0 {}

impl ObjectiveFunction0 {
    pub const OCP: u16 = 0;

    const RANK_STRETCH: u16 = 0;
    const RANK_FACTOR: u16 = 1;
    const RANK_STEP: u16 = 3;

    pub(crate) fn new_rank(_rank: Rank, parent_rank: Rank) -> Rank {
        Rank::new(
            parent_rank.value + Self::rank_increase(parent_rank),
            parent_rank.min_hop_rank_increase,
        )
    }

    pub(crate) fn rank_increase(parent_rank: Rank) -> u16 {
        (Self::RANK_FACTOR * Self::RANK_STEP + Self::RANK_STRETCH)
            * parent_rank.min_hop_rank_increase
    }

    /// Return the most preferred neighbor from the table.
    pub(crate) fn preferred_parent(neighbors: &ParentSet) -> Option<Parent> {
        let mut preferred_parent = None;
        for n in &neighbors.parents {
            if let ParentEntry::Parent((n, _)) = n {
                if preferred_parent.is_none() {
                    preferred_parent = Some(*n);
                } else {
                    let parent1 = preferred_parent.as_ref().unwrap();

                    if parent1.rank.dag_rank() > n.rank.dag_rank() {
                        preferred_parent = Some(*n);
                    }
                }
            }
        }

        preferred_parent
    }
}
