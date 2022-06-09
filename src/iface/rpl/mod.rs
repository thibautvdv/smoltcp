mod lollipop;
mod neighbor_table;
mod obj_function;
mod of_zero;
mod rank;
mod routing;
mod trickle;

use crate::time::Instant;
use crate::wire::ipv6::Address;
use crate::wire::rpl::ModeOfOperation;
use crate::wire::*;
use crate::{rand::Rand, time::Duration};
pub(crate) use lollipop::SequenceCounter;
pub(crate) use neighbor_table::{RplNeighbor, RplNeighborEntry, RplNeighborTable};
pub(crate) use of_zero::ObjectiveFunction0;
pub(crate) use routing::{RplNode, RplNodeRelation, RplNodeRelations};

use self::obj_function::ObjectiveFunction;
pub(crate) use self::rank::Rank;

pub const RPL_DEFAULT_INSTANCE: u8 = 0x1e;
pub const RPL_MAX_INSTANCES: u8 = 1;
pub const RPL_MAX_DAG_PER_INSTANCE: u8 = 2;
pub const RPL_DAG_LIFETIME: u8 = 3;
pub const RPL_DEFAULT_LIFETIME_UNIT: u8 = 60;
pub const RPL_DEFAULT_LIFETIME: u8 = 30;
pub const RPL_PREFERENCE: u8 = 0;
pub const RPL_WITH_DAO_ACK: bool = false;
pub const RPL_REPAIR_ON_DAO_NACK: bool = false;
pub const RPL_DIO_REFRESH_DAO_ROUTES: u8 = 1;
pub const RPL_WITH_PROBING: bool = true;
pub const RPL_PROBING_INTERVAL: usize = 60;
pub const RPL_DIS_INTERVAL: usize = 60;
pub const RPL_DIS_START_DELAY: usize = 5;

/// This is 3 in the standard, but in Contiki they use:
pub const DEFAULT_DIO_INTERVAL_MIN: u8 = 12;
/// This is 20 in the standard, but in Contiki they use:
pub const DEFAULT_DIO_INTERVAL_DOUBLINGS: u8 = 8;
pub const DEFAULT_DIO_REDUNDANCY_CONSTANT: u8 = 10;
pub const DEFAULT_MIN_HOP_RANK_INCREASE: u16 = 256;

#[derive(Debug)]
pub struct RplBuilder {
    is_root: bool,
    dodag_preference: u8,
    dio_timer: trickle::TrickleTimer,
    instance_id: RplInstanceId,
    version_number: lollipop::SequenceCounter,
    dodag_id: Option<Address>,
    rank: rank::Rank,
    dtsn: lollipop::SequenceCounter,
}

impl RplBuilder {
    /// Create a new RPL configuration builder.
    pub fn new(now: Instant, rand: &mut Rand) -> RplBuilder {
        RplBuilder {
            is_root: false,
            dodag_preference: 0,
            dio_timer: trickle::TrickleTimer::new(
                now,
                DEFAULT_DIO_INTERVAL_MIN as u32,
                DEFAULT_DIO_INTERVAL_MIN as u32 + DEFAULT_DIO_INTERVAL_DOUBLINGS as u32,
                DEFAULT_DIO_REDUNDANCY_CONSTANT as usize,
                rand,
            ),
            instance_id: RplInstanceId::from(30), // NOTE: this is the value that contiki uses.
            version_number: lollipop::SequenceCounter::default(),
            dodag_id: None,
            // address of the Device is known.
            rank: Rank::INFINITE,
            dtsn: lollipop::SequenceCounter::default(),
        }
    }

    #[inline]
    pub fn set_root(mut self) -> Self {
        self.is_root = true;
        self.rank = Rank::ROOT;
        self
    }

    #[inline]
    pub fn set_preference(mut self, preference: u8) -> Self {
        self.dodag_preference = preference;
        self
    }

    /// Set the trickle timer.
    #[inline]
    pub fn set_dio_timer(mut self, dio_timer: trickle::TrickleTimer) -> Self {
        self.dio_timer = dio_timer;
        self
    }

    /// Set the Instance ID.
    #[inline]
    pub fn set_instance_id(mut self, instance_id: RplInstanceId) -> Self {
        self.instance_id = instance_id;
        self
    }

    /// Set the Version number.
    #[inline]
    pub fn set_version_number(mut self, version_number: lollipop::SequenceCounter) -> Self {
        self.version_number = version_number;
        self
    }

    /// Set the DODAG ID.
    #[inline]
    pub fn set_dodag_id(mut self, dodag_id: Address) -> Self {
        self.dodag_id = Some(dodag_id);
        self
    }

    /// Set the Rank.
    #[inline]
    pub fn set_rank(mut self, rank: Rank) -> Self {
        self.rank = rank;
        self
    }

    /// Set the DTSN.
    #[inline]
    pub fn set_dtsn(mut self, dtsn: lollipop::SequenceCounter) -> Self {
        self.dtsn = dtsn;
        self
    }

    /// Build the RPL configuration.
    #[inline]
    pub fn finalize(self) -> Rpl {
        Rpl {
            is_root: self.is_root,
            dis_expiration: Instant::ZERO + Duration::from_secs(5),
            dio_timer: self.dio_timer,
            neighbor_table: Default::default(),
            node_relations: Default::default(),
            instance_id: self.instance_id,
            version_number: self.version_number,
            dodag_id: self.dodag_id,
            rank: self.rank,
            dtsn: self.dtsn,
            parent_address: None,
            parent_rank: None,
            parent_preference: None,
            parent_last_heard: None,
            mode_of_operation: ModeOfOperation::NoDownwardRoutesMaintained,
            dodag_configuration: Default::default(),
            grounded: false,
            dodag_preference: self.dodag_preference,
            ocp: 0,
        }
    }
}

#[derive(Debug)]
pub enum RplMode {
    Mesh = 0,
    Feather = 1,
    Leaf = 2,
}

#[derive(Debug)]
pub struct Rpl {
    pub is_root: bool,
    pub dis_expiration: Instant,
    pub dio_timer: trickle::TrickleTimer,
    pub neighbor_table: RplNeighborTable,
    pub node_relations: RplNodeRelations,
    pub instance_id: RplInstanceId,
    pub version_number: lollipop::SequenceCounter,
    pub dodag_id: Option<Address>,
    pub rank: rank::Rank,
    pub dtsn: lollipop::SequenceCounter,
    pub parent_address: Option<Address>,
    pub parent_rank: Option<Rank>,
    pub parent_preference: Option<u8>,
    pub parent_last_heard: Option<Instant>,
    pub mode_of_operation: ModeOfOperation,
    pub dodag_configuration: DodagConfiguration,
    pub grounded: bool,
    pub dodag_preference: u8,
    pub ocp: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DodagConfiguration {
    pub authentication_enabled: bool,
    pub path_control_size: u8,
    pub dio_interval_doublings: u8,
    pub dio_interval_min: u8,
    pub dio_redundancy_constant: u8,
    pub max_rank_increase: u16,
    pub minimum_hop_rank_increase: u16,
    pub objective_code_point: u16,
    pub default_lifetime: u8,
    pub lifetime_unit: u16,
}

impl Default for DodagConfiguration {
    fn default() -> Self {
        Self {
            authentication_enabled: false,
            path_control_size: 0,
            dio_interval_doublings: DEFAULT_DIO_INTERVAL_DOUBLINGS,
            dio_interval_min: DEFAULT_DIO_INTERVAL_MIN,
            dio_redundancy_constant: DEFAULT_DIO_REDUNDANCY_CONSTANT,
            // FIXME: check where this value comes from:
            max_rank_increase: 7 * DEFAULT_MIN_HOP_RANK_INCREASE,
            minimum_hop_rank_increase: DEFAULT_MIN_HOP_RANK_INCREASE,
            objective_code_point: ObjectiveFunction0::OCP,
            default_lifetime: 30,
            lifetime_unit: 60,
        }
    }
}

impl Rpl {
    pub fn has_parent(&self) -> bool {
        self.parent_address.is_some()
    }

    pub fn should_send_dis(&self, now: Instant) -> bool {
        !self.has_parent() && !self.is_root && now >= self.dis_expiration
    }

    pub fn set_dis_expiration(&mut self, expiration: Instant) {
        self.dis_expiration = expiration;
    }

    pub fn dodag_information_object<'p>(&self) -> RplRepr<'p> {
        RplRepr::DodagInformationObject {
            rpl_instance_id: self.instance_id,
            version_number: self.version_number.value(),
            rank: self.rank.value,
            grounded: false,
            mode_of_operation: rpl::ModeOfOperation::NoDownwardRoutesMaintained,
            dodag_preference: self.dodag_preference,
            dtsn: self.dtsn.value(),
            dodag_id: self.dodag_id.unwrap(),
            options: &[],
        }
    }

    pub fn dodag_configuration(&self) -> RplOptionRepr<'static> {
        RplOptionRepr::DodagConfiguration {
            authentication_enabled: self.dodag_configuration.authentication_enabled,
            path_control_size: self.dodag_configuration.path_control_size,
            dio_interval_doublings: self.dodag_configuration.dio_interval_doublings,
            dio_interval_min: self.dodag_configuration.dio_interval_min,
            dio_redundancy_constant: self.dodag_configuration.dio_redundancy_constant,
            max_rank_increase: self.dodag_configuration.max_rank_increase,
            minimum_hop_rank_increase: self.dodag_configuration.minimum_hop_rank_increase,
            objective_code_point: self.dodag_configuration.objective_code_point,
            default_lifetime: self.dodag_configuration.default_lifetime,
            lifetime_unit: self.dodag_configuration.lifetime_unit,
        }
    }

    pub fn update_dodag_conf(&mut self, dodag_conf: &RplOptionRepr) {
        match dodag_conf {
            RplOptionRepr::DodagConfiguration {
                authentication_enabled,
                path_control_size,
                dio_interval_doublings,
                dio_interval_min,
                dio_redundancy_constant,
                max_rank_increase,
                minimum_hop_rank_increase,
                objective_code_point,
                default_lifetime,
                lifetime_unit,
            } => {
                self.dodag_configuration.authentication_enabled = *authentication_enabled;
                self.dodag_configuration.path_control_size = *path_control_size;
                self.dodag_configuration.dio_interval_doublings = *dio_interval_doublings;
                self.dodag_configuration.dio_interval_min = *dio_interval_min;
                self.dodag_configuration.dio_redundancy_constant = *dio_redundancy_constant;
                self.dodag_configuration.max_rank_increase = *max_rank_increase;
                self.dodag_configuration.minimum_hop_rank_increase = *minimum_hop_rank_increase;
                self.dodag_configuration.objective_code_point = *objective_code_point;
                self.dodag_configuration.default_lifetime = *default_lifetime;
                self.dodag_configuration.lifetime_unit = *lifetime_unit;
            }
            _ => unreachable!(),
        }
    }
}
