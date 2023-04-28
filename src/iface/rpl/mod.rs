#![allow(unused)]

pub(crate) mod of0;
pub(crate) mod consts;
pub(crate) mod lollipop;
pub(crate) mod neighbor_table;
pub(crate) mod rank;
pub(crate) mod trickle;
pub(crate) mod relations;

use crate::time::{Duration, Instant};
use crate::wire::{Ipv6Address, RplInstanceId, RplOptionRepr, RplRepr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ModeOfOperation {
    #[cfg(feature = "rpl-mop-0")]
    NoDownwardRoutesMaintained,
    #[cfg(feature = "rpl-mop-1")]
    NonStoringMode,
    #[cfg(feature = "rpl-mop-2")]
    StoringModeWithoutMulticast,
    #[cfg(feature = "rpl-mop-3")]
    StoringModeWithMulticast,
}

impl From<crate::wire::rpl::ModeOfOperation> for ModeOfOperation {
    fn from(value: crate::wire::rpl::ModeOfOperation) -> Self {
        use crate::wire::rpl::ModeOfOperation as WireMop;
        match value {
            WireMop::NoDownwardRoutesMaintained => Self::NoDownwardRoutesMaintained,
            #[cfg(feature = "rpl-mop-1")]
            WireMop::NonStoringMode => Self::NonStoringMode,
            #[cfg(feature = "rpl-mop-2")]
            WireMop::StoringModeWithoutMulticast => Self::StoringModeWithoutMulticast,
            #[cfg(feature = "rpl-mop-3")]
            WireMop::StoringModeWithMulticast => Self::StoringModeWithMulticast,

            _ => Self::NoDownwardRoutesMaintained, // FIXME: is this the correct thing to do?
        }
    }
}

impl From<ModeOfOperation> for crate::wire::rpl::ModeOfOperation {
    fn from(value: ModeOfOperation) -> Self {
        use crate::wire::rpl::ModeOfOperation as WireMop;

        match value {
            ModeOfOperation::NoDownwardRoutesMaintained => WireMop::NoDownwardRoutesMaintained,
            #[cfg(feature = "rpl-mop-1")]
            ModeOfOperation::NonStoringMode => WireMop::NonStoringMode,
            #[cfg(feature = "rpl-mop-2")]
            ModeOfOperation::StoringModeWithoutMulticast => WireMop::StoringModeWithoutMulticast,
            #[cfg(feature = "rpl-mop-3")]
            ModeOfOperation::StoringModeWithMulticast => WireMop::StoringModeWithMulticast,
        }
    }
}

pub struct Config {
    pub root: Option<RootConfig>,
    pub dio_timer: trickle::TrickleTimer,
    pub instance_id: RplInstanceId,
    pub version_number: lollipop::SequenceCounter,
    pub mode_of_operation: ModeOfOperation,
    dtsn: lollipop::SequenceCounter,
    rank: rank::Rank,
}

impl Default for Config {
    fn default() -> Self {
        #![allow(unused_variables)]

        #[cfg(feature = "rpl-mop-0")]
        let mode_of_operation = ModeOfOperation::NoDownwardRoutesMaintained;
        #[cfg(feature = "rpl-mop-1")]
        let mode_of_operation = ModeOfOperation::NonStoringMode;
        #[cfg(feature = "rpl-mop-2")]
        let mode_of_operation = ModeOfOperation::StoringModeWithoutMulticast;
        #[cfg(feature = "rpl-mop-3")]
        let mode_of_operation = ModeOfOperation::StoringModeWithMulticast;

        Self {
            root: None,
            dio_timer: trickle::TrickleTimer::default(),
            instance_id: RplInstanceId::from(consts::DEFAULT_RPL_INSTANCE_ID),
            version_number: lollipop::SequenceCounter::default(),
            rank: rank::Rank::INFINITE,
            dtsn: lollipop::SequenceCounter::default(),
            mode_of_operation,
        }
    }
}

impl Config {
    pub fn into_root(mut self, root_config: RootConfig) -> Self {
        self.root = Some(root_config);
        self.rank = rank::Rank::ROOT;
        self
    }

    fn is_root(&self) -> bool {
        self.root.is_some()
    }
}

#[derive(Clone, Copy)]
pub struct RootConfig {
    pub preference: u8,
    pub dodag_id: Ipv6Address,
}

pub struct Rpl {
    pub(crate) is_root: bool,
    pub(crate) instance_id: RplInstanceId,
    pub(crate) version_number: lollipop::SequenceCounter,
    pub(crate) dodag_id: Option<Ipv6Address>,
    pub(crate) rank: rank::Rank,
    pub(crate) dtsn: lollipop::SequenceCounter,
    pub(crate) mode_of_operation: ModeOfOperation,
    pub(crate) preference: u8,

    pub(crate) dio_timer: trickle::TrickleTimer,
    pub(crate) dis_expiration: Instant,

    pub(crate) neighbors: neighbor_table::RplNeighborTable,
    pub(crate) relations: relations::Relations,

    pub(crate) parent_address: Option<Ipv6Address>,
    pub(crate) parent_rank: Option<rank::Rank>,
    pub(crate) parent_preference: Option<u8>,
    pub(crate) parent_last_heard: Option<Instant>,

    pub(crate) authentication_enabled: bool,
    pub(crate) path_contral_size: u8,
    pub(crate) dio_interval_doublings: u8,
    pub(crate) dio_interval_min: u8,
    pub(crate) dio_redundency_constant: u8,
    pub(crate) max_rank_increase: u16,
    pub(crate) minimum_hop_rank_increase: u16,
    pub(crate) objective_code_point: u16,
    pub(crate) default_lifetime: u8,
    pub(crate) lifetime_unit: u16,

    pub(crate) grounded: bool,
}

impl Rpl {
    pub fn new(config: Config) -> Self {
        Self {
            is_root: config.root.is_some(),
            instance_id: config.instance_id,
            version_number: config.version_number,
            dodag_id: config.root.map(|root| root.dodag_id),
            rank: config.rank,
            dtsn: config.dtsn,
            mode_of_operation: config.mode_of_operation,
            preference: config.root.map(|root| root.preference).unwrap_or(0),

            dio_timer: config.dio_timer,
            // TODO(thvdveld): we want to have it differently.
            dis_expiration: Instant::ZERO + Duration::from_secs(5),

            neighbors: neighbor_table::RplNeighborTable::default(),
            relations: relations::Relations::default(),

            parent_address: None,
            parent_rank: None,
            parent_preference: None,
            parent_last_heard: None,

            authentication_enabled: false,
            path_contral_size: 0,
            dio_interval_doublings: consts::DEFAULT_DIO_INTERVAL_DOUBLINGS as u8,
            dio_interval_min: consts::DEFAULT_DIO_INTERVAL_MIN as u8,
            dio_redundency_constant: consts::DEFAULT_DIO_REDUNDANCY_CONSTANT as u8,
            max_rank_increase: 7 * consts::DEFAULT_MIN_HOP_RANK_INCREASE,
            minimum_hop_rank_increase: consts::DEFAULT_MIN_HOP_RANK_INCREASE,
            objective_code_point: 0, // OCP0
            default_lifetime: 30,
            lifetime_unit: 60,

            grounded: false,
        }
    }

    pub fn has_parent(&self) -> bool {
        self.parent_address.is_some()
    }

    pub fn should_send_dis(&self, now: Instant) -> bool {
        !self.has_parent() && !self.is_root && now >= self.dis_expiration
    }

    pub fn dodag_information_object(&self) -> RplRepr {
        RplRepr::DodagInformationObject {
            rpl_instance_id: self.instance_id,
            version_number: self.version_number.value(),
            rank: self.rank.raw_value(),
            grounded: self.grounded,
            mode_of_operation: self.mode_of_operation.into(),
            dodag_preference: self.preference,
            dtsn: self.dtsn.value(),
            dodag_id: self.dodag_id.unwrap(),
            options: &[],
        }
    }
    pub fn dodag_configuration(&self) -> RplOptionRepr<'_> {
        RplOptionRepr::DodagConfiguration {
            authentication_enabled: self.authentication_enabled,
            path_control_size: self.path_contral_size,
            dio_interval_doublings: self.dio_interval_doublings,
            dio_interval_min: self.dio_interval_min,
            dio_redundancy_constant: self.dio_redundency_constant,
            max_rank_increase: self.max_rank_increase,
            minimum_hop_rank_increase: self.minimum_hop_rank_increase,
            objective_code_point: self.objective_code_point,
            default_lifetime: self.default_lifetime,
            lifetime_unit: self.lifetime_unit,
        }
    }

    pub fn update_dodag_configuration(&mut self, dodag_conf: &RplOptionRepr) {
        if let RplOptionRepr::DodagConfiguration {
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
        } = dodag_conf
        {
            self.authentication_enabled = *authentication_enabled;
            self.path_contral_size = *path_control_size;
            self.dio_interval_doublings = *dio_interval_doublings;
            self.dio_interval_min = *dio_interval_min;
            self.dio_redundency_constant = *dio_redundancy_constant;
            self.max_rank_increase = *max_rank_increase;
            self.minimum_hop_rank_increase = *minimum_hop_rank_increase;
            self.objective_code_point = *objective_code_point;
            self.default_lifetime = *default_lifetime;
            self.lifetime_unit = *lifetime_unit;
        }
    }

    pub fn parent(&self) -> Option<Ipv6Address> {
        self.parent_address
    }

    pub fn is_root(&self) -> bool {
        self.is_root
    }

    pub fn rank(&self) -> rank::Rank {
        self.rank
    }

    pub fn dodag_id(&self) -> Option<Ipv6Address> {
        self.dodag_id
    }

    pub fn instance_id(&self) -> RplInstanceId {
        self.instance_id
    }

    pub fn version_number(&self) -> lollipop::SequenceCounter {
        self.version_number
    }

    pub fn mode_of_operation(&self) -> ModeOfOperation {
        self.mode_of_operation
    }
}
