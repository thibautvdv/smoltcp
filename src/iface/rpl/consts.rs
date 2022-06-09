

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
