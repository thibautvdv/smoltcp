//! Implementation of the RPL packet formats. See [RFC 6550 § 6].
//!
//! [RFC 6550 § 6]: https://datatracker.ietf.org/doc/html/rfc6550#section-6

use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Icmpv6Message, Result};
use crate::wire::icmpv6::Packet;
use crate::wire::ipv6::Address;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum InstanceId {
    Global(u8),
    Local(u8),
}

impl From<u8> for InstanceId {
    fn from(val: u8) -> Self {
        const MASK: u8 = 0b0111_1111;

        if ((val >> 7) & 0xb1) == 0b0 {
            Self::Global(val & MASK)
        } else {
            Self::Local(val & MASK)
        }
    }
}

impl From<InstanceId> for u8 {
    fn from(val: InstanceId) -> Self {
        match val {
            InstanceId::Global(val) => 0b0000_0000 | val,
            InstanceId::Local(val) => 0b1000_0000 | val,
        }
    }
}

impl InstanceId {
    /// Return the real part of the ID.
    pub fn id(&self) -> u8 {
        match self {
            Self::Global(val) => *val,
            Self::Local(val) => *val,
        }
    }

    /// Returns `true` when the DODAG ID is the destination address of the IPv6 packet.
    #[inline]
    pub fn dodag_is_destination(&self) -> bool {
        match self {
            Self::Global(_) => false,
            Self::Local(val) => ((val >> 6) & 0b1) == 0b1,
        }
    }

    /// Returns `true` when the DODAG ID is the source address of the IPv6 packet.
    ///
    /// *NOTE*: this only makes sence when using a local RPL Instance ID and the packet is not a
    /// RPL control message.
    #[inline]
    pub fn dodag_is_source(&self) -> bool {
        !self.dodag_is_destination()
    }
}

mod field {
    use crate::wire::field::*;

    pub const RPL_INSTANCE_ID: usize = 4;

    // DODAG information solicitation fields (DIS)
    pub const DIS_FLAGS: usize = 4;
    pub const DIS_RESERVED: usize = 5;

    // DODAG information object fields (DIO)
    pub const DIO_VERSION_NUMBER: usize = 5;
    pub const DIO_RANK: Field = 6..8;
    pub const DIO_GROUNDED: usize = 8;
    pub const DIO_MOP: usize = 8;
    pub const DIO_PRF: usize = 8;
    pub const DIO_DTSN: usize = 9;
    //pub const DIO_FLAGS: usize = 10;
    //pub const DIO_RESERVED: usize = 11;
    pub const DIO_DODAG_ID: Field = 12..12 + 16;

    // Destination advertisment object (DAO)
    pub const DAO_K: usize = 5;
    pub const DAO_D: usize = 5;
    //pub const DAO_FLAGS: usize = 5;
    //pub const DAO_RESERVED: usize = 6;
    pub const DAO_SEQUENCE: usize = 7;
    pub const DAO_DODAG_ID: Field = 8..8 + 16;

    // Destination advertisment object ack (DAO-ACK)
    pub const DAO_ACK_D: usize = 5;
    //pub const DAO_ACK_RESERVED: usize = 5;
    pub const DAO_ACK_SEQUENCE: usize = 6;
    pub const DAO_ACK_STATUS: usize = 7;
    pub const DAO_ACK_DODAG_ID: Field = 8..8 + 16;

    // Consistench check (CC)
    pub const CC_R: usize = 4;
    //pub const CC_FLAGS: usize = 5;
    pub const CC_NONCE: Field = 6..8;
    pub const CC_DODAG_ID: Field = 8..25;
    pub const CC_DESTINATION_COUNTER: Field = 25..29;
}

enum_with_unknown! {
    /// RPL Control Message subtypes.
    pub enum RplControlMessage(u8) {
        DodagInformationSolicitation = 0x00,
        DodagInformationObject = 0x01,
        DestinationAdvertisementObject = 0x02,
        DestinationAdvertisementObjectAck = 0x03,
        SecureDodagInformationSolicitation = 0x80,
        SecureDodagInformationObject = 0x81,
        SecureDesintationAdvertismentObject = 0x82,
        SecureDestinationAdvertisementObjectAck = 0x83,
        ConsistencyCheck = 0x8a,
    }
}

impl core::fmt::Display for RplControlMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RplControlMessage::DodagInformationSolicitation => {
                write!(f, "DODAG information solicitation (DIS)")
            }
            RplControlMessage::DodagInformationObject => {
                write!(f, "DODAG information object (DIO)")
            }
            RplControlMessage::DestinationAdvertisementObject => {
                write!(f, "destination advertisment object (DAO)")
            }
            RplControlMessage::DestinationAdvertisementObjectAck => write!(
                f,
                "destination advertisment object acknowledgement (DAO-ACK)"
            ),
            RplControlMessage::SecureDodagInformationSolicitation => {
                write!(f, "secure DODAG information solicitation (DIS)")
            }
            RplControlMessage::SecureDodagInformationObject => {
                write!(f, "secure DODAG information object (DIO)")
            }
            RplControlMessage::SecureDesintationAdvertismentObject => {
                write!(f, "secure destination advertisment object (DAO)")
            }
            RplControlMessage::SecureDestinationAdvertisementObjectAck => write!(
                f,
                "secure destination advertisment object acknowledgement (DAO-ACK)"
            ),
            RplControlMessage::ConsistencyCheck => write!(f, "consistency check (CC)"),
            RplControlMessage::Unknown(id) => write!(f, "{}", id),
        }
    }
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the RPL instance ID.
    #[inline]
    pub fn rpl_instance_id(&self) -> InstanceId {
        get!(self.buffer, into: InstanceId, field: field::RPL_INSTANCE_ID)
    }
}

impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
    /// Return a pointer to the options.
    pub fn options(&self) -> &'p [u8] {
        match RplControlMessage::from(self.msg_code()) {
            RplControlMessage::DodagInformationSolicitation => {
                &self.buffer.as_ref()[field::DIS_RESERVED + 1..]
            }
            RplControlMessage::DodagInformationObject => {
                &self.buffer.as_ref()[field::DIO_DODAG_ID.end..]
            }
            RplControlMessage::DestinationAdvertisementObject => {
                if self.dao_dodag_id_present() {
                    &self.buffer.as_ref()[field::DAO_DODAG_ID.end..]
                } else {
                    &self.buffer.as_ref()[field::DAO_SEQUENCE + 1..]
                }
            }
            RplControlMessage::DestinationAdvertisementObjectAck => {
                if self.dao_dodag_id_present() {
                    &self.buffer.as_ref()[field::DAO_ACK_DODAG_ID.end..]
                } else {
                    &self.buffer.as_ref()[field::DAO_ACK_STATUS + 1..]
                }
            }
            RplControlMessage::SecureDodagInformationSolicitation => todo!(),
            RplControlMessage::SecureDodagInformationObject => todo!(),
            RplControlMessage::SecureDesintationAdvertismentObject => todo!(),
            RplControlMessage::SecureDestinationAdvertisementObjectAck => todo!(),
            RplControlMessage::ConsistencyCheck => {
                &self.buffer.as_ref()[field::CC_DESTINATION_COUNTER.end..]
            }
            RplControlMessage::Unknown(_) => todo!(),
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the RPL Instance ID field.
    #[inline]
    pub fn set_rpl_instance_id(&mut self, value: u8) {
        set!(self.buffer, value, field: field::RPL_INSTANCE_ID)
    }
}

impl<'p, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'p mut T> {
    /// Return a pointer to the options.
    pub fn options_mut(&mut self) -> &mut [u8] {
        match RplControlMessage::from(self.msg_code()) {
            RplControlMessage::DodagInformationSolicitation => {
                &mut self.buffer.as_mut()[field::DIS_RESERVED + 1..]
            }
            RplControlMessage::DodagInformationObject => {
                &mut self.buffer.as_mut()[field::DIO_DODAG_ID.end..]
            }
            RplControlMessage::DestinationAdvertisementObject => {
                if self.dao_dodag_id_present() {
                    &mut self.buffer.as_mut()[field::DAO_DODAG_ID.end..]
                } else {
                    &mut self.buffer.as_mut()[field::DAO_SEQUENCE + 1..]
                }
            }
            RplControlMessage::DestinationAdvertisementObjectAck => {
                if self.dao_dodag_id_present() {
                    &mut self.buffer.as_mut()[field::DAO_ACK_DODAG_ID.end..]
                } else {
                    &mut self.buffer.as_mut()[field::DAO_ACK_STATUS + 1..]
                }
            }
            RplControlMessage::SecureDodagInformationSolicitation => todo!(),
            RplControlMessage::SecureDodagInformationObject => todo!(),
            RplControlMessage::SecureDesintationAdvertismentObject => todo!(),
            RplControlMessage::SecureDestinationAdvertisementObjectAck => todo!(),
            RplControlMessage::ConsistencyCheck => {
                &mut self.buffer.as_mut()[field::CC_DESTINATION_COUNTER.end..]
            }
            RplControlMessage::Unknown(_) => todo!(),
        }
    }
}

/// Getters for the DODAG information solicitation (DIS) message.
///
/// ```txt
///  0                   1                   2
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Flags     |   Reserved    |   Option(s)...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the DIS flags field.
    #[inline]
    pub fn dis_flags(&self) -> u8 {
        get!(self.buffer, field: field::DIS_FLAGS)
    }

    /// Return the DIS reserved field.
    #[inline]
    pub fn dis_reserved(&self) -> u8 {
        get!(self.buffer, field: field::DIS_RESERVED)
    }
}

/// Setters for the DODAG information solicitation (DIS) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Clear the DIS flags field.
    pub fn clear_dis_flags(&mut self) {
        self.buffer.as_mut()[field::DIS_FLAGS] = 0;
    }

    /// Clear the DIS rserved field.
    pub fn clear_dis_reserved(&mut self) {
        self.buffer.as_mut()[field::DIS_RESERVED] = 0;
    }
}

enum_with_unknown! {
    pub enum ModeOfOperation(u8) {
        NoDownwardRoutesMaintained = 0x00,
        NonStoringMode = 0x01,
        StoringModeWithoutMulticast = 0x02,
        StoringModeWithMulticast = 0x03,
    }
}

impl Default for ModeOfOperation {
    fn default() -> Self {
        Self::StoringModeWithoutMulticast
    }
}

/// Getters for the DODAG information object (DIO) message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RPLInstanceID |Version Number |             Rank              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |G|0| MOP | Prf |     DTSN      |     Flags     |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID                            +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option(s)...
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Return the Version Number field.
    #[inline]
    pub fn dio_version_number(&self) -> u8 {
        get!(self.buffer, field: field::DIO_VERSION_NUMBER)
    }

    /// Return the Rank field.
    #[inline]
    pub fn dio_rank(&self) -> u16 {
        get!(self.buffer, u16, field: field::DIO_RANK)
    }

    /// Return the value of the Grounded flag.
    #[inline]
    pub fn dio_grounded(&self) -> bool {
        get!(self.buffer, bool, field: field::DIO_GROUNDED, shift: 7, mask: 0b01)
    }

    /// Return the mode of operation field.
    #[inline]
    pub fn dio_mode_of_operation(&self) -> ModeOfOperation {
        get!(self.buffer, into: ModeOfOperation, field: field::DIO_MOP, shift: 3, mask: 0b111)
    }

    /// Return the DODAG preference field.
    #[inline]
    pub fn dio_dodag_preference(&self) -> u8 {
        get!(self.buffer, field: field::DIO_PRF, mask: 0b111)
    }

    /// Return the destination advertisment trigger sequence number.
    #[inline]
    pub fn dio_dest_adv_trigger_seq_number(&self) -> u8 {
        get!(self.buffer, field: field::DIO_DTSN)
    }

    /// Return the DODAG id, which is an IPv6 address.
    #[inline]
    pub fn dio_dodag_id(&self) -> Address {
        get!(
            self.buffer,
            into: Address,
            fun: from_bytes,
            field: field::DIO_DODAG_ID
        )
    }
}

/// Setters for the DODAG information object (DIO) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Version Number field.
    #[inline]
    pub fn set_dio_version_number(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DIO_VERSION_NUMBER)
    }

    /// Set the Rank field.
    #[inline]
    pub fn set_dio_rank(&mut self, value: u16) {
        set!(self.buffer, value, u16, field: field::DIO_RANK)
    }

    /// Set the value of the Grounded flag.
    #[inline]
    pub fn set_dio_grounded(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DIO_GROUNDED, shift: 7, mask: 0b01)
    }

    ///  Set the mode of operation field.
    #[inline]
    pub fn set_dio_mode_of_operation(&mut self, mode: ModeOfOperation) {
        let raw = (self.buffer.as_ref()[field::DIO_MOP] & !(0b111 << 3)) | (u8::from(mode) << 3);
        self.buffer.as_mut()[field::DIO_MOP] = raw;
    }

    /// Set the DODAG preference field.
    #[inline]
    pub fn set_dio_dodag_preference(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DIO_PRF, mask: 0b111)
    }

    /// Set the destination advertisment trigger sequence number.
    #[inline]
    pub fn set_dio_dest_adv_trigger_seq_number(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DIO_DTSN)
    }

    /// Set the DODAG id, which is an IPv6 address.
    #[inline]
    pub fn set_dio_dodag_id(&mut self, address: Address) {
        set!(self.buffer, address: address, field: field::DIO_DODAG_ID)
    }
}

/// Getters for the Destination Advertisment Object (DAO) message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RPLInstanceID |K|D|   Flags   |   Reserved    | DAOSequence   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID*                           +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option(s)...
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Returns the Expect DAO-ACK flag.
    #[inline]
    pub fn dao_ack_request(&self) -> bool {
        get!(self.buffer, bool, field: field::DAO_K, shift: 7, mask: 0b1)
    }

    /// Returns the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn dao_dodag_id_present(&self) -> bool {
        get!(self.buffer, bool, field: field::DAO_D, shift: 6, mask: 0b1)
    }

    /// Returns the DODAG sequence flag.
    #[inline]
    pub fn dao_dodag_sequence(&self) -> u8 {
        get!(self.buffer, field: field::DAO_SEQUENCE)
    }

    /// Returns the DODAG ID, an IPv6 address, when it is present.
    #[inline]
    pub fn dao_dodag_id(&self) -> Option<Address> {
        if self.dao_dodag_id_present() {
            Some(Address::from_bytes(
                &self.buffer.as_ref()[field::DAO_DODAG_ID],
            ))
        } else {
            None
        }
    }
}

/// Setters for the Destination Advertisment Object (DAO) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the Expect DAO-ACK flag.
    #[inline]
    pub fn set_dao_ack_request(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DAO_K, shift: 7, mask: 0b1,)
    }

    /// Set the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn set_dao_dodag_id_present(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DAO_D, shift: 6, mask: 0b1)
    }

    /// Set the DODAG sequence flag.
    #[inline]
    pub fn set_dao_dodag_sequence(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DAO_SEQUENCE)
    }

    /// Set the DODAG ID.
    #[inline]
    pub fn set_dao_dodag_id(&mut self, address: Option<Address>) {
        match address {
            Some(address) => {
                self.buffer.as_mut()[field::DAO_DODAG_ID].copy_from_slice(address.as_bytes());
                self.set_dao_dodag_id_present(true);
            }
            None => {
                self.set_dao_dodag_id_present(false);
            }
        }
    }
}

/// Getters for the Destination Advertisment Object acknowledgement (DAO-ACK) message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RPLInstanceID |D|  Reserved   |  DAOSequence  |    Status     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID*                           +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option(s)...
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Returns the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn dao_ack_dodag_id_present(&self) -> bool {
        get!(self.buffer, bool, field: field::DAO_ACK_D, shift: 6, mask: 0b1)
    }

    /// Return the DODAG sequence number.
    #[inline]
    pub fn dao_ack_sequence(&self) -> u8 {
        get!(self.buffer, field: field::DAO_ACK_SEQUENCE)
    }

    /// Return the DOA status field.
    #[inline]
    pub fn dao_ack_status(&self) -> u8 {
        get!(self.buffer, field: field::DAO_ACK_STATUS)
    }

    /// Returns the DODAG ID, an IPv6 address, when it is present.
    #[inline]
    pub fn dao_ack_dodag_id(&self) -> Option<Address> {
        if self.dao_ack_dodag_id_present() {
            Some(Address::from_bytes(
                &self.buffer.as_ref()[field::DAO_ACK_DODAG_ID],
            ))
        } else {
            None
        }
    }
}

/// Setters for the Destination Advertisment Object acknowledgement (DAO-ACK) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the flag indicating that the DODAG ID is present or not.
    #[inline]
    pub fn set_dao_ack_dodag_id_present(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::DAO_ACK_D, shift: 6, mask: 0b1)
    }

    /// Set the DODAG sequence number.
    #[inline]
    pub fn set_dao_ack_sequence(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DAO_ACK_SEQUENCE)
    }

    /// Set the DOA status field.
    #[inline]
    pub fn set_dao_ack_status(&mut self, value: u8) {
        set!(self.buffer, value, field: field::DAO_ACK_STATUS)
    }

    /// Set the DODAG ID.
    #[inline]
    pub fn set_dao_ack_dodag_id(&mut self, address: Option<Address>) {
        match address {
            Some(address) => {
                self.buffer.as_mut()[field::DAO_ACK_DODAG_ID].copy_from_slice(address.as_bytes());
                self.set_dao_ack_dodag_id_present(true);
            }
            None => {
                self.set_dao_ack_dodag_id_present(false);
            }
        }
    }
}

/// Getters for the Consistency Check (CC) message.
///
/// ```txt
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | RPLInstanceID |R|    Flags    |           CC Nonce            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                            DODAGID                            +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Destination Counter                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option(s)...
/// +-+-+-+-+-+-+-+-+
/// ```
impl<T: AsRef<[u8]>> Packet<T> {
    /// Returns `true` when the message is a response.
    #[inline]
    pub fn cc_is_response(&self) -> bool {
        get!(self.buffer, bool, field: field::CC_R, shift: 7, mask: 0b1)
    }

    /// Return the CC Nonce field.
    #[inline]
    pub fn cc_nonce(&self) -> u16 {
        get!(self.buffer, u16, field: field::CC_NONCE)
    }

    /// Return the DODAG ID, which is an IPv6 address.
    #[inline]
    pub fn cc_dodag_id(&self) -> Address {
        get!(
            self.buffer,
            into: Address,
            fun: from_bytes,
            field: field::CC_DESTINATION_COUNTER
        )
    }

    /// Return the Destination Counter field.
    #[inline]
    pub fn cc_destination_counter(&self) -> u32 {
        get!(self.buffer, u32, field: field::CC_DESTINATION_COUNTER)
    }
}

/// Setters for the Consistency Check (CC) message.
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set `true` when the message is a response.
    #[inline]
    pub fn set_cc_is_response(&mut self, value: bool) {
        set!(self.buffer, value, bool, field: field::CC_R, shift: 7, mask: 0b1)
    }

    /// Set the CC Nonce field.
    #[inline]
    pub fn set_cc_nonce(&mut self, value: u16) {
        set!(self.buffer, value, u16, field: field::CC_NONCE)
    }

    /// Set the DODAG ID, which is an IPv6 address.
    #[inline]
    pub fn set_cc_dodag_id(&mut self, address: Address) {
        set!(
            self.buffer,
            address: address,
            field: field::CC_DESTINATION_COUNTER
        )
    }

    /// Set the Destination Counter field.
    #[inline]
    pub fn set_cc_destination_counter(&mut self, value: u32) {
        set!(
            self.buffer,
            value,
            u32,
            field: field::CC_DESTINATION_COUNTER
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Repr<'p> {
    DodagInformationSolicitation {
        options: &'p [u8],
    },
    DodagInformationObject {
        rpl_instance_id: InstanceId,
        version_number: u8,
        rank: u16,
        grounded: bool,
        mode_of_operation: ModeOfOperation,
        dodag_preference: u8,
        dtsn: u8,
        dodag_id: Address,
        options: &'p [u8],
    },
    DestinationAdvertisementObject {
        rpl_instance_id: InstanceId,
        expect_ack: bool,
        sequence: u8,
        dodag_id: Option<Address>,
        options: &'p [u8],
    },
    DestinationAdvertisementObjectAck {
        rpl_instance_id: InstanceId,
        sequence: u8,
        status: u8,
        dodag_id: Option<Address>,
        options: &'p [u8],
    },
    ConsistencyCheck {
        rpl_instance_id: InstanceId,
        is_response: bool,
        nonce: u16,
        dodag_id: Address,
        destination_counter: u32,
        options: &'p [u8],
    },
}

#[cfg(feature = "std")]
impl core::fmt::Display for Repr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut options: &[u8] = match self {
            Repr::DodagInformationSolicitation { options } => {
                write!(f, "DIS")?;
                options
            }
            Repr::DodagInformationObject {
                rpl_instance_id,
                version_number,
                rank,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                options,
            } => {
                writeln!(f, "DIO IID={rpl_instance_id:?} \
                V={version_number} R={rank} G={grounded} MOP={mode_of_operation:?} DODAGID={dodag_id}")?;
                options
            }
            Repr::DestinationAdvertisementObject {
                rpl_instance_id,
                expect_ack,
                sequence,
                dodag_id,
                options,
            } => {
                todo!();
                options
            }
            Repr::DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
                options,
            } => {
                todo!();
                options
            }
            Repr::ConsistencyCheck {
                rpl_instance_id,
                is_response,
                nonce,
                dodag_id,
                destination_counter,
                options,
            } => {
                todo!();
                options
            }
        };

        while let Ok(opt_packet) = options::Packet::new_checked(options) {
            let opt = options::Repr::parse(&opt_packet).unwrap();
            writeln!(f, "  └─ {opt}")?;
            options = &options[opt.buffer_len()..];
        }

        Ok(())
    }
}

impl<'p> Repr<'p> {
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'p T>) -> Result<Self> {
        let mut options = packet.options();

        match RplControlMessage::from(packet.msg_code()) {
            RplControlMessage::DodagInformationSolicitation => {
                Ok(Repr::DodagInformationSolicitation { options })
            }
            RplControlMessage::DodagInformationObject => Ok(Repr::DodagInformationObject {
                rpl_instance_id: packet.rpl_instance_id(),
                version_number: packet.dio_version_number(),
                rank: packet.dio_rank(),
                grounded: packet.dio_grounded(),
                mode_of_operation: packet.dio_mode_of_operation(),
                dodag_preference: packet.dio_dodag_preference(),
                dtsn: packet.dio_dest_adv_trigger_seq_number(),
                dodag_id: packet.dio_dodag_id(),
                options,
            }),
            RplControlMessage::DestinationAdvertisementObject => {
                Ok(Repr::DestinationAdvertisementObject {
                    rpl_instance_id: packet.rpl_instance_id(),
                    expect_ack: packet.dao_ack_request(),
                    sequence: packet.dao_dodag_sequence(),
                    dodag_id: packet.dao_dodag_id(),
                    options,
                })
            }
            RplControlMessage::DestinationAdvertisementObjectAck => {
                Ok(Repr::DestinationAdvertisementObjectAck {
                    rpl_instance_id: packet.rpl_instance_id(),
                    sequence: packet.dao_ack_sequence(),
                    status: packet.dao_ack_status(),
                    dodag_id: packet.dao_ack_dodag_id(),
                    options,
                })
            }
            RplControlMessage::ConsistencyCheck => Ok(Repr::ConsistencyCheck {
                rpl_instance_id: packet.rpl_instance_id(),
                is_response: packet.cc_is_response(),
                nonce: packet.cc_nonce(),
                dodag_id: packet.cc_dodag_id(),
                destination_counter: packet.cc_destination_counter(),
                options,
            }),
            RplControlMessage::SecureDodagInformationSolicitation
            | RplControlMessage::SecureDodagInformationObject
            | RplControlMessage::SecureDesintationAdvertismentObject
            | RplControlMessage::SecureDestinationAdvertisementObjectAck => Err(Error),
            RplControlMessage::Unknown(_) => Err(Error),
        }
    }

    pub fn buffer_len(&self) -> usize {
        let mut len = 4 + match self {
            Repr::DodagInformationSolicitation { .. } => 2,
            Repr::DodagInformationObject { .. } => 24,
            Repr::DestinationAdvertisementObject { dodag_id, .. } => {
                if dodag_id.is_some() {
                    20
                } else {
                    4
                }
            }
            Repr::DestinationAdvertisementObjectAck { dodag_id, .. } => {
                if dodag_id.is_some() {
                    20
                } else {
                    4
                }
            }
            Repr::ConsistencyCheck { .. } => 24,
        };

        len += match self {
            Repr::DodagInformationSolicitation { options } => options,
            Repr::DodagInformationObject { options, .. } => options,
            Repr::DestinationAdvertisementObject { options, .. } => options,
            Repr::DestinationAdvertisementObjectAck { options, .. } => options,
            Repr::ConsistencyCheck { options, .. } => options,
        }
        .len();

        len
    }

    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, packet: &mut Packet<&mut T>) {
        packet.set_msg_type(crate::wire::icmpv6::Message::RplControl);

        match self {
            Repr::DodagInformationSolicitation { .. } => {
                packet.set_msg_code(RplControlMessage::DodagInformationSolicitation.into());
                packet.clear_dis_flags();
                packet.clear_dis_reserved();
            }
            Repr::DodagInformationObject {
                rpl_instance_id,
                version_number,
                rank,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                ..
            } => {
                packet.set_msg_code(RplControlMessage::DodagInformationObject.into());
                packet.set_rpl_instance_id((*rpl_instance_id).into());
                packet.set_dio_version_number(*version_number);
                packet.set_dio_rank(*rank);
                packet.set_dio_grounded(*grounded);
                packet.set_dio_mode_of_operation(*mode_of_operation);
                packet.set_dio_dodag_preference(*dodag_preference);
                packet.set_dio_dest_adv_trigger_seq_number(*dtsn);
                packet.set_dio_dodag_id(*dodag_id);
            }
            Repr::DestinationAdvertisementObject {
                rpl_instance_id,
                expect_ack,
                sequence,
                dodag_id,
                options,
            } => {
                packet.set_msg_code(RplControlMessage::DestinationAdvertisementObject.into());
                packet.set_rpl_instance_id((*rpl_instance_id).into());
                packet.set_dao_ack_request(*expect_ack);
                packet.set_dao_dodag_sequence(*sequence);
                packet.set_dao_dodag_id(*dodag_id);
            }
            Repr::DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
                options,
            } => {
                packet.set_msg_code(RplControlMessage::DestinationAdvertisementObjectAck.into());
                packet.set_rpl_instance_id((*rpl_instance_id).into());
                packet.set_dao_ack_sequence(*sequence);
                packet.set_dao_ack_status(*status);
                packet.set_dao_ack_dodag_id(*dodag_id);
            }
            Repr::ConsistencyCheck {
                rpl_instance_id,
                is_response,
                nonce,
                dodag_id,
                destination_counter,
                options,
            } => {
                packet.set_msg_code(RplControlMessage::ConsistencyCheck.into());
                packet.set_rpl_instance_id((*rpl_instance_id).into());
                packet.set_cc_is_response(*is_response);
                packet.set_cc_nonce(*nonce);
                packet.set_cc_dodag_id(*dodag_id);
                packet.set_cc_destination_counter(*destination_counter);
            }
        }

        let options = match self {
            Repr::DodagInformationSolicitation { options } => options,
            Repr::DodagInformationObject { options, .. } => options,
            Repr::DestinationAdvertisementObject { options, .. } => options,
            Repr::DestinationAdvertisementObjectAck { options, .. } => options,
            Repr::ConsistencyCheck { options, .. } => options,
        };

        if !options.is_empty() {
            packet.options_mut().copy_from_slice(options);
        }
    }
}

pub mod options {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::{Error, InstanceId, Result};
    use crate::wire::ipv6::Address;

    /// A read/write wrapper around a RPL Control Message Option.
    #[derive(Debug, Clone)]
    pub struct Packet<T: AsRef<[u8]>> {
        buffer: T,
    }

    enum_with_unknown! {
        pub enum OptionType(u8) {
            Pad1 = 0x00,
            PadN = 0x01,
            DagMetricContainer = 0x02,
            RouteInformation = 0x03,
            DodagConfiguration = 0x04,
            RplTarget = 0x05,
            TransitInformation = 0x06,
            SolicitedInformation = 0x07,
            PrefixInformation = 0x08,
            RplTargetDescriptor = 0x09,
        }
    }

    impl From<&Repr<'_>> for OptionType {
        fn from(repr: &Repr) -> Self {
            match repr {
                Repr::Pad1 => Self::Pad1,
                Repr::PadN(_) => Self::PadN,
                Repr::DagMetricContainer => Self::DagMetricContainer,
                Repr::RouteInformation { .. } => Self::RouteInformation,
                Repr::DodagConfiguration { .. } => Self::DodagConfiguration,
                Repr::RplTarget { .. } => Self::RplTarget,
                Repr::TransitInformation { .. } => Self::TransitInformation,
                Repr::SolicitedInformation { .. } => Self::SolicitedInformation,
                Repr::PrefixInformation { .. } => Self::PrefixInformation,
                Repr::RplTargetDescriptor { .. } => Self::RplTargetDescriptor,
            }
        }
    }

    mod field {
        use crate::wire::field::*;

        // Generic fields.
        pub const TYPE: usize = 0;
        pub const LENGTH: usize = 1;

        pub const PADN: Rest = 2..;

        // Route Information fields.
        pub const ROUTE_INFO_PREFIX_LENGTH: usize = 2;
        pub const ROUTE_INFO_RESERVED: usize = 3;
        pub const ROUTE_INFO_PREFERENCE: usize = 3;
        pub const ROUTE_INFO_LIFETIME: Field = 4..9;

        // DODAG Configuration fields.
        pub const DODAG_CONF_FLAGS: usize = 2;
        pub const DODAG_CONF_AUTHENTICATION_ENABLED: usize = 2;
        pub const DODAG_CONF_PATH_CONTROL_SIZE: usize = 2;
        pub const DODAG_CONF_DIO_INTERVAL_DOUBLINGS: usize = 3;
        pub const DODAG_CONF_DIO_INTERVAL_MINIMUM: usize = 4;
        pub const DODAG_CONF_DIO_REDUNDANCY_CONSTANT: usize = 5;
        pub const DODAG_CONF_DIO_MAX_RANK_INCREASE: Field = 6..8;
        pub const DODAG_CONF_MIN_HOP_RANK_INCREASE: Field = 8..10;
        pub const DODAG_CONF_OBJECTIVE_CODE_POINT: Field = 10..12;
        pub const DODAG_CONF_DEFAULT_LIFETIME: usize = 13;
        pub const DODAG_CONF_LIFETIME_UNIT: Field = 14..16;

        // RPL Target fields.
        pub const RPL_TARGET_FLAGS: usize = 2;
        pub const RPL_TARGET_PREFIX_LENGTH: usize = 3;

        // Transit Information fields.
        pub const TRANSIT_INFO_FLAGS: usize = 2;
        pub const TRANSIT_INFO_EXTERNAL: usize = 2;
        pub const TRANSIT_INFO_PATH_CONTROL: usize = 3;
        pub const TRANSIT_INFO_PATH_SEQUENCE: usize = 4;
        pub const TRANSIT_INFO_PATH_LIFETIME: usize = 5;
        pub const TRANSIT_INFO_PARENT_ADDRESS: Field = 6..6 + 16;

        // Solicited Information fields.
        pub const SOLICITED_INFO_RPL_INSTANCE_ID: usize = 2;
        pub const SOLICITED_INFO_FLAGS: usize = 3;
        pub const SOLICITED_INFO_VERSION_PREDICATE: usize = 3;
        pub const SOLICITED_INFO_INSTANCE_ID_PREDICATE: usize = 3;
        pub const SOLICITED_INFO_DODAG_ID_PREDICATE: usize = 3;
        pub const SOLICITED_INFO_DODAG_ID: Field = 4..20;
        pub const SOLICITED_INFO_VERSION_NUMBER: usize = 20;

        // Prefix Information fields.
        pub const PREFIX_INFO_PREFIX_LENGTH: usize = 2;
        pub const PREFIX_INFO_RESERVED1: usize = 3;
        pub const PREFIX_INFO_ON_LINK: usize = 3;
        pub const PREFIX_INFO_AUTONOMOUS_CONF: usize = 3;
        pub const PREFIX_INFO_ROUTER_ADDRESS_FLAG: usize = 3;
        pub const PREFIX_INFO_VALID_LIFETIME: Field = 4..8;
        pub const PREFIX_INFO_PREFERRED_LIFETIME: Field = 8..12;
        pub const PREFIX_INFO_RESERVED2: Field = 12..16;
        pub const PREFIX_INFO_PREFIX: Field = 16..16 + 16;

        // RPL Target Descriptor fields.
        pub const TARGET_DESCRIPTOR: Field = 2..6;
    }

    /// Getters for the RPL Control Message Options.
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Imbue a raw octet buffer with RPL Control Message Option structure.
        #[inline]
        pub fn new_unchecked(buffer: T) -> Self {
            Packet { buffer }
        }

        #[inline]
        pub fn new_checked(buffer: T) -> Result<Self> {
            if buffer.as_ref().is_empty() {
                return Err(Error);
            }

            Ok(Packet { buffer })
        }

        /// Return the type field.
        #[inline]
        pub fn option_type(&self) -> OptionType {
            OptionType::from(self.buffer.as_ref()[field::TYPE])
        }

        /// Return the length field.
        #[inline]
        pub fn option_length(&self) -> u8 {
            get!(self.buffer, field: field::LENGTH)
        }
    }

    impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
        /// Return a pointer to the next option.
        #[inline]
        pub fn next_option(&self) -> Option<&[u8]> {
            if !self.buffer.as_ref().is_empty() {
                match self.option_type() {
                    OptionType::Pad1 => Some(&self.buffer.as_ref()[1..]),
                    OptionType::Unknown(_) => unreachable!(),
                    _ => {
                        let len = self.option_length();
                        Some(&self.buffer.as_ref()[2 + len as usize..])
                    }
                }
            } else {
                None
            }
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Set the Option Type field.
        #[inline]
        pub fn set_option_type(&mut self, option_type: OptionType) {
            self.buffer.as_mut()[field::TYPE] = option_type.into();
        }

        /// Set the Option Length field.
        #[inline]
        pub fn set_option_length(&mut self, length: u8) {
            self.buffer.as_mut()[field::LENGTH] = length;
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        #[inline]
        pub fn clear_padn(&mut self, size: u8) {
            for b in &mut self.buffer.as_mut()[field::PADN][..size as usize] {
                *b = 0;
            }
        }
    }

    /// Getters for the DAG Metric Container Option Message.

    /// Getters for the Route Information Option Message.
    ///
    /// ```txt
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Type = 0x03 | Option Length | Prefix Length |Resvd|Prf|Resvd|
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Route Lifetime                         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// .                   Prefix (Variable Length)                    .
    /// .                                                               .
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Return the Prefix Length field.
        #[inline]
        pub fn prefix_length(&self) -> u8 {
            get!(self.buffer, field: field::ROUTE_INFO_PREFIX_LENGTH)
        }

        /// Return the Route Preference field.
        #[inline]
        pub fn route_preference(&self) -> u8 {
            (self.buffer.as_ref()[field::ROUTE_INFO_PREFERENCE] & 0b0001_1000) >> 3
        }

        /// Return the Route Lifetime field.
        #[inline]
        pub fn route_lifetime(&self) -> u32 {
            get!(self.buffer, u32, field: field::ROUTE_INFO_LIFETIME)
        }
    }

    impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
        /// Return the Prefix field.
        #[inline]
        pub fn prefix(&self) -> &'p [u8] {
            let option_len = self.option_length();
            &self.buffer.as_ref()[field::ROUTE_INFO_LIFETIME.end..]
                [..option_len as usize - field::ROUTE_INFO_LIFETIME.end]
        }
    }

    /// Setters for the Route Information Option Message.
    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Set the Prefix Length field.
        #[inline]
        pub fn set_route_info_prefix_length(&mut self, value: u8) {
            set!(self.buffer, value, field: field::ROUTE_INFO_PREFIX_LENGTH)
        }

        /// Set the Route Preference field.
        #[inline]
        pub fn set_route_info_route_preference(&mut self, value: u8) {
            todo!();
            let raw = (self.buffer.as_mut()[field::ROUTE_INFO_PREFERENCE] & 0b111) | value as u8;
            self.buffer.as_mut()[field::ROUTE_INFO_PREFERENCE] = raw;
        }

        /// Set the Route Lifetime field.
        #[inline]
        pub fn set_route_info_route_lifetime(&mut self, value: u32) {
            set!(self.buffer, value, u32, field: field::ROUTE_INFO_LIFETIME)
        }

        /// Set the prefix field.
        #[inline]
        pub fn set_route_info_prefix(&mut self, prefix: &[u8]) {
            todo!();
        }

        /// Clear the reserved field.
        #[inline]
        pub fn clear_route_info_reserved(&mut self) {
            self.buffer.as_mut()[field::ROUTE_INFO_RESERVED] = 0;
        }
    }

    /// Getters for the DODAG Configuration Option Message.
    ///
    /// ```txt
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Type = 0x04 |Opt Length = 14| Flags |A| PCS | DIOIntDoubl.  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  DIOIntMin.   |   DIORedun.   |        MaxRankIncrease        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |      MinHopRankIncrease       |              OCP              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Reserved    | Def. Lifetime |      Lifetime Unit            |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Return the Authentication Enabled field.
        #[inline]
        pub fn authentication_enabled(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::DODAG_CONF_AUTHENTICATION_ENABLED,
                shift: 3,
                mask: 0b1
            )
        }

        /// Return the Path Control Size field.
        #[inline]
        pub fn path_control_size(&self) -> u8 {
            get!(self.buffer, field: field::DODAG_CONF_PATH_CONTROL_SIZE, mask: 0b111)
        }

        /// Return the DIO Interval Doublings field.
        #[inline]
        pub fn dio_interval_doublings(&self) -> u8 {
            get!(self.buffer, field: field::DODAG_CONF_DIO_INTERVAL_DOUBLINGS)
        }

        /// Return the DIO Interval Minimum field.
        #[inline]
        pub fn dio_interval_minimum(&self) -> u8 {
            get!(self.buffer, field: field::DODAG_CONF_DIO_INTERVAL_MINIMUM)
        }

        /// Return the DIO Redundancy Constant field.
        #[inline]
        pub fn dio_redundancy_constant(&self) -> u8 {
            get!(
                self.buffer,
                field: field::DODAG_CONF_DIO_REDUNDANCY_CONSTANT
            )
        }

        /// Return the Max Rank Increase field.
        #[inline]
        pub fn max_rank_increase(&self) -> u16 {
            get!(
                self.buffer,
                u16,
                field: field::DODAG_CONF_DIO_MAX_RANK_INCREASE
            )
        }

        /// Return the Minimum Hop Rank Increase field.
        #[inline]
        pub fn minimum_hop_rank_increase(&self) -> u16 {
            get!(
                self.buffer,
                u16,
                field: field::DODAG_CONF_MIN_HOP_RANK_INCREASE
            )
        }

        /// Return the Objective Code Point field.
        #[inline]
        pub fn objective_code_point(&self) -> u16 {
            get!(
                self.buffer,
                u16,
                field: field::DODAG_CONF_OBJECTIVE_CODE_POINT
            )
        }

        /// Return the Default Lifetime field.
        #[inline]
        pub fn default_lifetime(&self) -> u8 {
            get!(self.buffer, field: field::DODAG_CONF_DEFAULT_LIFETIME)
        }

        /// Return the Lifetime Unit field.
        #[inline]
        pub fn lifetime_unit(&self) -> u16 {
            get!(self.buffer, u16, field: field::DODAG_CONF_LIFETIME_UNIT)
        }
    }

    /// Getters for the DODAG Configuration Option Message.
    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Clear the Flags field.
        #[inline]
        pub fn clear_dodag_conf_flags(&mut self) {
            self.buffer.as_mut()[field::DODAG_CONF_FLAGS] = 0;
        }

        /// Set the Authentication Enabled field.
        #[inline]
        pub fn set_dodag_conf_authentication_enabled(&mut self, value: bool) {
            set!(
                self.buffer,
                value,
                bool,
                field: field::DODAG_CONF_AUTHENTICATION_ENABLED,
                shift: 3,
                mask: 0b1
            )
        }

        /// Set the Path Control Size field.
        #[inline]
        pub fn set_dodag_conf_path_control_size(&mut self, value: u8) {
            set!(
                self.buffer,
                value,
                field: field::DODAG_CONF_PATH_CONTROL_SIZE,
                mask: 0b111
            )
        }

        /// Set the DIO Interval Doublings field.
        #[inline]
        pub fn set_dodag_conf_dio_interval_doublings(&mut self, value: u8) {
            set!(
                self.buffer,
                value,
                field: field::DODAG_CONF_DIO_INTERVAL_DOUBLINGS
            )
        }

        /// Set the DIO Interval Minimum field.
        #[inline]
        pub fn set_dodag_conf_dio_interval_minimum(&mut self, value: u8) {
            set!(
                self.buffer,
                value,
                field: field::DODAG_CONF_DIO_INTERVAL_MINIMUM
            )
        }

        /// Set the DIO Redundancy Constant field.
        #[inline]
        pub fn set_dodag_conf_dio_redundancy_constant(&mut self, value: u8) {
            set!(
                self.buffer,
                value,
                field: field::DODAG_CONF_DIO_REDUNDANCY_CONSTANT
            )
        }

        /// Set the Max Rank Increase field.
        #[inline]
        pub fn set_dodag_conf_max_rank_increase(&mut self, value: u16) {
            set!(
                self.buffer,
                value,
                u16,
                field: field::DODAG_CONF_DIO_MAX_RANK_INCREASE
            )
        }

        /// Set the Minimum Hop Rank Increase field.
        #[inline]
        pub fn set_dodag_conf_minimum_hop_rank_increase(&mut self, value: u16) {
            set!(
                self.buffer,
                value,
                u16,
                field: field::DODAG_CONF_MIN_HOP_RANK_INCREASE
            )
        }

        /// Set the Objective Code Point field.
        #[inline]
        pub fn set_dodag_conf_objective_code_point(&mut self, value: u16) {
            set!(
                self.buffer,
                value,
                u16,
                field: field::DODAG_CONF_OBJECTIVE_CODE_POINT
            )
        }

        /// Set the Default Lifetime field.
        #[inline]
        pub fn set_dodag_conf_default_lifetime(&mut self, value: u8) {
            set!(
                self.buffer,
                value,
                field: field::DODAG_CONF_DEFAULT_LIFETIME
            )
        }

        /// Set the Lifetime Unit field.
        #[inline]
        pub fn set_dodag_conf_lifetime_unit(&mut self, value: u16) {
            set!(
                self.buffer,
                value,
                u16,
                field: field::DODAG_CONF_LIFETIME_UNIT
            )
        }
    }

    /// Getters for the RPL Target Option Message.
    ///
    /// ```txt
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Type = 0x05 | Option Length |     Flags     | Prefix Length |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                Target Prefix (Variable Length)                |
    /// .                                                               .
    /// .                                                               .
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Return the Target Prefix Length field.
        pub fn target_prefix_length(&self) -> u8 {
            #[inline]
            get!(self.buffer, field: field::RPL_TARGET_PREFIX_LENGTH)
        }
    }

    impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
        /// Return the Target Prefix field.
        #[inline]
        pub fn target_prefix(&self) -> &'p [u8] {
            let option_len = self.option_length();
            &self.buffer.as_ref()[field::RPL_TARGET_PREFIX_LENGTH + 1..]
                [..option_len as usize - field::RPL_TARGET_PREFIX_LENGTH + 1]
        }
    }

    /// Setters for the RPL Target Option Message.
    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Clear the Flags field.
        #[inline]
        pub fn clear_rpl_target_flags(&mut self) {
            self.buffer.as_mut()[field::RPL_TARGET_FLAGS] = 0;
        }

        /// Set the Target Prefix Length field.
        #[inline]
        pub fn set_rpl_target_prefix_length(&mut self, value: u8) {
            set!(self.buffer, value, field: field::RPL_TARGET_PREFIX_LENGTH)
        }

        /// Set the Target Prefix field.
        #[inline]
        pub fn set_rpl_target_prefix(&mut self, prefix: &[u8]) {
            todo!();
        }
    }

    /// Getters for the Transit Information Option Message.
    ///
    /// ```txt
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Type = 0x06 | Option Length |E|    Flags    | Path Control  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Path Sequence | Path Lifetime |                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                        Parent Address*                        +
    /// |                                                               |
    /// +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Return the External flag.
        #[inline]
        pub fn is_external(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::TRANSIT_INFO_EXTERNAL,
                shift: 7,
                mask: 0b1,
            )
        }

        /// Return the Path Control field.
        #[inline]
        pub fn path_control(&self) -> u8 {
            get!(self.buffer, field: field::TRANSIT_INFO_PATH_CONTROL)
        }

        /// Return the Path Sequence field.
        #[inline]
        pub fn path_sequence(&self) -> u8 {
            get!(self.buffer, field: field::TRANSIT_INFO_PATH_SEQUENCE)
        }

        /// Return the Path Lifetime field.
        #[inline]
        pub fn path_lifetime(&self) -> u8 {
            get!(self.buffer, field: field::TRANSIT_INFO_PATH_LIFETIME)
        }

        /// Return the Parent Address field.
        #[inline]
        pub fn parent_address(&self) -> Option<Address> {
            if self.option_length() > 5 {
                Some(Address::from_bytes(
                    &self.buffer.as_ref()[field::TRANSIT_INFO_PARENT_ADDRESS],
                ))
            } else {
                None
            }
        }
    }

    /// Setters for the Transit Information Option Message.
    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Clear the Flags field.
        #[inline]
        pub fn clear_transit_info_flags(&mut self) {
            self.buffer.as_mut()[field::TRANSIT_INFO_FLAGS] = 0;
        }

        /// Set the External flag.
        #[inline]
        pub fn set_transit_info_is_external(&mut self, value: bool) {
            set!(
                self.buffer,
                value,
                bool,
                field: field::TRANSIT_INFO_EXTERNAL,
                shift: 7,
                mask: 0b1
            )
        }

        /// Set the Path Control field.
        #[inline]
        pub fn set_transit_info_path_control(&mut self, value: u8) {
            set!(self.buffer, value, field: field::TRANSIT_INFO_PATH_CONTROL)
        }

        /// Set the Path Sequence field.
        #[inline]
        pub fn set_transit_info_path_sequence(&mut self, value: u8) {
            set!(self.buffer, value, field: field::TRANSIT_INFO_PATH_SEQUENCE)
        }

        /// Set the Path Lifetime field.
        #[inline]
        pub fn set_transit_info_path_lifetime(&mut self, value: u8) {
            set!(self.buffer, value, field: field::TRANSIT_INFO_PATH_LIFETIME)
        }

        /// Set the Parent Address field.
        #[inline]
        pub fn set_transit_info_parent_address(&mut self, address: Address) {
            self.buffer.as_mut()[field::TRANSIT_INFO_PARENT_ADDRESS]
                .copy_from_slice(address.as_bytes());
        }
    }

    /// Getters for the Solicited Information Option Message.
    ///
    /// ```txt
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Type = 0x07 |Opt Length = 19| RPLInstanceID |V|I|D|  Flags  |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                            DODAGID                            +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Version Number |
    /// +-+-+-+-+-+-+-+-+
    /// ```
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Return the RPL Instance ID field.
        #[inline]
        pub fn rpl_instance_id(&self) -> u8 {
            get!(self.buffer, field: field::SOLICITED_INFO_RPL_INSTANCE_ID)
        }

        /// Return the Version Predicate flag.
        #[inline]
        pub fn version_predicate(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::SOLICITED_INFO_VERSION_PREDICATE,
                shift: 7,
                mask: 0b1,
            )
        }

        /// Return the Instance ID Predicate flag.
        #[inline]
        pub fn instance_id_predicate(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::SOLICITED_INFO_INSTANCE_ID_PREDICATE,
                shift: 6,
                mask: 0b1,
            )
        }

        /// Return the DODAG Predicate ID flag.
        #[inline]
        pub fn dodag_id_predicate(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::SOLICITED_INFO_DODAG_ID_PREDICATE,
                shift: 5,
                mask: 0b1,
            )
        }

        /// Return the DODAG ID field.
        #[inline]
        pub fn dodag_id(&self) -> Address {
            get!(
                self.buffer,
                into: Address,
                fun: from_bytes,
                field: field::SOLICITED_INFO_DODAG_ID
            )
        }

        /// Return the Version Number field.
        #[inline]
        pub fn version_number(&self) -> u8 {
            get!(self.buffer, field: field::SOLICITED_INFO_VERSION_NUMBER)
        }
    }

    /// Setters for the Solicited Information Option Message.
    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Clear the Flags field.
        #[inline]
        pub fn clear_solicited_info_flags(&mut self) {
            self.buffer.as_mut()[field::SOLICITED_INFO_FLAGS] = 0;
        }

        /// Set the RPL Instance ID field.
        #[inline]
        pub fn set_solicited_info_rpl_instance_id(&mut self, value: u8) {
            set!(
                self.buffer,
                value,
                field: field::SOLICITED_INFO_RPL_INSTANCE_ID
            )
        }

        /// Set the Version Predicate flag.
        #[inline]
        pub fn set_solicited_info_version_predicate(&mut self, value: bool) {
            set!(
                self.buffer,
                value,
                bool,
                field: field::SOLICITED_INFO_VERSION_PREDICATE,
                shift: 7,
                mask: 0b1
            )
        }

        /// Set the Instance ID Predicate flag.
        #[inline]
        pub fn set_solicited_info_instance_id_predicate(&mut self, value: bool) {
            set!(
                self.buffer,
                value,
                bool,
                field: field::SOLICITED_INFO_INSTANCE_ID_PREDICATE,
                shift: 6,
                mask: 0b1
            )
        }

        /// Set the DODAG Predicate ID flag.
        #[inline]
        pub fn set_solicited_info_dodag_id_predicate(&mut self, value: bool) {
            set!(
                self.buffer,
                value,
                bool,
                field: field::SOLICITED_INFO_DODAG_ID_PREDICATE,
                shift: 5,
                mask: 0b1
            )
        }

        /// Set the DODAG ID field.
        #[inline]
        pub fn set_solicited_info_dodag_id(&mut self, address: Address) {
            set!(
                self.buffer,
                address: address,
                field: field::SOLICITED_INFO_DODAG_ID
            )
        }

        /// Set the Version Number field.
        #[inline]
        pub fn set_solicited_info_version_number(&mut self, value: u8) {
            set!(
                self.buffer,
                value,
                field: field::SOLICITED_INFO_VERSION_NUMBER
            )
        }
    }

    /// Getters for the Prefix Information Option Message.
    ///
    /// ```txt
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Type = 0x08 |Opt Length = 30| Prefix Length |L|A|R|Reserved1|
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                         Valid Lifetime                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                       Preferred Lifetime                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                           Reserved2                           |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                            Prefix                             +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Return the Prefix Length field.
        #[inline]
        pub fn prefix_info_prefix_length(&self) -> u8 {
            get!(self.buffer, field: field::PREFIX_INFO_PREFIX_LENGTH)
        }

        /// Return the On-Link flag.
        #[inline]
        pub fn on_link(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::PREFIX_INFO_ON_LINK,
                shift: 7,
                mask: 0b1,
            )
        }

        /// Return the Autonomous Address-Configuration flag.
        #[inline]
        pub fn autonomous_address_configuration(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::PREFIX_INFO_AUTONOMOUS_CONF,
                shift: 6,
                mask: 0b1,
            )
        }

        /// Return the Router Address flag.
        #[inline]
        pub fn router_address(&self) -> bool {
            get!(
                self.buffer,
                bool,
                field: field::PREFIX_INFO_ROUTER_ADDRESS_FLAG,
                shift: 5,
                mask: 0b1,
            )
        }

        /// Return the Valid Lifetime field.
        #[inline]
        pub fn valid_lifetime(&self) -> u32 {
            get!(self.buffer, u32, field: field::PREFIX_INFO_VALID_LIFETIME)
        }

        /// Return the Preferred Lifetime field.
        #[inline]
        pub fn preferred_lifetime(&self) -> u32 {
            get!(
                self.buffer,
                u32,
                field: field::PREFIX_INFO_PREFERRED_LIFETIME
            )
        }
    }

    impl<'p, T: AsRef<[u8]> + ?Sized> Packet<&'p T> {
        /// Return the Prefix field.
        #[inline]
        pub fn destination_prefix(&self) -> &'p [u8] {
            &self.buffer.as_ref()[field::PREFIX_INFO_PREFIX]
        }
    }

    /// Setters for the Prefix Information Option Message.
    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Clear the reserved fields.
        #[inline]
        pub fn clear_prefix_info_reserved(&mut self) {
            self.buffer.as_mut()[field::PREFIX_INFO_RESERVED1] = 0;
            self.buffer.as_mut()[field::PREFIX_INFO_RESERVED2].copy_from_slice(&[0; 4]);
        }

        /// Set the Prefix Length field.
        #[inline]
        pub fn set_prefix_info_prefix_length(&mut self, value: u8) {
            set!(self.buffer, value, field: field::PREFIX_INFO_PREFIX_LENGTH)
        }

        /// Set the On-Link flag.
        #[inline]
        pub fn set_prefix_info_on_link(&mut self, value: bool) {
            set!(self.buffer, value, bool, field: field::PREFIX_INFO_ON_LINK, shift: 7, mask: 0b1)
        }

        /// Set the Autonomous Address-Configuration flag.
        #[inline]
        pub fn set_prefix_info_autonomous_address_configuration(&mut self, value: bool) {
            set!(
                self.buffer,
                value,
                bool,
                field: field::PREFIX_INFO_AUTONOMOUS_CONF,
                shift: 6,
                mask: 0b1
            )
        }

        /// Set the Router Address flag.
        #[inline]
        pub fn set_prefix_info_router_address(&mut self, value: bool) {
            set!(
                self.buffer,
                value,
                bool,
                field: field::PREFIX_INFO_ROUTER_ADDRESS_FLAG,
                shift: 5,
                mask: 0b1
            )
        }

        /// Set the Valid Lifetime field.
        #[inline]
        pub fn set_prefix_info_valid_lifetime(&mut self, value: u32) {
            set!(
                self.buffer,
                value,
                u32,
                field: field::PREFIX_INFO_VALID_LIFETIME
            )
        }

        /// Set the Preferred Lifetime field.
        #[inline]
        pub fn set_prefix_info_preferred_lifetime(&mut self, value: u32) {
            set!(
                self.buffer,
                value,
                u32,
                field: field::PREFIX_INFO_PREFERRED_LIFETIME
            )
        }

        /// Set the Prefix field.
        #[inline]
        pub fn set_prefix_info_destination_prefix(&mut self, prefix: &[u8]) {
            self.buffer.as_mut()[field::PREFIX_INFO_PREFIX].copy_from_slice(prefix);
        }
    }

    /// Getters for the RPL Target Descriptor Option Message.
    ///
    /// ```txt
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Type = 0x09 |Opt Length = 4 |           Descriptor
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///        Descriptor (cont.)       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    impl<T: AsRef<[u8]>> Packet<T> {
        /// Return the Descriptor field.
        #[inline]
        pub fn descriptor(&self) -> u32 {
            get!(self.buffer, u32, field: field::TARGET_DESCRIPTOR)
        }
    }

    /// Setters for the RPL Target Descriptor Option Message.
    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        /// Set the Descriptor field.
        #[inline]
        pub fn set_rpl_target_descriptor_descriptor(&mut self, value: u32) {
            set!(self.buffer, value, u32, field: field::TARGET_DESCRIPTOR)
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum Repr<'p> {
        Pad1,
        PadN(u8),
        DagMetricContainer,
        RouteInformation {
            prefix_length: u8,
            preference: u8,
            lifetime: u32,
            prefix: &'p [u8],
        },
        DodagConfiguration {
            authentication_enabled: bool,
            path_control_size: u8,
            dio_interval_doublings: u8,
            dio_interval_min: u8,
            dio_redundancy_constant: u8,
            max_rank_increase: u16,
            minimum_hop_rank_increase: u16,
            objective_code_point: u16,
            default_lifetime: u8,
            lifetime_unit: u16,
        },
        RplTarget {
            prefix_length: u8,
            prefix: &'p [u8],
        },
        TransitInformation {
            external: bool,
            path_control: u8,
            path_sequence: u8,
            path_lifetime: u8,
            parent_address: Option<Address>,
        },
        SolicitedInformation {
            rpl_instance_id: InstanceId,
            version_predicate: bool,
            instance_id_predicate: bool,
            dodag_id_predicate: bool,
            dodag_id: Address,
            version_number: u8,
        },
        PrefixInformation {
            prefix_length: u8,
            on_link: bool,
            autonomous_address_configuration: bool,
            router_address: bool,
            valid_lifetime: u32,
            preferred_lifetime: u32,
            destination_prefix: &'p [u8],
        },
        RplTargetDescriptor {
            descriptor: u32,
        },
    }

    impl core::fmt::Display for Repr<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Repr::Pad1 | Repr::PadN(_) => Ok(()),
                Repr::DagMetricContainer => todo!(),
                Repr::RouteInformation {
                    prefix_length,
                    preference,
                    lifetime,
                    prefix,
                } => todo!(),
                Repr::DodagConfiguration {
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
                    write!(
                        f,
                        "DODAG CONF IntD={dio_interval_doublings} IntMin={dio_interval_min} \
                        RedCst={dio_redundancy_constant} MaxRankIncr={max_rank_increase} \
                        MinHopRankIncr={minimum_hop_rank_increase} OCP={objective_code_point} \
                        DefaultLifetime={default_lifetime} LifeUnit={lifetime_unit}"
                    )
                }
                Repr::RplTarget {
                    prefix_length,
                    prefix,
                } => todo!(),
                Repr::TransitInformation {
                    external,
                    path_control,
                    path_sequence,
                    path_lifetime,
                    parent_address,
                } => todo!(),
                Repr::SolicitedInformation {
                    rpl_instance_id,
                    version_predicate,
                    instance_id_predicate,
                    dodag_id_predicate,
                    dodag_id,
                    version_number,
                } => todo!(),
                Repr::PrefixInformation {
                    prefix_length,
                    on_link,
                    autonomous_address_configuration,
                    router_address,
                    valid_lifetime,
                    preferred_lifetime,
                    destination_prefix,
                } => todo!(),
                Repr::RplTargetDescriptor { descriptor } => todo!(),
            }
        }
    }

    impl<'p> Repr<'p> {
        pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&'p T>) -> Result<Self> {
            match packet.option_type() {
                OptionType::Pad1 => Ok(Repr::Pad1),
                OptionType::PadN => todo!(),
                OptionType::DagMetricContainer => todo!(),
                OptionType::RouteInformation => Ok(Repr::RouteInformation {
                    prefix_length: packet.prefix_length(),
                    preference: packet.route_preference(),
                    lifetime: packet.route_lifetime(),
                    prefix: packet.prefix(),
                }),
                OptionType::DodagConfiguration => Ok(Repr::DodagConfiguration {
                    authentication_enabled: packet.authentication_enabled(),
                    path_control_size: packet.path_control_size(),
                    dio_interval_doublings: packet.dio_interval_doublings(),
                    dio_interval_min: packet.dio_interval_minimum(),
                    dio_redundancy_constant: packet.dio_redundancy_constant(),
                    max_rank_increase: packet.max_rank_increase(),
                    minimum_hop_rank_increase: packet.minimum_hop_rank_increase(),
                    objective_code_point: packet.objective_code_point(),
                    default_lifetime: packet.default_lifetime(),
                    lifetime_unit: packet.lifetime_unit(),
                }),
                OptionType::RplTarget => Ok(Repr::RplTarget {
                    prefix_length: packet.target_prefix_length(),
                    prefix: packet.target_prefix(),
                }),
                OptionType::TransitInformation => Ok(Repr::TransitInformation {
                    external: packet.is_external(),
                    path_control: packet.path_control(),
                    path_sequence: packet.path_sequence(),
                    path_lifetime: packet.path_lifetime(),
                    parent_address: packet.parent_address(),
                }),
                OptionType::SolicitedInformation => Ok(Repr::SolicitedInformation {
                    rpl_instance_id: InstanceId::from(packet.rpl_instance_id()),
                    version_predicate: packet.version_predicate(),
                    instance_id_predicate: packet.instance_id_predicate(),
                    dodag_id_predicate: packet.dodag_id_predicate(),
                    dodag_id: packet.dodag_id(),
                    version_number: packet.version_number(),
                }),
                OptionType::PrefixInformation => Ok(Repr::PrefixInformation {
                    prefix_length: packet.prefix_info_prefix_length(),
                    on_link: packet.on_link(),
                    autonomous_address_configuration: packet.autonomous_address_configuration(),
                    router_address: packet.router_address(),
                    valid_lifetime: packet.valid_lifetime(),
                    preferred_lifetime: packet.preferred_lifetime(),
                    destination_prefix: packet.destination_prefix(),
                }),
                OptionType::RplTargetDescriptor => Ok(Repr::RplTargetDescriptor {
                    descriptor: packet.descriptor(),
                }),
                OptionType::Unknown(_) => Err(Error),
            }
        }

        pub fn buffer_len(&self) -> usize {
            match self {
                Repr::Pad1 => 1,
                Repr::PadN(size) => 2 + *size as usize,
                Repr::DagMetricContainer => todo!(),
                Repr::RouteInformation { prefix, .. } => 2 + 6 + prefix.len(),
                Repr::DodagConfiguration { .. } => 2 + 14,
                Repr::RplTarget { prefix, .. } => 2 + 2 + prefix.len(),
                Repr::TransitInformation { parent_address, .. } => {
                    2 + 4 + if parent_address.is_some() { 16 } else { 0 }
                }
                Repr::SolicitedInformation { .. } => 2 + 2 + 16 + 1,
                Repr::PrefixInformation { .. } => 32,
                Repr::RplTargetDescriptor { .. } => 2 + 4,
            }
        }

        pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, packet: &mut Packet<&'p mut T>) {
            let mut option_length = self.buffer_len() as u8;

            packet.set_option_type(self.into());

            if !matches!(self, Repr::Pad1) {
                option_length -= 2;
                packet.set_option_length(option_length);
            }

            match self {
                Repr::Pad1 => {}
                Repr::PadN(size) => {
                    packet.clear_padn(*size);
                }
                Repr::DagMetricContainer => {
                    unimplemented!();
                }
                Repr::RouteInformation {
                    prefix_length,
                    preference,
                    lifetime,
                    prefix,
                } => {
                    packet.clear_route_info_reserved();
                    packet.set_route_info_prefix_length(*prefix_length);
                    packet.set_route_info_route_preference(*preference);
                    packet.set_route_info_route_lifetime(*lifetime);
                    packet.set_route_info_prefix(prefix);
                }
                Repr::DodagConfiguration {
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
                    packet.clear_dodag_conf_flags();
                    packet.set_dodag_conf_authentication_enabled(*authentication_enabled);
                    packet.set_dodag_conf_path_control_size(*path_control_size);
                    packet.set_dodag_conf_dio_interval_doublings(*dio_interval_doublings);
                    packet.set_dodag_conf_dio_interval_minimum(*dio_interval_min);
                    packet.set_dodag_conf_dio_redundancy_constant(*dio_redundancy_constant);
                    packet.set_dodag_conf_max_rank_increase(*max_rank_increase);
                    packet.set_dodag_conf_minimum_hop_rank_increase(*minimum_hop_rank_increase);
                    packet.set_dodag_conf_objective_code_point(*objective_code_point);
                    packet.set_dodag_conf_default_lifetime(*default_lifetime);
                    packet.set_dodag_conf_lifetime_unit(*lifetime_unit);
                }
                Repr::RplTarget {
                    prefix_length,
                    prefix,
                } => {
                    packet.clear_rpl_target_flags();
                    packet.set_rpl_target_prefix_length(*prefix_length);
                    packet.set_rpl_target_prefix(prefix);
                }
                Repr::TransitInformation {
                    external,
                    path_control,
                    path_sequence,
                    path_lifetime,
                    parent_address,
                } => {
                    packet.clear_transit_info_flags();
                    packet.set_transit_info_is_external(*external);
                    packet.set_transit_info_path_control(*path_control);
                    packet.set_transit_info_path_sequence(*path_sequence);
                    packet.set_transit_info_path_lifetime(*path_lifetime);

                    if let Some(address) = parent_address {
                        packet.set_transit_info_parent_address(*address);
                    }
                }
                Repr::SolicitedInformation {
                    rpl_instance_id,
                    version_predicate,
                    instance_id_predicate,
                    dodag_id_predicate,
                    dodag_id,
                    version_number,
                } => {
                    packet.clear_solicited_info_flags();
                    packet.set_solicited_info_rpl_instance_id((*rpl_instance_id).into());
                    packet.set_solicited_info_version_predicate(*version_predicate);
                    packet.set_solicited_info_instance_id_predicate(*instance_id_predicate);
                    packet.set_solicited_info_dodag_id_predicate(*dodag_id_predicate);
                    packet.set_solicited_info_version_number(*version_number);
                    packet.set_solicited_info_dodag_id(*dodag_id);
                }
                Repr::PrefixInformation {
                    prefix_length,
                    on_link,
                    autonomous_address_configuration,
                    router_address,
                    valid_lifetime,
                    preferred_lifetime,
                    destination_prefix,
                } => {
                    packet.clear_prefix_info_reserved();
                    packet.set_prefix_info_prefix_length(*prefix_length);
                    packet.set_prefix_info_on_link(*on_link);
                    packet.set_prefix_info_autonomous_address_configuration(
                        *autonomous_address_configuration,
                    );
                    packet.set_prefix_info_router_address(*router_address);
                    packet.set_prefix_info_valid_lifetime(*valid_lifetime);
                    packet.set_prefix_info_preferred_lifetime(*preferred_lifetime);
                    packet.set_prefix_info_destination_prefix(destination_prefix);
                }
                Repr::RplTargetDescriptor { descriptor } => {
                    packet.set_rpl_target_descriptor_descriptor(*descriptor);
                }
            }
        }
    }
}

pub mod data {
    use super::{Error, InstanceId, Result};
    use byteorder::{ByteOrder, NetworkEndian};

    mod field {
        use crate::wire::field::*;

        pub const FLAGS: usize = 0;
        pub const INSTANCE_ID: usize = 1;
        pub const SENDER_RANK: Field = 2..4;
    }

    /// A read/write wrapper around a RPL Packet Information send with an IPv6 Hop-by-Hop option.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct Packet<T: AsRef<[u8]>> {
        buffer: T,
    }

    impl<T: AsRef<[u8]>> Packet<T> {
        #[inline]
        pub fn new_unchecked(buffer: T) -> Self {
            Self { buffer }
        }

        #[inline]
        pub fn new_checked(buffer: T) -> Result<Self> {
            Ok(Self { buffer })
        }

        #[inline]
        pub fn is_down(&self) -> bool {
            get!(self.buffer, bool, field: field::FLAGS, shift: 7, mask: 0b1)
        }

        #[inline]
        pub fn has_rank_error(&self) -> bool {
            get!(self.buffer, bool, field: field::FLAGS, shift: 6, mask: 0b1)
        }

        #[inline]
        pub fn has_forwarding_error(&self) -> bool {
            get!(self.buffer, bool, field: field::FLAGS, shift: 5, mask: 0b1)
        }

        #[inline]
        pub fn rpl_instance_id(&self) -> InstanceId {
            get!(self.buffer, into: InstanceId, field: field::INSTANCE_ID)
        }

        #[inline]
        pub fn sender_rank(&self) -> u16 {
            get!(self.buffer, u16, field: field::SENDER_RANK)
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        #[inline]
        pub fn set_is_down(&mut self, value: bool) {
            set!(self.buffer, value, bool, field: field::FLAGS, shift: 7, mask: 0b1)
        }

        #[inline]
        pub fn set_has_rank_error(&mut self, value: bool) {
            set!(self.buffer, value, bool, field: field::FLAGS, shift: 6, mask: 0b1)
        }

        #[inline]
        pub fn set_has_forwarding_error(&mut self, value: bool) {
            set!(self.buffer, value, bool, field: field::FLAGS, shift: 5, mask: 0b1)
        }

        #[inline]
        pub fn set_rpl_instance_id(&mut self, value: u8) {
            set!(self.buffer, value, field: field::INSTANCE_ID)
        }

        #[inline]
        pub fn set_sender_rank(&mut self, value: u16) {
            set!(self.buffer, value, u16, field: field::SENDER_RANK)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::options::{OptionType, Packet as OptionPacket, Repr as OptionRepr};
    use super::Repr as RplRepr;
    use super::*;
    use crate::wire::icmpv6::*;

    /// Parsing of DIO packets.
    #[test]
    fn dio_packet() {
        let data = [
            0x9b, 0x01, 0x01, 0x21, 0x00, 0xf0, 0x00, 0x80, 0x08, 0xf0, 0x00, 0x00, 0xfd, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x04, 0x0e, 0x00, 0x08, 0x0c, 0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x01, 0x00, 0x1e,
            0x00, 0x3c, 0x08, 0x1e, 0x40, 0x40, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let addr = Address::from_bytes(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x01,
        ]);

        let dest_prefix = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let packet = Packet::new_checked(&data[..]).unwrap();
        assert_eq!(packet.msg_type(), Message::RplControl);
        assert_eq!(
            RplControlMessage::from(packet.msg_code()),
            RplControlMessage::DodagInformationObject
        );

        let dio_repr = RplRepr::parse(&packet).unwrap();
        match dio_repr {
            RplRepr::DodagInformationObject {
                rpl_instance_id,
                version_number,
                rank,
                grounded,
                mode_of_operation,
                dodag_preference,
                dtsn,
                dodag_id,
                ..
            } => {
                assert_eq!(rpl_instance_id, InstanceId::from(0));
                assert_eq!(version_number, 240);
                assert_eq!(rank, 128);
                assert_eq!(grounded, false);
                assert_eq!(mode_of_operation, ModeOfOperation::NonStoringMode);
                assert_eq!(dodag_preference, 0);
                assert_eq!(dtsn, 240);
                assert_eq!(dodag_id, addr);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(packet.options());
        let option_repr = OptionRepr::parse(&option).unwrap();
        match option_repr {
            OptionRepr::DodagConfiguration {
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
                assert_eq!(authentication_enabled, false);
                assert_eq!(path_control_size, 0);
                assert_eq!(dio_interval_doublings, 8);
                assert_eq!(dio_interval_min, 12);
                assert_eq!(dio_redundancy_constant, 0);
                assert_eq!(max_rank_increase, 1024);
                assert_eq!(minimum_hop_rank_increase, 128);
                assert_eq!(objective_code_point, 1);
                assert_eq!(default_lifetime, 30);
                assert_eq!(lifetime_unit, 60);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(option.next_option().unwrap());
        let option_repr = OptionRepr::parse(&option).unwrap();
        match option_repr {
            OptionRepr::PrefixInformation {
                prefix_length,
                on_link,
                autonomous_address_configuration,
                router_address,
                valid_lifetime,
                preferred_lifetime,
                destination_prefix,
            } => {
                assert_eq!(prefix_length, 64);
                assert_eq!(on_link, false);
                assert_eq!(autonomous_address_configuration, true);
                assert_eq!(valid_lifetime, u32::MAX);
                assert_eq!(preferred_lifetime, u32::MAX);
                assert_eq!(destination_prefix, &dest_prefix[..]);
            }
            _ => unreachable!(),
        }
    }

    /// Parsing of DAO packets.
    #[test]
    fn dao_packet() {
        let data = [
            0x9b, 0x02, 0x5b, 0x40, 0x00, 0x80, 0x00, 0xf1, 0x05, 0x12, 0x00, 0x80, 0xfd, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02,
            0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        ];

        let target_prefix = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x02,
            0x00, 0x02,
        ];

        let parent_addr = Address::from_bytes(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x01,
        ]);

        let packet = Packet::new_checked(&data[..]).unwrap();
        let dao_repr = RplRepr::parse(&packet).unwrap();
        match dao_repr {
            RplRepr::DestinationAdvertisementObject {
                rpl_instance_id,
                expect_ack,
                sequence,
                dodag_id,
                ..
            } => {
                assert_eq!(rpl_instance_id, InstanceId::from(0));
                assert_eq!(expect_ack, true);
                assert_eq!(sequence, 241);
                assert_eq!(dodag_id, None);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(packet.options());

        let option_repr = OptionRepr::parse(&option).unwrap();
        match option_repr {
            OptionRepr::RplTarget {
                prefix_length,
                prefix,
            } => {
                assert_eq!(prefix_length, 128);
                assert_eq!(prefix, &target_prefix[..]);
            }
            _ => unreachable!(),
        }

        let option = OptionPacket::new_unchecked(option.next_option().unwrap());
        let option_repr = OptionRepr::parse(&option).unwrap();
        match option_repr {
            OptionRepr::TransitInformation {
                external,
                path_control,
                path_sequence,
                path_lifetime,
                parent_address,
            } => {
                assert_eq!(external, false);
                assert_eq!(path_control, 0);
                assert_eq!(path_sequence, 0);
                assert_eq!(path_lifetime, 30);
                assert_eq!(parent_address, Some(parent_addr));
            }
            _ => unreachable!(),
        }
    }

    /// Parsing of DAO-ACK packets.
    #[test]
    fn dao_ack_packet() {
        let data = [0x9b, 0x03, 0x75, 0xab, 0x00, 0x00, 0xf1, 0x00];

        let packet = Packet::new_checked(&data[..]).unwrap();
        let dao_ack_repr = RplRepr::parse(&packet).unwrap();
        match dao_ack_repr {
            RplRepr::DestinationAdvertisementObjectAck {
                rpl_instance_id,
                sequence,
                status,
                dodag_id,
                ..
            } => {
                assert_eq!(rpl_instance_id, InstanceId::from(0));
                assert_eq!(sequence, 241);
                assert_eq!(status, 0);
                assert_eq!(dodag_id, None);
            }
            _ => unreachable!(),
        }
    }

    ///// Parsing of SRH packets.
    //#[test]
    //fn srh_packet() {
    //let data = [
    //0xe3, 0x16, 0x03, 0x02, 0x99, 0x20, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
    //0x04, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00, 0x09, 0x00,
    //];

    //let packet = crate::wire::SixlowpanExtHeaderPacket::new_checked(&data).unwrap();
    //assert_eq!(
    //packet.next_header(),
    //crate::wire::sixlowpan::NextHeader::Compressed
    //);
    //assert_eq!(
    //packet.extension_header_id(),
    //crate::wire::sixlowpan::nhc::ExtHeaderId::RoutingHeader
    //);
    //assert_eq!(packet.length(), 22);

    //let packet = crate::wire::Ipv6RoutingHeader::new_checked_compressed(packet.payload(), 2).unwrap();

    //// This is none, because we have a compressed extension header.
    //assert_eq!(packet.next_header(), None);
    //assert_eq!(packet.length(), None);
    //assert_eq!(packet.routing_type(), 3);
    //assert_eq!(packet.segments_left(), 2);
    //assert_eq!(packet.compressed_internal_bytes(), 9);
    //assert_eq!(packet.compressed_final_bytes(), 9);
    //assert_eq!(packet.padding_bytes(), 2);
    //}
}
