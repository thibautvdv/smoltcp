use core::fmt;

use byteorder::{ByteOrder, LittleEndian};

use crate::wire::ipv6::Address as Ipv6Address;
use crate::Error;
use crate::Result;

enum_with_unknown! {
    /// IEEE 802.15.4 frame type.
    pub enum FrameType(u8) {
        Beacon = 0b000,
        Data = 0b001,
        Acknowledgement = 0b010,
        MacCommand = 0b011,
        Multipurpose = 0b101,
        FragmentOrFrak = 0b110,
        Extended = 0b111,
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FrameType::Beacon => write!(f, "Beacon"),
            FrameType::Data => write!(f, "Data"),
            FrameType::Acknowledgement => write!(f, "Ack"),
            FrameType::MacCommand => write!(f, "MAC command"),
            FrameType::Multipurpose => write!(f, "Multipurpose"),
            FrameType::FragmentOrFrak => write!(f, "FragmentOrFrak"),
            FrameType::Extended => write!(f, "Extended"),
            FrameType::Unknown(id) => write!(f, "0b{:04b}", id),
        }
    }
}

enum_with_unknown! {
    /// IEEE 802.15.4 addressing mode for destination and source addresses.
    pub enum AddressingMode(u8) {
        Absent    = 0b00,
        Short     = 0b10,
        Extended  = 0b11,
    }
}

impl AddressingMode {
    /// Return the size in octets of the address.
    fn size(&self) -> usize {
        match self {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            AddressingMode::Unknown(_) => 0, // TODO(thvdveld): what do we need to here?
        }
    }
}

impl fmt::Display for AddressingMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddressingMode::Absent => write!(f, "Absent"),
            AddressingMode::Short => write!(f, "Short"),
            AddressingMode::Extended => write!(f, "Extended"),
            AddressingMode::Unknown(id) => write!(f, "0b{:04b}", id),
        }
    }
}

/// A IEEE 802.15.4 PAN.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Pan(pub u16);

impl Pan {
    pub const BROADCAST: Self = Self(0xffff);

    /// Return the PAN ID as bytes.
    pub fn as_bytes(&self) -> [u8; 2] {
        let mut pan = [0u8; 2];
        LittleEndian::write_u16(&mut pan, self.0);
        pan
    }
}

/// A IEEE 802.15.4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    Absent,
    Short([u8; 2]),
    Extended([u8; 8]),
}

impl Address {
    /// The broadcast address.
    pub const BROADCAST: Address = Address::Short([0xff; 2]);

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast()
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    fn short_from_bytes(a: [u8; 2]) -> Self {
        Self::Short(a)
    }

    fn extended_from_bytes(a: [u8; 8]) -> Self {
        Self::Extended(a)
    }

    pub fn from_bytes(a: &[u8]) -> Self {
        if a.len() == 2 {
            let mut b = [0u8; 2];
            b.copy_from_slice(a);
            Address::Short(b)
        } else if a.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(a);
            Address::Extended(b)
        } else {
            panic!("Not an IEEE802.15.4 address");
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Address::Absent => &[],
            Address::Short(value) => value,
            Address::Extended(value) => value,
        }
    }

    /// Convert the extended address to an Extended Unique Identifier (EUI-64)
    pub fn as_eui_64(&self) -> Option<[u8; 8]> {
        match self {
            Address::Absent | Address::Short(_) => None,
            Address::Extended(value) => {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(&value[..]);

                bytes[0] ^= 1 << 1;

                Some(bytes)
            }
        }
    }

    /// Convert an extended address to a link-local IPv6 address using the EUI-64 format from
    /// RFC2464.
    pub fn as_link_local_address(&self) -> Option<Ipv6Address> {
        let mut bytes = [0; 16];
        bytes[0] = 0xfe;
        bytes[1] = 0x80;
        bytes[8..].copy_from_slice(&self.as_eui_64()?);

        Some(Ipv6Address::from_bytes(&bytes))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Absent => write!(f, "not-present"),
            Self::Short(bytes) => write!(f, "{:02x}-{:02x}", bytes[0], bytes[1]),
            Self::Extended(bytes) => write!(
                f,
                "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
            ),
        }
    }
}

enum_with_unknown! {
    /// IEEE 802.15.4 addressing mode for destination and source addresses.
    pub enum FrameVersion(u8) {
        Ieee802154_2003 = 0b00,
        Ieee802154_2006 = 0b01,
        Ieee802154 = 0b10,
    }
}

enum_with_unknown! {
    /// IEEE 802.15.4 security level.
    pub enum SecurityLevel(u8) {
        None = 0b000,
        Mic32 = 0b001,
        Mic64 = 0b010,
        Mic128 = 0b011,
        Enc = 0b100,
        EncMic32 = 0b101,
        EncMic64 = 0b110,
        EncMic128 = 0b111,
    }
}

impl SecurityLevel {
    /// Return the size in bytes of the encrypted authentication tag.
    pub fn mic_len(&self) -> Option<u8> {
        match self {
            SecurityLevel::None | SecurityLevel::Enc => None,
            SecurityLevel::Mic32 | SecurityLevel::EncMic32 => Some(4),
            SecurityLevel::Mic64 | SecurityLevel::EncMic64 => Some(8),
            SecurityLevel::Mic128 | SecurityLevel::EncMic128 => Some(16),
            SecurityLevel::Unknown(_) => None,
        }
    }
}

/// A read/write wrapper around an IEEE 802.15.4 frame buffer.
#[derive(Debug, Clone)]
pub struct Frame<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    pub const FRAMECONTROL: Field = 0..2;
    pub const SEQUENCE_NUMBER: usize = 2;
    pub const ADDRESSING: Rest = 3..;
}

macro_rules! fc_bit_field {
    ($field:ident, $bit:literal) => {
        #[inline]
        pub fn $field(&self) -> bool {
            let data = self.buffer.as_ref();
            let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);

            ((raw >> $bit) & 0b1) == 0b1
        }
    };
}

macro_rules! set_fc_bit_field {
    ($field:ident, $bit:literal) => {
        #[inline]
        pub fn $field(&mut self, val: bool) {
            let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
            let mut raw = LittleEndian::read_u16(data);
            raw |= ((val as u16) << $bit);

            data.copy_from_slice(&raw.to_le_bytes());
        }
    };
}

impl<T: AsRef<[u8]>> Frame<T> {
    /// Input a raw octet buffer with Ethernet frame structure.
    pub fn new_unchecked(buffer: T) -> Frame<T> {
        Frame { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;

        if matches!(packet.dst_addressing_mode(), AddressingMode::Unknown(_)) {
            return Err(Error::Malformed);
        }

        if matches!(packet.src_addressing_mode(), AddressingMode::Unknown(_)) {
            return Err(Error::Malformed);
        }

        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        // We need at least 3 bytes
        if self.buffer.as_ref().len() < 3 {
            return Err(Error::Truncated);
        }

        let mut offset = field::ADDRESSING.start + 2;

        // Calculate the size of the addressing field.
        offset += self.dst_addressing_mode().size();
        offset += self.src_addressing_mode().size();

        if !self.pan_id_compression() {
            offset += 2;
        }

        if offset > self.buffer.as_ref().len() {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    /// Consumes the frame, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the FrameType field.
    #[inline]
    pub fn frame_type(&self) -> FrameType {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let ft = (raw & 0b11) as u8;
        FrameType::from(ft)
    }

    fc_bit_field!(security_enabled, 3);
    fc_bit_field!(frame_pending, 4);
    fc_bit_field!(ack_request, 5);
    fc_bit_field!(pan_id_compression, 6);

    fc_bit_field!(sequence_number_suppression, 8);
    fc_bit_field!(ie_present, 9);

    /// Return the destination addressing mode.
    #[inline]
    pub fn dst_addressing_mode(&self) -> AddressingMode {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let am = ((raw >> 10) & 0b11) as u8;
        AddressingMode::from(am)
    }

    /// Return the frame version.
    #[inline]
    pub fn frame_version(&self) -> FrameVersion {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let fv = ((raw >> 12) & 0b11) as u8;
        FrameVersion::from(fv)
    }

    /// Return the source addressing mode.
    #[inline]
    pub fn src_addressing_mode(&self) -> AddressingMode {
        let data = self.buffer.as_ref();
        let raw = LittleEndian::read_u16(&data[field::FRAMECONTROL]);
        let am = ((raw >> 14) & 0b11) as u8;
        AddressingMode::from(am)
    }

    /// Return the sequence number of the frame.
    #[inline]
    pub fn sequence_number(&self) -> Option<u8> {
        match self.frame_type() {
            FrameType::Beacon
            | FrameType::Data
            | FrameType::Acknowledgement
            | FrameType::MacCommand
            | FrameType::Multipurpose => {
                let data = self.buffer.as_ref();
                let raw = data[field::SEQUENCE_NUMBER];
                Some(raw)
            }
            FrameType::Extended | FrameType::FragmentOrFrak | FrameType::Unknown(_) => None,
        }
    }

    /// Return the addressing fields.
    #[inline]
    fn addressing_fields(&self) -> Option<&[u8]> {
        match self.frame_type() {
            FrameType::Beacon
            | FrameType::Data
            | FrameType::MacCommand
            | FrameType::Multipurpose => (),
            FrameType::Acknowledgement if self.frame_version() == FrameVersion::Ieee802154 => (),
            FrameType::Acknowledgement
            | FrameType::Extended
            | FrameType::FragmentOrFrak
            | FrameType::Unknown(_) => return None,
        }

        let mut offset = 2;

        // Calculate the size of the addressing field.
        offset += self.dst_addressing_mode().size();
        offset += self.src_addressing_mode().size();

        if !self.pan_id_compression() {
            offset += 2;
        }

        Some(&self.buffer.as_ref()[field::ADDRESSING][..offset])
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn dst_pan_id(&self) -> Option<Pan> {
        let addressing_fields = self.addressing_fields()?;
        match self.dst_addressing_mode() {
            AddressingMode::Absent => None,
            AddressingMode::Short | AddressingMode::Extended => {
                Some(Pan(LittleEndian::read_u16(&addressing_fields[0..2])))
            }
            AddressingMode::Unknown(_) => None,
        }
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Option<Address> {
        let addressing_fields = self.addressing_fields()?;
        match self.dst_addressing_mode() {
            AddressingMode::Absent => Some(Address::Absent),
            AddressingMode::Short => {
                let mut raw = [0u8; 2];
                raw.clone_from_slice(&addressing_fields[2..4]);
                raw.reverse();
                Some(Address::short_from_bytes(raw))
            }
            AddressingMode::Extended => {
                let mut raw = [0u8; 8];
                raw.clone_from_slice(&addressing_fields[2..10]);
                raw.reverse();
                Some(Address::extended_from_bytes(raw))
            }
            AddressingMode::Unknown(_) => None,
        }
    }

    /// Return the destination PAN field.
    #[inline]
    pub fn src_pan_id(&self) -> Option<Pan> {
        if self.pan_id_compression() {
            return None;
        }

        let addressing_fields = self.addressing_fields()?;
        let offset = self.dst_addressing_mode().size() + 2;

        match self.src_addressing_mode() {
            AddressingMode::Absent => None,
            AddressingMode::Short | AddressingMode::Extended => Some(Pan(LittleEndian::read_u16(
                &addressing_fields[offset..offset + 2],
            ))),
            AddressingMode::Unknown(_) => None,
        }
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Option<Address> {
        let addressing_fields = self.addressing_fields()?;
        let mut offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => return None, // TODO(thvdveld): what do we do here?
        } + 2;

        if !self.pan_id_compression() {
            offset += 2;
        }

        match self.src_addressing_mode() {
            AddressingMode::Absent => Some(Address::Absent),
            AddressingMode::Short => {
                let mut raw = [0u8; 2];
                raw.clone_from_slice(&addressing_fields[offset..offset + 2]);
                raw.reverse();
                Some(Address::short_from_bytes(raw))
            }
            AddressingMode::Extended => {
                let mut raw = [0u8; 8];
                raw.clone_from_slice(&addressing_fields[offset..offset + 8]);
                raw.reverse();
                Some(Address::extended_from_bytes(raw))
            }
            AddressingMode::Unknown(_) => None,
        }
    }

    /// Return the index where the auxiliary security header starts.
    fn aux_security_header_start(&self) -> usize {
        // We start with 3, because 2 bytes for frame control and the sequence number.
        let mut index = 3;
        index += self.addressing_fields().unwrap().len();
        index
    }

    /// Return the index where the payload starts.
    fn payload_start(&self) -> usize {
        let mut index = self.aux_security_header_start();

        if self.security_enabled() {
            // We add 5 because 1 byte for control bits and 4 bytes for frame counter.
            index += 5;
            index += if let Some(len) = self.key_identifier_length() {
                len as usize
            } else {
                0
            };
        }

        index
    }

    /// Return the lenght of the key identifier field.
    fn key_identifier_length(&self) -> Option<u8> {
        Some(match self.key_identifier_mode() {
            0 => 0,
            1 => 1,
            2 => 5,
            3 => 9,
            _ => return None,
        })
    }

    /// Return the security level of the auxiliary security header.
    pub fn security_level(&self) -> SecurityLevel {
        let index = self.aux_security_header_start();
        let b = self.buffer.as_ref()[index..][0];
        SecurityLevel::from(b & 0b111)
    }

    /// Return the key identifier mode used by the auxiliary security header.
    pub fn key_identifier_mode(&self) -> u8 {
        let index = self.aux_security_header_start();
        let b = self.buffer.as_ref()[index..][0];
        (b >> 3) & 0b11
    }

    /// Return the frame counter field.
    pub fn frame_counter(&self) -> u32 {
        let index = self.aux_security_header_start();
        let b = &self.buffer.as_ref()[index..];
        LittleEndian::read_u32(&b[1..1 + 4])
    }

    /// Return the Key Identifier field.
    fn key_identifier(&self) -> &[u8] {
        let index = self.aux_security_header_start();
        let b = &self.buffer.as_ref()[index..];
        let length = if let Some(len) = self.key_identifier_length() {
            len as usize
        } else {
            0
        };
        &b[5..][..length]
    }

    /// Return the Key Source field.
    pub fn key_source(&self) -> Option<&[u8]> {
        let ki = self.key_identifier();
        let len = ki.len();
        if len > 1 {
            Some(&ki[..len - 1])
        } else {
            None
        }
    }

    /// Return the Key Index field.
    pub fn key_index(&self) -> Option<u8> {
        let ki = self.key_identifier();
        let len = ki.len();

        if len > 0 {
            Some(ki[len - 1])
        } else {
            None
        }
    }

    /// Return the Message Integrity Code (MIC).
    pub fn message_integrity_code(&self) -> Option<&[u8]> {
        let mic_len = match self.security_level().mic_len() {
            Some(len) => len as usize,
            None => return None,
        };

        let data = &self.buffer.as_ref();
        let len = data.len();

        Some(&data[len - mic_len..])
    }

    pub fn message_integrity_code_index(&self) -> Option<usize> {
        let data = &self.buffer.as_ref();

        let end = match self.security_level().mic_len() {
            Some(len) => len as usize,
            None => return None,
        };

        let data = &data[self.payload_start()..];
        Some(data.len() - end)
    }

    /// Return the MAC header.
    pub fn mac_header(&self) -> &[u8] {
        let data = &self.buffer.as_ref();
        &data[..self.payload_start()]
    }

    /// Return the nonce, which is based on the extended source address, the frame counter and the
    /// security level.
    pub fn nonce(&self, source_address: &[u8]) -> Option<[u8; 13]> {
        if source_address.len() != 8 {
            net_debug!("Expected extended source address.");
            return None;
        }

        match self.security_level() {
            SecurityLevel::Unknown(_) => None,
            level => {
                let mut n = [0u8; 13];
                n[0..8].copy_from_slice(source_address);
                n[8..12].copy_from_slice(&self.frame_counter().to_be_bytes());
                n[12] = level.into();
                Some(n)
            }
        }
    }

}

impl<'a, T: AsRef<[u8]> + ?Sized> Frame<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> Option<&'a [u8]> {
        match self.frame_type() {
            FrameType::Data => {
                let index = self.payload_start();
                let data = &self.buffer.as_ref();

                Some(&data[index..])
            }
            _ => None,
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    /// Set the frame type.
    #[inline]
    pub fn set_frame_type(&mut self, frame_type: FrameType) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b111)) | (u8::from(frame_type) as u16 & 0b111);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    set_fc_bit_field!(set_security_enabled, 3);
    set_fc_bit_field!(set_frame_pending, 4);
    set_fc_bit_field!(set_ack_request, 5);
    set_fc_bit_field!(set_pan_id_compression, 6);

    /// Set the frame version.
    #[inline]
    pub fn set_frame_version(&mut self, version: FrameVersion) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b11 << 12)) | ((u8::from(version) as u16 & 0b11) << 12);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    /// Set the frame sequence number.
    #[inline]
    pub fn set_sequence_number(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::SEQUENCE_NUMBER] = value;
    }

    /// Set the destination PAN ID.
    #[inline]
    pub fn set_dst_pan_id(&mut self, value: Pan) {
        // NOTE the destination addressing mode must be different than Absent.
        // This is the reason why we set it to Extended.
        self.set_dst_addressing_mode(AddressingMode::Extended);

        let data = self.buffer.as_mut();
        data[field::ADDRESSING][..2].copy_from_slice(&value.as_bytes());
    }

    /// Set the destination address.
    #[inline]
    pub fn set_dst_addr(&mut self, mut value: Address) {
        match value {
            Address::Absent => self.set_dst_addressing_mode(AddressingMode::Absent),
            Address::Short(ref mut value) => {
                value.reverse();
                self.set_dst_addressing_mode(AddressingMode::Short);
                let data = self.buffer.as_mut();
                data[field::ADDRESSING][2..2 + 2].copy_from_slice(value);
                value.reverse();
            }
            Address::Extended(ref mut value) => {
                value.reverse();
                self.set_dst_addressing_mode(AddressingMode::Extended);
                let data = &mut self.buffer.as_mut()[field::ADDRESSING];
                data[2..2 + 8].copy_from_slice(value);
                value.reverse();
            }
        }
    }

    /// Set the destination addressing mode.
    #[inline]
    fn set_dst_addressing_mode(&mut self, value: AddressingMode) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b11 << 10)) | ((u8::from(value) as u16 & 0b11) << 10);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    /// Set the source PAN ID.
    #[inline]
    pub fn set_src_pan_id(&mut self, value: Pan) {
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2;

        let data = &mut self.buffer.as_mut()[field::ADDRESSING];
        data[offset..offset + 2].copy_from_slice(&value.as_bytes());
    }

    /// Set the source address.
    #[inline]
    pub fn set_src_addr(&mut self, mut value: Address) {
        let offset = match self.dst_addressing_mode() {
            AddressingMode::Absent => 0,
            AddressingMode::Short => 2,
            AddressingMode::Extended => 8,
            _ => unreachable!(),
        } + 2;

        let offset = offset + if self.pan_id_compression() { 0 } else { 2 };

        match value {
            Address::Absent => self.set_src_addressing_mode(AddressingMode::Absent),
            Address::Short(ref mut value) => {
                value.reverse();
                self.set_src_addressing_mode(AddressingMode::Short);
                let data = &mut self.buffer.as_mut()[field::ADDRESSING];
                data[offset..offset + 2].copy_from_slice(value);
                value.reverse();
            }
            Address::Extended(ref mut value) => {
                value.reverse();
                self.set_src_addressing_mode(AddressingMode::Extended);
                let data = &mut self.buffer.as_mut()[field::ADDRESSING];
                data[offset..offset + 8].copy_from_slice(value);
                value.reverse();
            }
        }
    }

    /// Set the source addressing mode.
    #[inline]
    fn set_src_addressing_mode(&mut self, value: AddressingMode) {
        let data = &mut self.buffer.as_mut()[field::FRAMECONTROL];
        let mut raw = LittleEndian::read_u16(data);

        raw = (raw & !(0b11 << 14)) | ((u8::from(value) as u16 & 0b11) << 14);
        data.copy_from_slice(&raw.to_le_bytes());
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> Option<&mut [u8]> {
        match self.frame_type() {
            FrameType::Data => {
                let index = self.payload_start();
                let data = self.buffer.as_mut();
                Some(&mut data[index..])
            }
            _ => None,
        }
    }

    /// Unsecure a secured IEEE 802.15.4 frame into `buffer`.
    pub fn decrypt(&mut self, key: &[u8; 16]) -> Result<()> {
        use aes::Aes128;
        use ccm::{
            aead::{
                generic_array::{
                    typenum::consts::{U13, U16, U4, U8},
                    GenericArray,
                },
                AeadInPlace, NewAead,
            },
            Ccm,
        };
        pub use cipher::{BlockCipher, BlockEncrypt, NewBlockCipher};

        let mut buffer = [0u8; 128];

        let inner = self.buffer.as_ref();
        let buffer = &mut buffer[..inner.len()];
        buffer.copy_from_slice(inner);

        let src_addr = self.src_addr().unwrap();
        let nonce = self.nonce(src_addr.as_bytes()).unwrap();
        let nonce = GenericArray::from_slice(&nonce);

        let mic_index = if let Some(index) = self.message_integrity_code_index() {
            index
        } else {
            0
        };

        let payload = &mut buffer[self.payload_start()..];
        let (auth_enc_part, tag) = payload.split_at_mut(mic_index);
        let mhr = self.mac_header();

        let authenticated = match self.security_level() {
            SecurityLevel::None | SecurityLevel::Unknown(_) => todo!(),
            SecurityLevel::Enc => return Err(Error::NotSupported),
            SecurityLevel::Mic32 => {
                let aead = Ccm::<Aes128, U4, U13>::new(key.into());
                let tag = GenericArray::from_slice(tag);
                aead.decrypt_in_place_detached(nonce, auth_enc_part, &mut [], tag)
            }
            SecurityLevel::EncMic32 => {
                let aead = Ccm::<Aes128, U4, U13>::new(key.into());
                let tag = GenericArray::from_slice(tag);
                aead.decrypt_in_place_detached(nonce, mhr, auth_enc_part, tag)
            }
            SecurityLevel::Mic64 => {
                let aead = Ccm::<Aes128, U8, U13>::new(key.into());
                let tag = GenericArray::from_slice(tag);
                aead.decrypt_in_place_detached(nonce, auth_enc_part, &mut [], tag)
            }
            SecurityLevel::EncMic64 => {
                let aead = Ccm::<Aes128, U8, U13>::new(key.into());
                let tag = GenericArray::from_slice(tag);
                aead.decrypt_in_place_detached(nonce, mhr, auth_enc_part, tag)
            }
            SecurityLevel::Mic128 => {
                let aead = Ccm::<Aes128, U16, U13>::new(key.into());
                let tag = GenericArray::from_slice(tag);
                aead.decrypt_in_place_detached(nonce, auth_enc_part, &mut [], tag)
            }
            SecurityLevel::EncMic128 => {
                let aead = Ccm::<Aes128, U16, U13>::new(key.into());
                let tag = GenericArray::from_slice(tag);
                aead.decrypt_in_place_detached(nonce, mhr, auth_enc_part, tag)
            }
        };

        match authenticated {
            Ok(()) => {
                self.buffer.as_mut().copy_from_slice(&buffer[..]);
                Ok(())
            }
            Err(e) => {
                net_debug!("Error decrypting: {:?}", e);
                Err(Error::Malformed)
            }
        }
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Frame<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IEEE802.15.4 frame type={} seq={:2x?} dst_pan={:x?} dest={:x?} src_pan={:?} src={:x?}",
            self.frame_type(),
            self.sequence_number(),
            self.dst_pan_id(),
            self.dst_addr(),
            self.src_pan_id(),
            self.src_addr(),
        )
    }
}

/// A high-level representation of an IEEE802.15.4 frame.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub frame_type: FrameType,
    pub security_enabled: bool,
    pub frame_pending: bool,
    pub ack_request: bool,
    pub sequence_number: Option<u8>,
    pub pan_id_compression: bool,
    pub frame_version: FrameVersion,
    pub dst_pan_id: Option<Pan>,
    pub dst_addr: Option<Address>,
    pub src_pan_id: Option<Pan>,
    pub src_addr: Option<Address>,
}

impl Repr {
    /// Parse an IEEE 802.15.4 frame and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Frame<&T>) -> Result<Repr> {

        Ok(Repr {
            frame_type: packet.frame_type(),
            security_enabled: packet.security_enabled(),
            frame_pending: packet.frame_pending(),
            ack_request: packet.ack_request(),
            sequence_number: packet.sequence_number(),
            pan_id_compression: packet.pan_id_compression(),
            frame_version: packet.frame_version(),
            dst_pan_id: packet.dst_pan_id(),
            dst_addr: packet.dst_addr(),
            src_pan_id: packet.src_pan_id(),
            src_addr: packet.src_addr(),
        })
    }

    /// Return the length of a buffer required to hold a packet with the payload of a given length.
    #[inline]
    pub fn buffer_len(&self) -> usize {
        3 + 2
            + match self.dst_addr {
                Some(Address::Absent) | None => 0,
                Some(Address::Short(_)) => 2,
                Some(Address::Extended(_)) => 8,
            }
            + if !self.pan_id_compression { 2 } else { 0 }
            + match self.src_addr {
                Some(Address::Absent) | None => 0,
                Some(Address::Short(_)) => 2,
                Some(Address::Extended(_)) => 8,
            }
    }

    /// Emit a high-level representation into an IEEE802.15.4 frame.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Frame<T>) {
        frame.set_frame_type(self.frame_type);
        frame.set_security_enabled(self.security_enabled);
        frame.set_frame_pending(self.frame_pending);
        frame.set_ack_request(self.ack_request);
        frame.set_pan_id_compression(self.pan_id_compression);
        frame.set_frame_version(self.frame_version);

        if let Some(sequence_number) = self.sequence_number {
            frame.set_sequence_number(sequence_number);
        }

        if let Some(dst_pan_id) = self.dst_pan_id {
            frame.set_dst_pan_id(dst_pan_id);
        }
        if let Some(dst_addr) = self.dst_addr {
            frame.set_dst_addr(dst_addr);
        }

        if !self.pan_id_compression && self.src_pan_id.is_some() {
            frame.set_src_pan_id(self.src_pan_id.unwrap());
        }

        if let Some(src_addr) = self.src_addr {
            frame.set_src_addr(src_addr);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
    }

    #[test]
    fn prepare_frame() {
        let mut buffer = [0u8; 128];

        let repr = Repr {
            frame_type: FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            pan_id_compression: true,
            frame_version: FrameVersion::Ieee802154,
            sequence_number: Some(1),
            dst_pan_id: Some(Pan(0xabcd)),
            dst_addr: Some(Address::BROADCAST),
            src_pan_id: None,
            src_addr: Some(Address::Extended([
                0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00,
            ])),
        };

        let buffer_len = repr.buffer_len();

        let mut frame = Frame::new_unchecked(&mut buffer[..buffer_len]);
        repr.emit(&mut frame);

        println!("{:2x?}", frame);

        assert_eq!(frame.frame_type(), FrameType::Data);
        assert!(!frame.security_enabled());
        assert!(!frame.frame_pending());
        assert!(frame.ack_request());
        assert!(frame.pan_id_compression());
        assert_eq!(frame.frame_version(), FrameVersion::Ieee802154);
        assert_eq!(frame.sequence_number(), Some(1));
        assert_eq!(frame.dst_pan_id(), Some(Pan(0xabcd)));
        assert_eq!(frame.dst_addr(), Some(Address::BROADCAST));
        assert_eq!(frame.src_pan_id(), None);
        assert_eq!(
            frame.src_addr(),
            Some(Address::Extended([
                0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00
            ]))
        );
    }

    macro_rules! vector_test {
        ($name:ident $bytes:expr ; $($test_method:ident -> $expected:expr,)*) => {
            #[test]
            #[allow(clippy::bool_assert_comparison)]
            fn $name() -> Result<()> {
                let frame = &$bytes;
                let frame = Frame::new_checked(frame)?;

                $(
                    assert_eq!(frame.$test_method(), $expected, stringify!($test_method));
                )*

                Ok(())
            }
        }
    }

    vector_test! {
        extended_addr
        [
            0b0000_0001, 0b1100_1100, // frame control
            0b0, // seq
            0xcd, 0xab, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, // dst addr
            0x03, 0x04, // pan id
            0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, // src addr
        ];
        frame_type -> FrameType::Data,
        dst_addr -> Some(Address::Extended([0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00])),
        src_addr -> Some(Address::Extended([0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00])),
        dst_pan_id -> Some(Pan(0xabcd)),
    }

    vector_test! {
        short_addr
        [
            0x01, 0x98,             // frame control
            0x00,                   // sequence number
            0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
            0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
        ];
        frame_type -> FrameType::Data,
        security_enabled -> false,
        frame_pending -> false,
        ack_request -> false,
        pan_id_compression -> false,
        dst_addressing_mode -> AddressingMode::Short,
        frame_version -> FrameVersion::Ieee802154_2006,
        src_addressing_mode -> AddressingMode::Short,
        dst_pan_id -> Some(Pan(0x1234)),
        dst_addr -> Some(Address::Short([0x56, 0x78])),
        src_pan_id -> Some(Pan(0x1234)),
        src_addr -> Some(Address::Short([0x9a, 0xbc])),
    }

    vector_test! {
        zolertia_remote
        [
            0x41, 0xd8, // frame control
            0x01, // sequence number
            0xcd, 0xab, // Destination PAN id
            0xff, 0xff, // Short destination address
            0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, // Extended source address
            0x2b, 0x00, 0x00, 0x00, // payload
        ];
        frame_type -> FrameType::Data,
        security_enabled -> false,
        frame_pending -> false,
        ack_request -> false,
        pan_id_compression -> true,
        dst_addressing_mode -> AddressingMode::Short,
        frame_version -> FrameVersion::Ieee802154_2006,
        src_addressing_mode -> AddressingMode::Extended,
        payload -> Some(&[0x2b, 0x00, 0x00, 0x00][..]),
    }

    vector_test! {
        security
        [
            0x69,0xdc, // frame control
            0x32, // sequence number
            0xcd,0xab, // destination PAN id
            0xbf,0x9b,0x15,0x06,0x00,0x4b,0x12,0x00, // extended destination address
            0xc7,0xd9,0xb5,0x14,0x00,0x4b,0x12,0x00, // extended source address
            0x05, // security control field
            0x31,0x01,0x00,0x00, // frame counter
            0x3e,0xe8,0xfb,0x85,0xe4,0xcc,0xf4,0x48,0x90,0xfe,0x56,0x66,0xf7,0x1c,0x65,0x9e,0xf9, // data
            0x93,0xc8,0x34,0x2e,// MIC
        ];
        frame_type -> FrameType::Data,
        security_enabled -> true,
        frame_pending -> false,
        ack_request -> true,
        pan_id_compression -> true,
        dst_addressing_mode -> AddressingMode::Extended,
        frame_version -> FrameVersion::Ieee802154_2006,
        src_addressing_mode -> AddressingMode::Extended,
        dst_pan_id -> Some(Pan(0xabcd)),
        dst_addr -> Some(Address::Extended([0x00,0x12,0x4b,0x00,0x06,0x15,0x9b,0xbf])),
        src_pan_id -> None,
        src_addr -> Some(Address::Extended([0x00,0x12,0x4b,0x00,0x14,0xb5,0xd9,0xc7])),
        security_level -> SecurityLevel::EncMic32,
        key_identifier_mode -> 0,
        frame_counter -> 305,
        key_source -> None,
        key_index -> None,
        payload -> Some(&[0x3e,0xe8,0xfb,0x85,0xe4,0xcc,0xf4,0x48,0x90,0xfe,0x56,0x66,0xf7,0x1c,0x65,0x9e,0xf9,0x93,0xc8,0x34,0x2e][..]),
        message_integrity_code -> Some(&[0x93, 0xC8, 0x34, 0x2E][..]),
        mac_header -> &[
            0x69,0xdc, // frame control
            0x32, // sequence number
            0xcd,0xab, // destination PAN id
            0xbf,0x9b,0x15,0x06,0x00,0x4b,0x12,0x00, // extended destination address
            0xc7,0xd9,0xb5,0x14,0x00,0x4b,0x12,0x00, // extended source address
            0x05, // security control field
            0x31,0x01,0x00,0x00, // frame counter
        ][..],
    }

    #[test]
    fn decryption() {
        let mut frame = [
            0x69, 0xdc, 0x2a, 0xcd, 0xab, 0xbf, 0x9b, 0x15, 0x06, 0x00, 0x4b, 0x12, 0x00, 0xc7,
            0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, 0x05, 0x59, 0x00, 0x00, 0x00, 0x3f, 0x3b,
            0xe8, 0xcd, 0xcb, 0xbb, 0xcc, 0x34, 0x00, 0xc5, 0x26, 0xb9, 0x4b, 0x59, 0x62, 0xb9,
            0x5b, 0xda, 0xf9, 0x8d, 0xf1, 0xe4, 0x2c, 0x86, 0xb0, 0xb5,
        ];

        let key = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];

        let mut frame = Frame::new_checked(&mut frame[..]).unwrap();

        let res = frame.decrypt(&key);

        assert_eq!(res, Ok(()));

        if res.is_ok() {
            println!("{:?}", frame.payload());
            let inner = frame.into_inner();
            let frame = Frame::new_checked(&inner[..]).unwrap();
            println!("{:?}", Repr::parse(&frame));

            let payload = frame.payload().unwrap();
            // *NOTE*: we start at 9 because those are the headers bytes for 6LoWPAN.
            let payload = &payload[9..frame.message_integrity_code_index().unwrap()];

            assert_eq!(String::from_utf8_lossy(payload), "Hello to Rust");
        }
    }
}
