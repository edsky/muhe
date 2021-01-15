/// copy from https://github.com/gz/rust-x86
use bitflags::*;

macro_rules! bit {
    ($x:expr) => {
        1 << $x
    };
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
/// x86 Protection levels
///
/// # Note
/// This should not contain values larger than 2 bits, otherwise
/// segment descriptor code needs to be adjusted accordingly.
pub enum Ring {
    Ring0 = 0b00,
    Ring1 = 0b01,
    Ring2 = 0b10,
    Ring3 = 0b11,
}

bitflags! {
    /// Specifies which element to load into a segment from
    /// descriptor tables (i.e., is a index to LDT or GDT table
    /// with some additional flags).
    ///
    /// See Intel 3a, Section 3.4.2 "Segment Selectors"
    pub struct SegmentSelector: u16 {
        /// Requestor Privilege Level
        const RPL_0 = 0b00;
        const RPL_1 = 0b01;
        const RPL_2 = 0b10;
        const RPL_3 = 0b11;

        /// Table Indicator (TI) 0 means GDT is used.
        const TI_GDT = 0 << 2;
        /// Table Indicator (TI) 1 means LDT is used.
        const TI_LDT = 1 << 2;
    }
}

impl SegmentSelector {
    /// Create a new SegmentSelector
    ///
    /// # Arguments
    ///  * `index` - index in GDT or LDT array.
    ///  * `rpl` - Requested privilege level of the selector
    pub const fn new(index: u16, rpl: Ring) -> SegmentSelector {
        SegmentSelector {
            bits: index << 3 | (rpl as u16),
        }
    }

    /// Returns segment selector's index in GDT or LDT.
    pub fn index(&self) -> u16 {
        self.bits >> 3
    }

    /// Make a new segment selector from a untyped u16 value.
    pub const fn from_raw(bits: u16) -> SegmentSelector {
        SegmentSelector { bits }
    }
}

/// System-Segment and Gate-Descriptor Types 32-bit mode.
/// See also Intel 3a, Table 3-2 System Segment and Gate-Descriptor Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemDescriptorTypes32 {
    //Reserved0 = 0b0000,
    TSSAvailable16 = 0b0001,
    LDT = 0b0010,
    TSSBusy16 = 0b0011,
    CallGate16 = 0b0100,
    TaskGate = 0b0101,
    InterruptGate16 = 0b0110,
    TrapGate16 = 0b0111,
    //Reserved1 = 0b1000,
    TssAvailable32 = 0b1001,
    //Reserved2 = 0b1010,
    TssBusy32 = 0b1011,
    CallGate32 = 0b1100,
    //Reserved3 = 0b1101,
    InterruptGate32 = 0b1110,
    TrapGate32 = 0b1111,
}

/// Data Segment types for descriptors.
/// See also Intel 3a, Table 3-1 Code- and Data-Segment Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataSegmentType {
    /// Data Read-Only
    ReadOnly = 0b0000,
    /// Data Read-Only, accessed
    ReadOnlyAccessed = 0b0001,
    /// Data Read/Write
    ReadWrite = 0b0010,
    /// Data Read/Write, accessed
    ReadWriteAccessed = 0b0011,
    /// Data Read-Only, expand-down
    ReadExpand = 0b0100,
    /// Data Read-Only, expand-down, accessed
    ReadExpandAccessed = 0b0101,
    /// Data Read/Write, expand-down
    ReadWriteExpand = 0b0110,
    /// Data Read/Write, expand-down, accessed
    ReadWriteExpandAccessed = 0b0111,
}

/// Code Segment types for descriptors.
/// See also Intel 3a, Table 3-1 Code- and Data-Segment Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodeSegmentType {
    /// Code Execute-Only
    Execute = 0b1000,
    /// Code Execute-Only, accessed
    ExecuteAccessed = 0b1001,
    /// Code Execute/Read
    ExecuteRead = 0b1010,
    /// Code Execute/Read, accessed
    ExecuteReadAccessed = 0b1011,
    /// Code Execute-Only, conforming
    ExecuteConforming = 0b1100,
    /// Code Execute-Only, conforming, accessed
    ExecuteConformingAccessed = 0b1101,
    /// Code Execute/Read, conforming
    ExecuteReadConforming = 0b1110,
    /// Code Execute/Read, conforming, accessed
    ExecuteReadConformingAccessed = 0b1111,
}

/// Helper enum type to differentiate between the different descriptor types that all end up written in the same field.
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum DescriptorType {
    System32(SystemDescriptorTypes32),
    Data(DataSegmentType),
    Code(CodeSegmentType),
}

#[repr(packed)]
#[derive(Copy, Clone, Default, Debug)]
pub struct SegmentDescriptor
{
    lower: u32, upper: u32,
}

impl SegmentDescriptor {
    pub const NULL: SegmentDescriptor = SegmentDescriptor { lower: 0, upper: 0 };

    pub fn as_u64(&self) -> u64 {
        (self.upper as u64) << 32 | self.lower as u64
    }

    /// Create a new segment, TSS or LDT descriptor
    /// by setting the three base and two limit fields.
    pub fn set_base_limit(&mut self, base: u32, limit: u32) {
        // Clear the base and limit fields in Descriptor
        self.lower = 0;
        self.upper = self.upper & 0x00F0FF00;

        // Set the new base
        self.lower |= base << 16;
        self.upper |= (base >> 16) & 0xff;
        self.upper |= (base >> 24) << 24;

        // Set the new limit
        self.lower |= limit & 0xffff;
        let limit_last_four_bits = (limit >> 16) & 0x0f;
        self.upper |= limit_last_four_bits << 16;
    }

    /// Creates a new descriptor with selector and offset (for IDT Gate descriptors,
    /// e.g. Trap, Interrupts and Task gates)
    pub fn set_selector_offset(&mut self, selector: SegmentSelector, offset: u32) {
        // Clear the selector and offset
        self.lower = 0;
        self.upper = self.upper & 0x0000ffff;

        // Set selector
        self.lower |= (selector.bits() as u32) << 16;

        // Set offset
        self.lower |= offset & 0x0000ffff;
        self.upper |= offset & 0xffff0000;
    }

    pub fn set_type(&mut self, _type: u8) {
        self.upper &= !(0x0f << 8); // clear
        self.upper |= (_type as u32 & 0x0f) << 8;
    }

    /// Specifies whether the segment descriptor is for a system segment (S flag is clear) or a code or data segment (S flag is set).
    pub fn set_s(&mut self) {
        self.upper |= bit!(12);
    }

    /// Specifies the privilege level of the segment. The DPL is used to control access to the segment.
    pub fn set_dpl(&mut self, ring: Ring) {
        assert!(ring as u32 <= 0b11);
        self.upper &= !(0b11 << 13);
        self.upper |= (ring as u32) << 13;
    }

    /// Set Present bit.
    /// Indicates whether the segment is present in memory (set) or not present (clear).
    /// If this flag is clear, the processor generates a segment-not-present exception (#NP) when a segment selector
    /// that points to the segment descriptor is loaded into a segment register.
    pub fn set_p(&mut self) {
        self.upper |= bit!(15);
    }

    /// Set AVL bit. System software can use this bit to store information.
    pub fn set_avl(&mut self) {
        self.upper |= bit!(20);
    }

    /// Set L
    /// In IA-32e mode, bit 21 of the second doubleword of the segment descriptor indicates whether a
    /// code segment contains native 64-bit code. A value of 1 indicates instructions in this code
    /// segment are executed in 64-bit mode. A value of 0 indicates the instructions in this code segment
    /// are executed in compatibility mode. If L-bit is set, then D-bit must be cleared.
    pub fn set_l(&mut self) {
        self.upper |= bit!(21);
    }

    /// Set D/B.
    /// Performs different functions depending on whether the segment descriptor is an executable code segment,
    /// an expand-down data segment, or a stack segment.
    pub fn set_db(&mut self) {
        self.upper |= bit!(22);
    }

    /// Set G bit
    /// Determines the scaling of the segment limit field.
    /// When the granularity flag is clear, the segment limit is interpreted in byte units;
    /// when flag is set, the segment limit is interpreted in 4-KByte units.
    pub fn set_g(&mut self) {
        self.upper |= bit!(23);
    }
}