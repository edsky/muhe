use scroll::{Pread, Pwrite};

#[derive(Pread, Pwrite)]
pub(crate) struct ApiSetNamespace
{
    version:        u32,
    size:           u32,
    flags:          u32,
    pub(crate) count:          u32,
    pub(crate) entry_offset:   u32,
    hash_offset:    u32,
    hash_factor:    u32,
}

#[derive(Pread, Pwrite)]
struct ApiSetHashEntry
{
    hash:           u32,
    index:          u32,
}

#[derive(Pread, Pwrite)]
pub(crate) struct ApiSetNamespaceEntry
{
    flags:          u32,
    pub(crate) name_offset:    u32,
    pub(crate) name_length:    u32,
    hashed_length:  u32,
    pub(crate) value_offset:   u32,
    pub(crate) value_count:    u32,
}

#[derive(Pread, Pwrite)]
pub(crate) struct ApiSetValueEntry
{
    flags:          u32,
    pub(crate) name_offset:    u32,
    pub(crate) name_length:    u32,
    pub(crate) value_offset:   u32,
    pub(crate) value_length:   u32,
}