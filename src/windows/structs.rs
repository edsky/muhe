use std::mem::size_of;

#[repr(C)]
#[derive(Default)]
pub(crate) struct ThreadInformationBlock32
{
    // reference: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    seh_frame:                u32,  //0x00
    stack_base:               u32,  //0x04
    stack_limit:              u32,  //0x08
    subsystem_tib:            u32,  //0x0C
    fiber_data:               u32,  //0x10
    arbitrary_data:           u32,  //0x14
    self_addr:                u32,  //0x18
    //End                     of    NT      subsystem independent part
    environment_ptr:          u32,  //0x1C
    process_id:               u32,  //0x20
    thread_id:                u32,  //0x24
    active_rpc_handle:        u32,  //0x28
    tls_addr:                 u32,  //0x2C  thread    local       storage
    peb_addr:                 u32,  //0x30
    last_error:               u32,  //0x34
    critical_section_count:   u32,  //0x38
    csr_client_thread:        u32,  //0x3C
    win32_thread_info:        u32,  //0x40
    win32_client_info:        [u32; 31],    //0x44
    fastsyscall:              u32,  //0xC0
    current_locale:           u32,  //0xC4
    fp_software_status_reg:   u32,  //0xC8
    reserved:                 [u64; 27],    //0xCC
    exception_code:           u32,  //0x1A4
    activation_context_stack: [u8;  20],    //0x1A8
    spare_bytes:              [u8;  24],    //0x1BC

/*
    // Ignoring
    gdi_teb_batch: [u8; 1248], //0x1D4
    gdi_region: u32, //0x6DC
    gdi_pen: u32, //0x6E0
    gdi_brush: u32, //0x6E4
    real_process_id: u32, //0x6E8
    real_thread_id: u32, //0x6EC
    gdi_catched_handle: u32, //0x6F0
    gdi_client_process_id: u32, //0x6F4
    gdi_client_thread_id: u32, //0x6F8
    gdi_thead_locale_info: u32, //0x6FC
    reserved2: [u8; 20], //0x700
    reserved3: [u8; 1248], //0x714
    last_status_value: u32, //0xBF4
    static_unicode_string: [u8; 532], //0xBF8
    deallocation_stack: u32, //0xE0C
    tls_slots: [u8; 256], //0xE10
    tls_links: u64, //0xF10
    vdm: u32, //0xF18
    reserved4: u32, //0xF1C
    thread_error_mode: u32, //0xF28
*/
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct ProcessEnvironmentBlock32
{
    inherited_addr_space:                   bool, //0x000
    read_image_fileexec_options:            bool, //0x001
    being_debugged:                         bool, //0x002
    bit_field:                              u8,  //0x003
    mutant:                                 u32,  //0x004
    image_base_address:                     u32,  //0x008
    peb_ldr_data:                           u32,  //0x000C
    process_parameters:                     u32,  //0x0010
    sub_system_data:                        u32,  //0x0014
    process_heap:                           u32,  //0x0018
    fast_peb_lock:                          u32,  //0x001C
    atl_thunk_s_list_ptr:                   u32,  //0x0020
    ifeo_key:                               u32,  //0x0024
    cross_process_flags:                    u32,  //0x0028
    kernel_callback_table:                  u32,  //0x002C
    system_reserved:                        u32,  //0x0030
    atl_thunk_slist_ptr32:                  u32,  //0x0034
    api_set_map:                            u32,  //0x0038
    tls_expansion_counter:                  u32,  //0x003C
    tls_bitmap:                             u32,  //0x0040
    tls_bitmap_bits:                        [u32; 2],      //0x0044
    read_only_shared_memory_base:           u32,  //0x004C
    hotpatch_information:                   u32,  //0x0050
    read_only_static_server_data:           u32,  //0x0054
    ansi_code_page_data:                    u32,  //0x0058
    oem_code_page_data:                     u32,  //0x005C
    unicode_case_table_data:                u32,  //0x0060
    number_of_processors:                   u32,  //0x0064
    nt_global_flag:                         u64,  //0x0068
    critical_section_timeout:               i64,  //0x0070
    heap_segment_reserve:                   u32,  //0x0078
    heap_segment_commit:                    u32,  //0x007C
    heap_de_commit_total_free_threshold:    u32,  //0x0080
    heap_de_commit_free_block_threshold:    u32,  //0x0084
    number_of_heaps:                        u32,  //0x0088
    maximum_number_of_heaps:                u32,  //0x008C
    process_heaps:                          u32,  //0x0090
    gdi_shared_handle_table:                u32,  //0x0094
    process_starter_helper:                 u32,  //0x0098
    gdi_d_c_attribute_list:                 u32,  //0x009C
    loader_lock:                            u32,  //0x00A0
    os_major_version:                       u32,  //0x00A4
    os_minor_version:                       u32,  //0x00A8
    os_build_number:                        u16,  //0x00AC
    os_csd_version:                         u16,  //0x00AE
    os_platform_id:                         u32,  //0x00B0
    image_subsystem:                        u32,  //0x00B4
    image_subsystem_major_version:          u32,  //0x00B8
    image_subsystem_minor_version:          u32,  //0x00BC
    active_process_affinity_mask:           u32,  //0x00C0
    gdi_handle_buffer:                      [u32; 17],   //0x00C4
    gdi_handle_buffer1:                     [u32; 17],   //0x00C4 Hack
    post_process_init_routine:              u32,  //0x014C
    tls_expansion_bitmap:                   u32,  //0x0150
    tls_expansion_bitmap_bits:              [u32; 32],   //0x0154
    session_id:                             u32,  //0x01D4
    app_compat_flags:                       u64,  //0x01D8
    app_compat_flags_user:                  u64,  //0x01E0
    pshim_data:                             u32,  //0x01E8
    app_compat_info:                        u32,  //0x01EC
    csd_version:                            [u8;  8],      //0x01F0
    activation_context_data:                u32,  //0x01F8
    process_assembly_storage_map:           u32,  //0x01FC
    system_default_activation_context_data: u32,  //0x0200
    system_assembly_storage_map:            u32,  //0x0204
    minimum_stack_commit:                   u32,  //0x0208
    fls_callback:                           u32,  //0x020C
    fls_list_head:                          u64,  //0x0210
    fls_bitmap:                             u32,  //0x0218
    fls_bitmap_bits:                        [u32; 4],      //0x021C
    fls_high_index:                         u32,  //0x022C
    wer_registration_data:                  u32,  //0x0230
    wer_ship_assert_ptr:                    u32,  //0x0234
    pcontext_data:                          u32,  //0x0238
    pimage_header_hash:                     u32,  //0x023C
    tracing_flags:                          u32,  //0x0240
}

#[repr(C)]
#[derive(Clone,Default)]
pub(crate) struct PebLoaderData32
{
    // Size of structure, used by ntdll.dll as structure version ID
    length: u32, //0x00
    // If set, loader data section for current process is initialized
    initialized: [u8; 4], //0x04
    ss_handle: u32, //0x08
    // Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in load order
    pub in_load_order_module_list: [u32; 2], //0x0C
    // Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in memory placement order
    pub in_memory_order_module_list: [u32; 2], //0x14
    // Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in initialization order
    pub in_initialization_order_module_list: [u32; 2], //0x1C
    entry_in_progress: u32, //0x24
    shutdown_in_progress: u32, //0x28
    shutdown_thread_id: u32, //0x2C
}

#[derive(Clone,Default)]
pub(crate) struct PebLoaderData32Map
{
    pub data: PebLoaderData32,
    pub base: u32,
}

#[repr(C)]
#[derive(Clone,Default)]
pub(crate) struct WinUnicodeSting32
{
    length: u16,
    maximum_length: u16,
    buffer: u32,
}

#[repr(C)]
#[derive(Clone,Default)]
pub(crate) struct PebLdrTableEntry32
{
    pub in_load_order_links:           [u32;              2], //0x00
    pub in_memory_order_links:         [u32;              2], //0x08
    pub in_initialization_order_links: [u32;              2], //0x10
    dll_base:                      u32,               //0x18
    entry_point:                   u32,               //0x1C
    size_of_image:                 u32,               //0x20
    full_dll_name:                 WinUnicodeSting32, //0x24
    base_dll_name:                 WinUnicodeSting32, //0x2C
    flags:                         u32,               //0x34
    load_count:                    u16,               //0x38
    tls_index:                     u16,               //0x3A
    hash_links:                    [u32;              2], //0x3C
}

#[derive(Clone)]
pub(crate) struct PebLdrTableEntry32Map
{
    pub data: PebLdrTableEntry32,
    pub base: u32,
}

impl ThreadInformationBlock32 {
    pub fn new(stack_base: u32, stack_limit: u32, self_addr: u32, peb_addr: u32) -> ThreadInformationBlock32 {
        ThreadInformationBlock32 {
            stack_base,
            stack_limit,
            self_addr,
            peb_addr,
            ..ThreadInformationBlock32::default()
        }
    }

    pub fn size() -> u32 {
        size_of::<ThreadInformationBlock32>() as u32
    }
}

impl ProcessEnvironmentBlock32 {
    pub fn new(peb_ldr_data: u32, process_heap: u32) -> ProcessEnvironmentBlock32 {
        ProcessEnvironmentBlock32 {
            peb_ldr_data,
            process_heap,
            number_of_processors: 1,
            ..ProcessEnvironmentBlock32::default()
        }
    }

    pub fn size() -> u32 {
        size_of::<ProcessEnvironmentBlock32>() as u32
    }
}

impl PebLoaderData32 {
    pub fn new(base_addr: u32) -> PebLoaderData32 {
        PebLoaderData32 {
            in_load_order_module_list: [base_addr + 2 * 4; 2],
            in_memory_order_module_list: [base_addr + 4 * 4; 2],
            in_initialization_order_module_list: [base_addr + 6 * 4; 2],
            ..PebLoaderData32::default()
        }
    }

    pub fn size() -> u32 {
        size_of::<PebLoaderData32>() as u32
    }
}

impl WinUnicodeSting32 {
    pub fn new(length: u16, buffer: u32) -> WinUnicodeSting32 {
        WinUnicodeSting32 {
            length,
            maximum_length: 260,
            buffer
        }
    }
}

impl PebLdrTableEntry32 {
    pub fn new(dll_base: u32, full_dll_name: WinUnicodeSting32, base_dll_name: WinUnicodeSting32) -> PebLdrTableEntry32 {
        PebLdrTableEntry32 {
            dll_base,
            full_dll_name,
            base_dll_name,
            ..PebLdrTableEntry32::default()
        }
    }

    pub fn size() -> u32 {
        size_of::<PebLdrTableEntry32>() as u32
    }
}