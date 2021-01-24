#![allow(non_snake_case)]

use unicorn::{Protection, CpuX86, RegisterX86, Cpu, InsnSysX86, Register, Unicorn};
use goblin::pe::PE;
use crate::heap::Heap;
use crate::utils::{as_u8_slice, load_file};
use std::path::Path;
use std::cmp::{min, max};
use std::collections::HashMap;
use bimap::BiMap;
use byte_slice_cast::AsByteSlice;
use std::error::Error;
use std::cell::{Cell, RefCell};
use goblin::pe::section_table::{IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE};
use crate::windows::structs::{PebLoaderData32Map, ThreadInformationBlock32, ProcessEnvironmentBlock32};
use crate::windows::structs::{PebLoaderData32, WinUnicodeSting32, PebLdrTableEntry32, PebLdrTableEntry32Map};
use std::borrow::Borrow;
use crate::windows::segmentation::{SegmentDescriptor, Ring};
use scroll::{Pread, Pwrite};
use crate::windows::api_set;
use widestring::WideString;
use std::sync::Arc;

const FS_SEGMENT_ADDR: u32 = 0x6000;
const FS_SEGMENT_SIZE: u32 = 0x6000;
const GDT_ADDRESS: u64 = 0xc0000000;
const SYSTEM_PATH: &str = "./files/rootfs/Windows/System32/";
const SYSTEM32_PATH: &str = "./files/rootfs/Windows/SysWOW64/";

pub struct PeLoader<'a> {
    emu: Box<CpuX86<'a>>,               // unicorn
    heap: Box<Heap>,                    // heap
    #[allow(dead_code)]
    fs_last_addr: u64,                  // fs 结构最后地址
    pub entry_point: u64,               // oep
    ldr_data_map: PebLoaderData32Map,   // peb
    ldr_list: RefCell<Vec<PebLdrTableEntry32Map>>,// peb table
    dll_last_addr: Cell<u64>,           // dll module last address
    dll_mmap: RefCell<BiMap<String, u32>>,// dll映射表, 名称 <-> 基地址
    dll_imports: RefCell<HashMap<String, HashMap<String, u32>>>,   // 导入表, 名称 <-> [函数名 <-> 地址]
    dll_exports: RefCell<HashMap<String, HashMap<u32, String>>>,
    dll_api_sets: RefCell<HashMap<String, Vec<String>>>,    // api sets
}

#[repr(C)]
#[derive(Default,Debug)]
struct X86Mmr
{
    selector:   u16,    /* not used by GDTR and IDTR */
    base:       u64,    /* handle 32 or 64 bit CPUs */
    limit:      u32,
    flags:      u32,    /* not used by GDTR and IDTR */
}

impl<'a> PeLoader<'a>
{
    pub fn new(file: &str) -> Result<Arc<PeLoader>, Box<dyn Error>> {
        let emu = Box::new(CpuX86::new(unicorn::Mode::MODE_32)?);
        let heap = Box::new(Heap::new(0x5000000, 0x5000000 + 0x5000000));
        // alloc
        let image_address = 0x400000 as u64;
        // 堆栈
        let stack_address = 0xfffdd000;
        let stack_size = 0x21000 as usize;
        emu.mem_map(stack_address, stack_size as usize, Protection::READ | Protection::WRITE)?;
        let esp = stack_address + stack_size as u64 - 0x1000;

        emu.reg_write(RegisterX86::ESP, esp)?;
        emu.reg_write(RegisterX86::EBP, esp)?;

        // init thead information block
        let mut fs_last_addr = FS_SEGMENT_ADDR;
        emu.mem_map(FS_SEGMENT_ADDR as u64, FS_SEGMENT_SIZE as usize, Protection::READ | Protection::WRITE)?;
        // - init tib
        let teb_addr = fs_last_addr;
        fs_last_addr += ThreadInformationBlock32::size();
        let teb_data = ThreadInformationBlock32::new(stack_address as u32 + stack_size as u32, stack_size as u32, teb_addr, fs_last_addr);
        emu.mem_write(teb_addr as u64, as_u8_slice(&teb_data))?;
        // - init peb
        let peb_addr = fs_last_addr;
        fs_last_addr += ProcessEnvironmentBlock32::size();

        let process_heap = { PeLoader::uc_alloc(emu.borrow(), heap.borrow(), 0x100) };
        let peb_data = ProcessEnvironmentBlock32::new(fs_last_addr, process_heap as u32, image_address as u32);
        emu.mem_write(peb_addr as u64, as_u8_slice(&peb_data))?;
        // - init ldr_data
        let ldr_addr = fs_last_addr;
        fs_last_addr += PebLoaderData32::size();
        let ldr_data = PebLoaderData32::new(ldr_addr);
        emu.mem_write(ldr_addr as u64, as_u8_slice(&ldr_data))?;
        let ldr_data_map = PebLoaderData32Map { data: ldr_data, base: ldr_addr };
        let fs_last_addr = fs_last_addr as u64;
        // mmap PE file into memory
        let data = &load_file(file)?[..];
        let pe = PE::parse(data)?;
        let entry_point = pe.header.optional_header.unwrap().standard_fields.address_of_entry_point + image_address;
        // 初始化
        let loader = PeLoader {
            emu,
            heap,
            fs_last_addr,
            entry_point,
            dll_last_addr: Cell::new(0x10000000),
            dll_mmap: RefCell::new(BiMap::new()),
            ldr_data_map,
            ldr_list: RefCell::new(vec![]),
            dll_imports: RefCell::new(HashMap::new()),
            dll_exports: RefCell::new(HashMap::new()),
            dll_api_sets: RefCell::new(HashMap::new()),
        };
        // - init exports
        for _ in &pe.exports {
            // now is none
        }
        // load api set map
        loader.init_api_set_schema()?;
        // 加载 pe 到内存
        loader.load_memory(&pe, data, image_address as u32)?;
        // add pe to ldr_data_table
        loader.insert_to_dlls(file, image_address as u32)?;
        // add ntdll to ldr_data_table
        let last_dll_addr = loader.get_dll_of_last_addr();
        loader.emu.mem_map(last_dll_addr as u64, 0x9000, Protection::EXEC)?;
        loader.set_dll_of_last_addr(last_dll_addr + 0x9000);
        loader.load_dll("ntdll.dll", true)?;
        // import dll
        for lib in &pe.libraries {
            let dll_name = lib.to_lowercase();
            loader.load_dll(&dll_name, true)?;
        }
        // fix import table
        loader.fix_import_table(image_address, &pe)?;
        // init segmentation
        loader.init_gdtr(FS_SEGMENT_ADDR)?;

        // wow64
        let wow64 = loader.ntdll_GetProcAddress(loader.ntdll_LoadLibrary("ntdll.dll"), "Wow64Transition") as u64;
        let wow64_syscall_addr = last_dll_addr + 0x6000;
        loader.emu.mem_write(wow64, &wow64_syscall_addr.to_le_bytes())?;
        loader.emu.mem_write(wow64_syscall_addr as u64, &vec![0x0f, 0x05, 0xc3])?;

        let loader = Arc::new(loader);
        let loader_clone = loader.clone();
        loader.emu.add_insn_sys_hook(InsnSysX86::SYSCALL, wow64_syscall_addr as u64, (wow64_syscall_addr + 2) as u64, move |uc| {
            loader_clone.syscall(uc).unwrap();
        } )?;

        Ok(loader)
    }

    /* 加载dll */
    pub fn load_dll(&self, dll_name: &str, is_win32: bool) -> Result<u32, Box<dyn Error>>
    {
        let mut path = if is_win32 {
            format!("{}{}", SYSTEM32_PATH, dll_name)
        } else {
            format!("{}{}", SYSTEM_PATH, dll_name)
        };
        // TODO: 优化 dll 查找
        if !is_file_library(dll_name) {
            path += ".dll";
        }
        let dll_name = &dll_name.to_string();
        // 判断是否已加载
        {
            let dlls = self.dll_mmap.borrow();
            if dlls.contains_left(dll_name) {
                return Ok(*dlls.get_by_left(dll_name).unwrap());
            }
        }
        let base_addr = self.get_dll_of_last_addr();
        println!("[+] Loading {} to 0x{:x}", dll_name, base_addr);
        // Add dll to IAT
        let data = &load_file(&path)?[..];
        let pe = PE::parse(data)?;
        self.set_dll_of_last_addr(self.load_memory(&pe, data, base_addr)?);
        // Export
        {
            let mut imports = self.dll_imports.borrow_mut();
            let mut exports = self.dll_exports.borrow_mut();
            let mut exports_l:HashMap<String, u32> = HashMap::new();
            let mut exports_r: HashMap<u32, String> = HashMap::new();
            for export in &pe.exports {
                if let Some(name) = export.name {
                    exports_l.insert(name.to_owned(), base_addr + export.rva as u32);
                    exports_r.insert(base_addr + export.rva as u32, name.to_owned());
                }
            }
            imports.insert(dll_name.to_owned(), exports_l);
            exports.insert(dll_name.to_owned(), exports_r);
        }
        self.insert_to_dlls(dll_name, base_addr)?;

        // Resolve imported modules
        for import in &pe.libraries {
            let dll_name = import.to_lowercase();

            if dll_name.starts_with("api-") {
                if let Some(dlls) = self.dll_api_sets.borrow().get(&dll_name[..dll_name.len()-5]) {
                    for dll in dlls {
                        self.load_dll(dll, true)?;
                    }
                }
            } else {
                self.load_dll(&dll_name, true)?;
            }
        }

        // fix import table
        self.fix_import_table(base_addr as u64, &pe)?;

        // run Dll main
        Ok(base_addr)
    }

    fn fix_import_table(&self, base_addr: u64, pe: &PE) -> Result<(), Box<dyn Error>>
    {
        let imports = self.dll_imports.borrow();
        for import in &pe.imports {
            let import_name = import.name.as_ref().to_owned();
            let target_addr = base_addr + import.offset as u64;
            let target_dll = &import.dll.to_lowercase();
            if let Some(m) = imports.get(target_dll) {
                if let Some(addr) = m.get(&import_name) {
                    self.emu.mem_write(target_addr, as_u8_slice(addr))?;
                } else {
                    println!("[-] Not found {} on {} ===> {:08x}", import.name, import.dll.to_lowercase(), target_addr);
                }
            } else {
                // Import replacement api
                if target_dll.starts_with("api-") {
                    let mut found = false;
                    if let Some(dlls) = self.dll_api_sets.borrow().get(&target_dll[..target_dll.len()-5]) {
                        for dll in dlls {
                            // println!("wann {} ===> {}", dll, )
                            if let Some(m) = imports.get(dll) {
                                if let Some(addr) = m.get(&import_name) {
                                    found = true;
                                    self.emu.mem_write(target_addr, as_u8_slice(addr))?;
                                    break;
                                }
                            }
                        }
                    }
                    if !found {
                        println!("[-] Not found module {} for {} ===> {:08x}", import.dll.to_lowercase(), import.name, target_addr);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn ntdll_LoadLibrary(&self, module: &str) -> u32 {
        if let Ok(m) = self.load_dll(module, true) {
            m
        } else {
            0
        }
    }

    pub fn ntdll_GetProcAddress(&self, module: u32, proc_name: &str) -> u32 {
        let name = {
            if let Some(name) = self.dll_mmap.borrow().get_by_right(&module) {
                Some(name.clone())
            } else {
                None
            }
        };

        if let Some(dll_name) = name {
            let imports = self.dll_imports.borrow();
            *imports.get(&dll_name).unwrap().get(&proc_name.to_owned()).unwrap_or(&(0 as u32))
        } else {
            0
        }
    }

    #[inline]
    fn uc_alloc(emu: &CpuX86, heap: &Heap, size: u32) -> u32 {
        let (a, b) = heap.alloc(size);
        if let Some((addr, size)) = b {
            // need map
            if (emu.mem_map(addr as u64, size as usize, Protection::WRITE | Protection::READ)).is_ok() {
                a
            } else {
                0
            }
        } else {
            a
        }
    }
    
    pub fn malloc(&self, size: u32) -> u32 {
        PeLoader::uc_alloc(self.emu.borrow(), self.heap.borrow(), size)
    }

    pub fn free(&self, addr: u32) {
        self.heap.free(addr);
    }

    pub fn vm(&self) -> &CpuX86<'a> { self.emu.borrow() }

    #[inline]
    fn init_descriptor(desc: &mut SegmentDescriptor, base: u32, limit: u32, is_code: bool, ring: Ring) {
        let _type = if is_code { 0xb } else { 3 };
        let mut limit = limit;
        if limit> 0xfffff { desc.set_g(); limit >>= 12 }
        desc.set_base_limit(base, limit);

        // defaults
        desc.set_dpl(ring);
        desc.set_p();
        desc.set_db();  // 32 bit
        desc.set_type(_type);
        desc.set_s();
    }

    fn init_gdtr(&self, fs_address: u32) -> Result<(), Box<dyn Error>> {
        let (r_cs, r_ss, r_ds, r_es, r_fs) = (0x73, 0x88, 0x7b, 0x7b, 0x83);
        let mut gdt = [SegmentDescriptor::default(); 31];
        let gdtr: X86Mmr = X86Mmr {
            base: GDT_ADDRESS,
            limit: (31 * ::std::mem::size_of::<SegmentDescriptor>() - 1) as u32,
            ..X86Mmr::default()
        };

        Self::init_descriptor(&mut gdt[14], 0, 0xfffff000, true, Ring::Ring3);             // code segment
        Self::init_descriptor(&mut gdt[15], 0, 0xfffff000, false, Ring::Ring3);            // data segment
        Self::init_descriptor(&mut gdt[16], fs_address, 0xfff, false, Ring::Ring3);        // one page data segment simulate fs
        Self::init_descriptor(&mut gdt[17], 0, 0xfffff000, false, Ring::Ring0);            // ring 0 data

        self.emu.mem_map(GDT_ADDRESS, 0x10000, Protection::WRITE | Protection::READ)?;
        unsafe { self.emu.reg_write_generic(RegisterX86::GDTR, gdtr)?; }
        self.emu.mem_write(GDT_ADDRESS, as_u8_slice(&gdt))?;

        self.emu.reg_write_i32(RegisterX86::SS, r_ss)?;
        self.emu.reg_write_i32(RegisterX86::CS, r_cs)?;
        self.emu.reg_write_i32(RegisterX86::DS, r_ds)?;
        self.emu.reg_write_i32(RegisterX86::ES, r_es)?;
        self.emu.reg_write_i32(RegisterX86::FS, r_fs)?;

        Ok(())
    }

    fn init_api_set_schema(&self) -> Result<(), Box<dyn Error>> {
        // load ApiSetSchema
        let data = &load_file(format!("{}{}", SYSTEM_PATH, "ApiSetSchema.dll").as_str())?[..];
        let pe = PE::parse(data)?;
        for section in &pe.sections {
            if let Ok(".apiset") = section.name() {
                let end_of_raw_data = (section.pointer_to_raw_data + min(section.virtual_size, section.size_of_raw_data)) as usize;
                self.init_api_map(&data[section.pointer_to_raw_data as usize..end_of_raw_data])?;
                break;
            }
        }
        Ok(())
    }

    #[inline]
    fn read_unicode(data: &[u8], offset: usize, length: usize) -> Result<String, Box<dyn Error>> {
        let vec: Vec<u16> = data[offset..offset+length]
            .chunks_exact(2)
            .into_iter()
            .map(|a| u16::from_ne_bytes([a[0], a[1]]))
            .collect();
        Ok(WideString::from_vec(vec).to_string_lossy())
    }

    #[inline]
    fn init_api_map(&self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let api: api_set::ApiSetNamespace = data.pread(0)?;
        let mut last_entry_offset = api.entry_offset as usize;

        let mut api_sets = self.dll_api_sets.borrow_mut();

        for _ in 0..api.count {
            let entry: api_set::ApiSetNamespaceEntry = data.pread(last_entry_offset)?;
            last_entry_offset += ::std::mem::size_of::<api_set::ApiSetNamespaceEntry>();
            let origin = Self::read_unicode(data, entry.name_offset as usize, entry.name_length as usize)?;
            let mut last_value_offset = entry.value_offset as usize;

            let mut vec: Vec<String> = Vec::new();
            for _ in 0..entry.value_count {
                let value: api_set::ApiSetValueEntry = data.pread(last_value_offset)?;
                last_value_offset += ::std::mem::size_of::<api_set::ApiSetValueEntry>();

                let value_str = Self::read_unicode(data, value.value_offset as usize, value.value_length as usize)?;
                // let name_str = Self::read_unicode(data, value.name_offset as usize, value.name_length as usize)?;

                if !value_str.is_empty() {
                    vec.push(value_str.to_lowercase());
                }
            }
            api_sets.insert(origin[0..origin.len()-1].to_lowercase(), vec);
        }
        Ok(())
    }

    fn syscall(&self, uc: &Unicorn) -> Result<(), Box<dyn Error>>  {
        let esp = uc.reg_read(RegisterX86::ESP.to_i32())?;
        let eax = uc.reg_read_i32(RegisterX86::EAX.to_i32())?;

        // read stack
        let stack = uc.mem_read_as_vec(esp,  0x100)?;

        // return addr
        let return_addr: u32 = stack.pread(0)?;
        // ret
        let ret_n = uc.mem_read_as_vec(return_addr as u64, 3)?;
        let arg_nums:Option<u16> = if ret_n[0] == 0xc2 {
            Some(ret_n.pread(1)?)
        } else {
            None
        };
        // name


        println!(">>> call to {} return {:x} arg num is {}", eax, return_addr, arg_nums.unwrap() / 4);

        Ok(())
    }
}

// TODO: 可以优化为移位操作
fn get_protection(flag: u32) -> Protection
{
    // 可以优化为右移位 取三个位
    let mut protection = Protection::NONE;
    if (flag & IMAGE_SCN_MEM_READ) != 0 {
        protection = protection | Protection::READ;
    }
    if (flag & IMAGE_SCN_MEM_WRITE) != 0  {
        protection = protection | Protection::WRITE;
    }
    if (flag & IMAGE_SCN_MEM_EXECUTE) != 0 {
        protection = protection | Protection::EXEC;
    }
    protection
}

// for debug
fn get_protection_str(flag: u32) -> String
{
    // 可以优化为右移位 取三个位
    let mut protection = String::from("");
    if (flag & IMAGE_SCN_MEM_READ) != 0 {
        protection += "R,";
    }
    if (flag & IMAGE_SCN_MEM_WRITE) != 0  {
        protection += "W,";
    }
    if (flag & IMAGE_SCN_MEM_EXECUTE) != 0 {
        protection += "E";
    }
    protection
}

impl<'a> PeLoader<'a>
{
    /* 将pe映射到内存 */
    #[inline]
    fn load_memory(&self, pe: &PE, data: &[u8], to: u32) -> Result<u32, Box<dyn Error>>
    {
        let alignment = pe.header.optional_header.unwrap().windows_fields.section_alignment;
        let header_size: usize = ( 0x18
            + pe.header.dos_header.pe_pointer
            + pe.header.coff_header.size_of_optional_header as u32
            + pe.header.coff_header.number_of_sections as u32 * 0x28) as usize;

        let mut next_image_address = 0;
        let image_address = to;
        let emu = self.vm();

        emu.mem_map(image_address as u64, alignment as usize, Protection::READ)?;
        emu.mem_write(image_address as u64, &data[..header_size])?;

        for section in &pe.sections {
            let start = section.virtual_address as u64 + image_address as u64;
            let end_of_raw_data = (section.pointer_to_raw_data + min(section.virtual_size, section.size_of_raw_data)) as usize;
            let virtual_size = ((max(section.virtual_size, section.size_of_raw_data) - 1 ) / alignment + 1) * alignment;
            println!("MAP {:x} ===> {:x} {}", start, virtual_size, get_protection_str(section.characteristics));
            emu.mem_map(start, virtual_size as usize, get_protection(section.characteristics))?;
            if section.pointer_to_raw_data > 0 {
                emu.mem_write(start, &data[section.pointer_to_raw_data as usize..end_of_raw_data])?;
            }
            // last write address
            next_image_address = start as u32 + virtual_size;
        }

        // fix reloc table
        if let Some(header) = pe.header.optional_header {
            if let Some(reloc) = header.data_directories.get_base_relocation_table() {
                if let Ok(reloc_vec) = emu.mem_read_as_vec((image_address + reloc.virtual_address) as u64, reloc.size as usize) {
                    self.fix_reloc_table(&reloc_vec, image_address as u64, header.windows_fields.image_base)?;
                }
            }
        }
        Ok(next_image_address)
    }

    #[inline]
    fn fix_reloc_table(&self, bytes: &[u8], image_addr: u64, base: u64) -> Result<(), Box<dyn Error>> {
        let bytes_len = bytes.len();
        let mut col = 0;
        loop {
            let va = bytes.gread_with::<u32>(&mut col, scroll::LE)?;
            let size = bytes.gread_with::<u32>(&mut col, scroll::LE)?;
            let block_num = (size - 8) / 2;
            let mut blocks: Vec<u16> = Vec::with_capacity(block_num as usize);
            for _ in 0..block_num {
                blocks.push(bytes.gread_with::<u16>(&mut col, scroll::LE)?);
            }

            self.fix_reloc_addr(va, blocks, image_addr, base)?;

            if bytes_len <= col { break; }
        }
        Ok(())
    }

    #[inline]
    fn fix_reloc_addr(&self, va: u32, blocks: Vec<u16>, image_addr: u64, base: u64) -> Result<(), Box<dyn Error>> {
        let delta: i32 = image_addr as i32 - base as i32;
        let mut buf = [0u8; 0x1000];
        self.emu.mem_read(image_addr + va as u64, &mut buf)?;
        for block in &blocks {
            let ty = (*block & 0xf000) >> 12;
            let real: usize = (*block & 0xfff) as usize;
            if ty == 0 { continue; }
            let old:u32 = buf.pread(real)?;
            let new = (old as i32 + delta) as u32;
            buf.pwrite(new, real )?;
        }
        self.emu.mem_write(image_addr + va as u64, &buf)?;
        Ok(())
    }

    #[inline]
    fn set_dll_of_last_addr(&self, val: u32)
    {
        self.dll_last_addr.set(val as u64);
    }

    #[inline]
    fn get_dll_of_last_addr(&self) -> u32 { self.dll_last_addr.get() as u32 }

    #[inline]
    /* 插入dll 到 映射 */
    fn insert_to_dlls(&self, dll_path: &str, base_addr: u32) -> Result<(), Box<dyn Error>>
    {
        let filename = Path::new(dll_path).file_name().unwrap().to_string_lossy().to_string();
        {
            let mut dlls = self.dll_mmap.borrow_mut();
            dlls.insert(filename.clone(), base_addr);
        }
        self.add_ldr_data_table_entry(&filename)
    }

    /* 插入dll 到 LDR TODO: 未测试 */
    #[inline]
    fn add_ldr_data_table_entry(&self, dll_name: &str) -> Result<(), Box<dyn Error>>{
        let dll_base = {
            let dlls = self.dll_mmap.borrow();
            *dlls.get_by_left(&dll_name.to_owned()).unwrap()
        };
        let emu = self.vm();

        let path = format!("{}{}", SYSTEM32_PATH, dll_name);
        let ldr_table_entry_size = PebLdrTableEntry32::size();
        let base = self.malloc(ldr_table_entry_size);
        let mut ldr_table_entry = PebLdrTableEntry32Map{ data: PebLdrTableEntry32::new(dll_base, self.alloc_string(&path)?, self.alloc_string(&dll_name)?), base: base as u32 };

        let ldr = &self.ldr_data_map;
        let mut ldr_list = self.ldr_list.borrow_mut();
        if ldr_list.is_empty() {
            let mut flink:PebLoaderData32Map = (*ldr).clone();
            ldr_table_entry.data.in_load_order_links[0] = flink.data.in_load_order_module_list[0];
            ldr_table_entry.data.in_memory_order_links[0] = flink.data.in_memory_order_module_list[0];
            ldr_table_entry.data.in_initialization_order_links[0] = flink.data.in_initialization_order_module_list[0];

            flink.data.in_load_order_module_list[0] = ldr_table_entry.base;
            flink.data.in_memory_order_module_list[0] = ldr_table_entry.base + 2 * 4;
            flink.data.in_initialization_order_module_list[0] = ldr_table_entry.base + 4 * 4;

            emu.mem_write(flink.base as u64, as_u8_slice(&flink.data))?;
        } else{
            let mut flink = (*ldr_list.last().unwrap()).clone();
            ldr_table_entry.data.in_load_order_links[0] = flink.data.in_load_order_links[0];
            ldr_table_entry.data.in_memory_order_links[0] = flink.data.in_memory_order_links[0];
            ldr_table_entry.data.in_initialization_order_links[0] = flink.data.in_initialization_order_links[0];

            flink.data.in_load_order_links[0] = ldr_table_entry.base;
            flink.data.in_memory_order_links[0] = ldr_table_entry.base + 2 * 4;
            flink.data.in_initialization_order_links[0] = ldr_table_entry.base + 4 * 4;

            emu.mem_write(flink.base as u64, as_u8_slice(&flink.data))?;
        };

        let mut blink = (*ldr).clone();
        ldr_table_entry.data.in_load_order_links[1] = blink.data.in_load_order_module_list[1];
        ldr_table_entry.data.in_memory_order_links[1] = blink.data.in_memory_order_module_list[1];
        ldr_table_entry.data.in_initialization_order_links[1] = blink.data.in_initialization_order_module_list[1];

        blink.data.in_load_order_module_list[1] = ldr_table_entry.base;
        blink.data.in_memory_order_module_list[1] = ldr_table_entry.base + 2 * 4;
        blink.data.in_initialization_order_module_list[1] = ldr_table_entry.base + 4 * 4;

        emu.mem_write(blink.base as u64, as_u8_slice(&blink.data))?;
        emu.mem_write(ldr_table_entry.base as u64, as_u8_slice(&ldr_table_entry))?;

        ldr_list.push(ldr_table_entry);

        Ok(())
    }

    // TODO: 未测试
    #[inline]
    fn alloc_string(&self, string: &str) -> Result<WinUnicodeSting32, Box<dyn Error>> {
        let mut string:Vec<u16> = string.encode_utf16().collect();
        string.push(0);
        let string = string.as_byte_slice();
        let emu = self.vm();
        let addr = self.malloc(string.len() as u32);
        emu.mem_write(addr as u64, &string)?;
        Ok(WinUnicodeSting32::new((string.len() - 2) as u16, addr as u32))
    }
}

#[inline]
fn is_file_library(file: &str) -> bool
{
    /* TODO: 优化后缀判断 */
    [".dll", ".exe", ".sys", ".drv"].contains(&&file[file.len() - 4..])
}