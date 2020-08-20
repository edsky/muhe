use unicorn::{Protection, CpuX86, RegisterX86, Cpu};
use goblin::pe::PE;
use crate::heap::uc_alloc;
use crate::utils::{as_u8_slice, load_file};
use std::path::Path;
use std::cmp::{min, max};
use std::collections::HashMap;
use byte_slice_cast::AsByteSlice;
use std::error::Error;
use std::cell::{Cell, RefCell};
use goblin::pe::section_table::{IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE};
use crate::windows::structs::{PebLoaderData32Map, ThreadInformationBlock32, ProcessEnvironmentBlock32};
use crate::windows::structs::{PebLoaderData32, WinUnicodeSting32, PebLdrTableEntry32, PebLdrTableEntry32Map};
use std::borrow::Borrow;

pub struct PeLoader<'a> {
    emu: Box<CpuX86<'a>>,               // unicorn
    fs_last_addr: u64,                  // fs 结构最后地址
    pub entry_point: u64,               // oep
    ldr_data_map: PebLoaderData32Map,   // peb
    ldr_list: RefCell<Vec<PebLdrTableEntry32Map>>,// peb table
    dll_last_addr: Cell<u64>,           // dll module last address
    dll_mmap: RefCell<HashMap<String,u32>>,// dll映射表, 名称 <-> 基地址
    dll_imports: RefCell<HashMap<String, HashMap<String, u32>>>,   // 导入表, 名称 <-> [函数名 <-> 地址]
}

impl<'a> PeLoader<'a>
{
    pub fn new(file: &str) -> Result<PeLoader, Box<dyn Error>> {
        let emu = Box::new(CpuX86::new(unicorn::Mode::MODE_32)?);
        // alloc
        emu.mem_map(0x5000000, 0x20000, Protection::READ | Protection::WRITE)?;
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
        let process_heap = uc_alloc(&emu, 0x100)?;
        let peb_data = ProcessEnvironmentBlock32::new(fs_last_addr, process_heap as u32);
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
            fs_last_addr,
            entry_point,
            dll_last_addr: Cell::new(0x10000000),
            dll_mmap: RefCell::new(HashMap::new()),
            ldr_data_map,
            ldr_list: RefCell::new(vec![]),
            dll_imports: RefCell::new(HashMap::new())
        };
        // - init exports
        for _ in &pe.exports {
            // now is none
        }
        // 加载 pe 到内存
        loader.load_memory(&pe, data, image_address as u32)?;
        // add pe to ldr_data_table
        loader.insert_to_dlls(file, image_address as u32)?;
        // add ntdll to ldr_data_table
        loader.load_dll("ntdll.dll")?;
        // import dll
        for lib in pe.libraries {
            let dll_name = lib.to_lowercase();
            loader.load_dll(&dll_name)?;
        }
        {
            let imports = loader.dll_imports.borrow();
            for import in pe.imports {
                if let Some(addr) = imports.get(&import.dll.to_lowercase()).unwrap().get(&*import.name) {
                    loader.emu.mem_write(image_address + import.offset as u64, as_u8_slice(addr))?;
                } else {
                    println!("[-] Not found {} ===> {:x}", import.name, import.offset);
                }
            }
        }

        Ok(loader)
    }

    /* 加载dll */
    pub fn load_dll(&self, dll_name: &str) -> Result<(), Box<dyn Error>>
    {
        let mut path = format!("{}/{}", SYSTEM_PATH, dll_name);
        // TODO: 优化 dll 查找
        if !is_file_library(dll_name) {
            path += ".dll";
        }
        // 判断是否已加载
        {
            let dlls = self.dll_mmap.borrow();
            if dlls.contains_key(dll_name) {
                return Ok(());
            }
        }
        let base_addr = self.get_dll_of_last_addr();
        println!("[+] Loading {} to 0x{:x}", path, base_addr);
        // Add dll to IAT
        let data = &load_file(&path)?[..];
        let pe = PE::parse(data)?;
        self.set_dll_of_last_addr(self.load_memory(&pe, data, base_addr)?);
        // Export
        {
            let mut imports = self.dll_imports.borrow_mut();
            let mut exports:HashMap<String, u32> = HashMap::new();
            for export in pe.exports {
                if let Some(name) = export.name {
                    exports.insert(name.to_owned(), base_addr + export.rva as u32);
                }
            }
            imports.insert(dll_name.to_owned(), exports);
        }
        self.insert_to_dlls(dll_name, base_addr)?;

        // 解析导入
        for import in pe.libraries {
            let dll_name = import.to_lowercase();

            if dll_name.starts_with("api-") {

            } else {
                self.load_dll(&dll_name)?;
            }
        }

        // run Dll main
        Ok(())
    }
}

const FS_SEGMENT_ADDR: u32 = 0x6000;
const FS_SEGMENT_SIZE: u32 = 0x6000;
const SYSTEM_PATH: &str = "./files/rootfs/Windows/System32/";

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
        let emu = &self.emu;

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
        Ok(next_image_address)
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
            *dlls.get(dll_name).unwrap()
        };
        let emu = self.emu.borrow();

        let path = format!("{}/{}", SYSTEM_PATH, dll_name);
        let ldr_table_entry_size = PebLdrTableEntry32::size();
        let base = uc_alloc(emu, ldr_table_entry_size as u64)?;
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
        let emu = self.emu.borrow();
        let addr = uc_alloc(emu, string.len() as u64)?;
        emu.mem_write(addr, &string)?;
        Ok(WinUnicodeSting32::new((string.len() - 2) as u16, addr as u32))
    }
}

#[inline]
fn is_file_library(file: &str) -> bool
{
    /* TODO: 优化后缀判断 */
    [".dll", ".exe", ".sys", ".drv"].contains(&&file[file.len() - 4..])
}