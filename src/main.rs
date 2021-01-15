#![feature(option_unwrap_none)]

pub mod windows;
pub mod loader;
pub mod utils;
pub mod heap;
#[allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate error_chain;

use unicorn::{Cpu, RegisterX86};
#[allow(unused_imports)]
use unicorn::InsnSysX86::{SYSCALL, SYSENTER};
#[allow(unused_imports)]
use unicorn::CodeHookType::{CODE, BLOCK};

use zydis::*;
#[allow(unused_imports)]
use byte_slice_cast::AsByteSlice;

// quick_main!(run);
error_chain! {
    foreign_links {
        Io(::std::io::Error);
        BinErr(goblin::error::Error);
        UcErr(unicorn::Error);
        ZydisErr(zydis::Status);
    }
}


fn main() -> Result<()> {
    const FILE_NAME: &str = "files/x86_hello.exe";
    let pe = loader::pe::PeLoader::new(FILE_NAME).unwrap();
    let vm = pe.vm();

    let formatter = Formatter::new(FormatterStyle::INTEL)?;
    let decoder = Decoder::new(MachineMode::LONG_COMPAT_32, AddressWidth::_32)?;
    let mut code = [0u8; 10];
    let mut buffer = [0u8; 200];
    let mut buffer = OutputBuffer::new(&mut buffer[..]);

    println!("[+] Load all dlls ok.");
    println!("[+] entry is 0x{:x}", pe.entry_point);
    let mut eip = pe.entry_point;

    loop {
        vm.mem_read(eip, &mut code)?;
        let ins = decoder.decode(&code)?.unwrap();
        formatter.format_instruction(&ins, &mut buffer, Some(eip), None)?;

        println!("0x{:08X} {}", eip, buffer);

        if vm.emu_start(eip, 0, 0, 1).is_err() {
            break;
        }
        eip = vm.reg_read(RegisterX86::EIP)?;
    }
    Ok(())
}