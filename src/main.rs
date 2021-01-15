pub mod windows;
pub mod loader;
pub mod utils;
pub mod heap;
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate error_chain;

use unicorn::{Cpu, RegisterX86, Register};
use unicorn::InsnSysX86::{SYSCALL, SYSENTER};
use unicorn::CodeHookType::{CODE, BLOCK};

// quick_main!(run);
error_chain! {
    foreign_links {
        Io(::std::io::Error);
        BinErr(goblin::error::Error);
        UcErr(unicorn::Error);
    }
}


fn main() -> Result<()> {
    const FILE_NAME: &str = "files/x86_hello.exe";
    let pe = loader::pe::PeLoader::new(FILE_NAME).unwrap();
    let vm = pe.vm();

    println!("[+] Load all dlls ok.");
    vm.emu_start(pe.entry_point, 0, 0, 10)?;
    println!("eip is {:x}", vm.reg_read(RegisterX86::EIP)?);
    println!("eax is {:x}", vm.reg_read(RegisterX86::EAX)?);
    Ok(())
}