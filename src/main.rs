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

    // 代码
    // vm.add_code_hook();
    // 异常
    // vm.add_intr_hook();
    // 内存
    // vm.add_mem_hook();

    let x86_code32: Vec<u8> = vec![0xFF, 0xD0];
    vm.mem_write(pe.entry_point, &x86_code32);
    let addrof = pe.ntdll_GetProcAddress(pe.ntdll_LoadLibrary("ntdll.dll"), "NtCreateFile");
    println!("addr of is {:x}", addrof);
    vm.reg_write_i32(RegisterX86::EAX, addrof as i32);

    vm.add_code_hook(CODE, addrof as u64, (addrof + 0x10) as u64, |emu, a, b| {
        println!("hook: eip is {:x} {:x}, {:x}", emu.reg_read(RegisterX86::EIP.to_i32()).unwrap(), a, b);

        emu.emu_stop();
    });

    let data = &mut [0; 0x10];
    vm.mem_read(addrof as u64, data);
    println!("data is {:?}", data);

    // vm.add_insn_sys_hook(SYSENTER, addrof as u64, (addrof + 0x11) as u64, |emu| {
    //     println!("callback is call, {:x}", emu.reg_read(RegisterX86::EIP.to_i32()).unwrap());
    // });
    println!("[+] Load all dlls ok.");
    vm.emu_start(pe.entry_point, 0, 0, 10)?;
    println!("eip is {:x}", vm.reg_read(RegisterX86::EIP)?);
    println!("eax is {:x}", vm.reg_read(RegisterX86::EAX)?);
    Ok(())
}