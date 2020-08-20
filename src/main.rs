pub mod windows;
pub mod loader;
pub mod utils;
pub mod heap;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate error_chain;

quick_main!(run);
error_chain! {
    foreign_links {
        Io(::std::io::Error);
        BinErr(goblin::error::Error);
        UcErr(unicorn::Error);
    }
}


fn run() -> Result<()> {
    const FILE_NAME: &str = "files/x86_hello.exe";
    loader::pe::PeLoader::new(FILE_NAME).unwrap();

    println!("[+] Load all dlls ok.");

    // emu.emu_start(entry_point, 0, 10 * unicorn::SECOND_SCALE, 12)?;

    // println!("eip is {:x}", emu.reg_read(RegisterX86::EIP)?);

    Ok(())
}