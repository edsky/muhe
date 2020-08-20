use std::sync::Mutex;
use unicorn::CpuX86;
use std::error::Error;
/*
 * 实现自定义 堆管理
 */
// TODO: 分配地址
lazy_static! {
    static ref LAST_ADDR: Mutex<u32> = Mutex::new(0x5000000);
}

#[inline]
pub fn uc_alloc(_emu: &CpuX86, size: u64) -> Result<u64, Box<dyn Error>> {
    let mut last_addr = LAST_ADDR.lock().unwrap();

    *last_addr = *last_addr + size as u32;
    Ok((*last_addr) as u64)
}