use memmap2::{Mmap, MmapOptions};
use std::fs::File;
use std::error::Error;

/*
 转换结构到 &vec![u8]
 */
pub fn as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }
}

/*
 加载文件到内存
 */
#[inline]
pub fn load_file(path: &str) -> Result<Mmap, Box<dyn Error>>
{
    let file = File::open(path)?;
    Ok( unsafe { MmapOptions::new().map(&file)? } )
}

/*
 值向上对齐
 */
#[inline]
pub fn align(value: &u32, size: &u32) -> u32
{
    let v: u32 = *value;
    let s: u32 = *size;
    if v % s == 0 {
        v
    }
    else {
        (v / s + 1) * s
    }
}