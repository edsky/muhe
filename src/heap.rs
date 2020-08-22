use std::sync::Mutex;
use unicorn::CpuX86;
use std::error::Error;
use std::cell::{Cell, RefCell};
use std::borrow::Borrow;
use crate::utils::align;
use std::collections::HashMap;
/*
 * 实现自定义 简单堆管理/ TODO: 使用 mimalloc
 */
pub struct Heap
{
    start_address: u32,
    end_address: u32,
    current_alloc: Cell<u32>,
    current_use: Cell<u32>,
    chunks: RefCell<HashMap<u32, (u32, bool)>>,     // 地址 <-> (大小, 使用?)
}

const PAGE_SIZE:u32 = 0x1000;

impl Heap
{
    pub fn new(start: u32, end: u32) -> Heap {
        Heap {
            start_address: start,
            end_address: end,
            current_alloc: Cell::new(0),
            current_use: Cell::new(0),
            chunks: RefCell::new(HashMap::new()),
        }
    }

    #[inline]
    fn get_first_match(&self, size: u32) -> Option<(u32, u32)> {
        if let Some(chunk) = self.chunks.borrow().iter().filter(|&(_, &(v, is_use))| {
            v > size && !is_use
        }).min_by(|&(_, &(a, _)), &(_, &(b, _))|{
            a.cmp(&b)
        }) {
            Some((*chunk.0, (*chunk.1).0))
        } else {
            None
        }
    }

    // 返回地址和需要map的地址&大小
    pub fn alloc(&self, size: &u32) -> (u32, Option<(u32, u32)>){
        let size = align(&size, &4);
        // 判断大小最符合的
        if let Some(v) = self.get_first_match(size) {
            let mut chunks = self.chunks.borrow_mut();
            chunks.insert(v.0, (v.1, true));
            return (v.0, None);
        }
        // 判断是否需要申请
        let current_use = {
            self.current_use.get()
        };
        let current_alloc = {
            self.current_alloc.get()
        };
        if current_use + size > current_alloc {
            let real_size = align(&size, &PAGE_SIZE);
            if self.start_address + current_use + real_size > self.end_address {
                (0, None)
            } else {
                let addr = self.start_address + current_use;
                self.chunks.borrow_mut().insert(
                    addr,
                    (size, true)
                );
                self.current_alloc.set(current_alloc + real_size);
                self.current_use.set(current_use + size);

                (addr, Some((self.start_address + current_alloc, real_size)))
            }
        } else {
            let addr = self.start_address + current_use;
            self.current_use.set(current_use + size);
            self.chunks.borrow_mut().insert(
                addr,
                (size, true)
            );
            (addr, None)
        }
    }

    // 地址大小
    pub fn size(&self, addr: u32) -> u32 {
        if let Some(chunk) = self.chunks.borrow().get(&addr) {
            chunk.0
        } else {
            0
        }
    }

    // 释放
    pub fn free(&self, addr: u32) -> bool {
        if let Some(chunk) = self.chunks.borrow_mut().get_mut(&addr) {
            chunk.1 = true;
            true
        } else {
            false
        }
    }
}