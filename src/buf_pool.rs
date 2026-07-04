
use crossbeam_queue::ArrayQueue;
use lazy_static::lazy_static;
use std::ops::{Deref, DerefMut};
use bytes::Buf;

const POOL_SIZE: usize = 10000;
const BUF_CAPACITY: usize = 8192;

lazy_static! {
    
    static ref VEC_POOL: ArrayQueue<Vec<u8>> = ArrayQueue::new(POOL_SIZE);
}

pub struct PooledVec {
    vec: Option<Vec<u8>>,
}

impl PooledVec {
    pub fn new() -> Self {
        let vec = if let Some(mut v) = VEC_POOL.pop() {
            v.clear();
            v
        } else {
            Vec::with_capacity(BUF_CAPACITY)
        };
        Self { vec: Some(vec) }
    }
    
    pub fn new_with_size(size: usize) -> Self {
        let mut v = Self::new();
        v.resize(size, 0);
        v
    }
}

impl Drop for PooledVec {
    fn drop(&mut self) {
        if let Some(vec) = self.vec.take() {
            if vec.capacity() >= BUF_CAPACITY {
                let _ = VEC_POOL.push(vec);
            }
        }
    }
}

impl Deref for PooledVec {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        self.vec.as_ref().unwrap()
    }
}

impl DerefMut for PooledVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.vec.as_mut().unwrap()
    }
}


impl Buf for PooledVec {
    fn remaining(&self) -> usize {
        self.vec.as_ref().unwrap().len()
    }
    fn chunk(&self) -> &[u8] {
        self.vec.as_ref().unwrap().as_slice()
    }
    fn advance(&mut self, cnt: usize) {
        self.vec.as_mut().unwrap().drain(0..cnt);
    }
}

pub fn get_vec() -> Vec<u8> {
    if let Some(mut vec) = VEC_POOL.pop() {
        vec.clear();
        vec
    } else {
        Vec::with_capacity(BUF_CAPACITY)
    }
}

pub fn return_vec(vec: Vec<u8>) {
    if vec.capacity() >= BUF_CAPACITY {
        let _ = VEC_POOL.push(vec);
    }
}
