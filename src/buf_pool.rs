use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use lazy_static::lazy_static;
use std::ops::{Deref, DerefMut};

const POOL_SIZE: usize = 10000;
const BUF_CAPACITY: usize = 8192;

lazy_static! {
    static ref BYTES_MUT_POOL: ArrayQueue<BytesMut> = ArrayQueue::new(POOL_SIZE);
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

pub struct PooledBytesMut {
    buf: Option<BytesMut>,
}

impl PooledBytesMut {
    pub fn new() -> Self {
        let buf = if let Some(mut b) = BYTES_MUT_POOL.pop() {
            b.clear();
            b
        } else {
            BytesMut::with_capacity(BUF_CAPACITY)
        };
        Self { buf: Some(buf) }
    }
}

impl Drop for PooledBytesMut {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            if buf.capacity() >= BUF_CAPACITY {
                let _ = BYTES_MUT_POOL.push(buf);
            }
        }
    }
}

impl Deref for PooledBytesMut {
    type Target = BytesMut;
    fn deref(&self) -> &Self::Target {
        self.buf.as_ref().unwrap()
    }
}

impl DerefMut for PooledBytesMut {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().unwrap()
    }
}
