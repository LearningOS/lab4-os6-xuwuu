//! File and filesystem-related syscalls

use crate::fs;
use crate::fs::open_file;
use crate::fs::OpenFlags;
use crate::fs::Stat;
use crate::mm::{translated_byte_buffer, translated_str, UserBuffer};
use crate::task::current_task;
use crate::task::current_user_token;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

// YOUR JOB: 扩展 easy-fs 和内核以实现以下三个 syscall
pub fn sys_fstat(_fd: usize, _st: *mut Stat) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if _fd >= inner.fd_table.len() || inner.fd_table[_fd].is_none() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[_fd] {
        let mut st = translated_byte_buffer(token, _st as *const u8, core::mem::size_of::<Stat>());
        let _st = st[0].as_mut_ptr() as *mut Stat;
        let (ino, mode, nlink) = file.fstat();
        let dev: u64 = 0;
        let pad: [u64; 7] = [0; 7];
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        unsafe {
            *_st = Stat {
                dev,
                ino,
                mode,
                nlink,
                pad,
            }
        }
        return 0;
    }
    drop(inner);
    -1
}

pub fn sys_linkat(_old_name: *const u8, _new_name: *const u8) -> isize {
    let token = current_user_token();
    let old_path = translated_str(token, _old_name);
    let new_path = translated_str(token, _new_name);
    if old_path == new_path {
        return -1;
    }
    fs::linkat(old_path.as_str(), new_path.as_str())
}

pub fn sys_unlinkat(_name: *const u8) -> isize {
    let token = current_user_token();
    let name = translated_str(token, _name);
    fs::unlinkat(name.as_str())
}
