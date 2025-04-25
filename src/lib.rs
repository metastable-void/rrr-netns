#![warn(missing_docs)]
//! Utilities for managing Network Namespaces in Linux.

use std::ffi::{c_int, CStr, CString};
use std::mem::MaybeUninit;
use std::cell::Cell;

/// The directory path to save network namespaces.
pub const NETNS_RUN_DIR: &CStr = assume_cstr(b"/var/run/netns\0");

/// Path to our own network namespace.
pub const NETNS_SELF: &CStr = assume_cstr(b"/proc/self/ns/net\0");

thread_local! {
    static LAST_ERR: Cell<ErrorCode> = Cell::new(ErrorCode::NoError);
}

/// error codes of this crate.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum ErrorCode {
    /// No error
    NoError = 0,

    /// Failed to create a file.
    FileCreateFailed = 1,

    /// Failed to mount.
    MountFailed = 2,

    /// Failed to read a file.
    FileReadFailed = 3,

    /// Failed to create a namespace.
    NsCreateFailed = 4,

    /// Invalid data.
    InvalidData = 5,

    /// Failed to unmount.
    UnmountFailed = 6,

    /// Failed to delete a file.
    FileDeleteFailed = 7,

    /// Failed to set a namespace.
    NsSetFailed = 8,
}

fn last_err_set(e: ErrorCode) {
    LAST_ERR.set(e);
}

/// Gets the last error code on a thread-local manner.
pub fn last_err_get() -> ErrorCode {
    LAST_ERR.get()
}

const fn assume_cstr<'a>(bytes: &'a [u8]) -> &'a CStr {
    match CStr::from_bytes_until_nul(bytes) {
        Ok(s) => s,
        Err(_) => panic!("Non-terminated C str"),
    }
}

fn touch(path: &CStr) -> c_int {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL, 0) };
    if fd < 0 {
        log::error!("Failed to create a file at path '{}'", path.to_string_lossy());
        last_err_set(ErrorCode::FileCreateFailed);
        return -1;
    }
    unsafe { libc::close(fd) };
    0
}

fn bind_mount(from_path: &CStr, to_path: &CStr) -> c_int {
    if 0 > unsafe { libc::mount(from_path.as_ptr(), to_path.as_ptr(), b"none\0".as_ptr() as *const i8, libc::MS_BIND, std::ptr::null()) } {
        log::error!("Failed to bind-mount '{}' into '{}'", from_path.to_string_lossy(), to_path.to_string_lossy());
        last_err_set(ErrorCode::MountFailed);
        return -1;
    }

    0
}

/// Returns the nsid of the current network namespace.
/// 
/// On failure, zero is returned.
pub fn netns_id_get_current() -> libc::ino_t {
    let mut statbuf: MaybeUninit<libc::stat> = MaybeUninit::uninit();

    if 0 > unsafe { libc::stat(NETNS_SELF.as_ptr(), statbuf.as_mut_ptr()) } {
        log::error!("Failed to get the nsid of the current network namespace");
        last_err_set(ErrorCode::FileReadFailed);
        return 0;
    }

    let statbuf = unsafe { statbuf.assume_init() };
    let major = libc::major(statbuf.st_dev);
    let minor = libc::minor(statbuf.st_dev);
    assert_eq!(major, 0, "Major device number should be 0");
    assert_eq!(minor, 4, "Minor device number should be 4");

    last_err_set(ErrorCode::NoError);
    statbuf.st_ino
}

/// Enters a newly created network namespace and returns the id of it.
/// 
/// On failure, zero is returned.
pub fn netns_unshare() -> libc::ino_t {
    let nsid_pre = netns_id_get_current();
    if nsid_pre == 0 {
        // failure
        return 0;
    }

    if 0 > unsafe { libc::unshare(libc::CLONE_NEWNET) } {
        // failure
        log::error!("Failed to create and enter a new network namespace");
        last_err_set(ErrorCode::NsCreateFailed);
        return 0;
    }

    let nsid_post = netns_id_get_current();
    if nsid_post == 0 {
        // failure
        return 0;
    }

    assert_ne!(nsid_post, nsid_pre, "New and old nsids should be different");
    last_err_set(ErrorCode::NoError);
    nsid_post
}

/// Saves the current netns with a name.
pub fn netns_save_current(name: &CStr) -> c_int {
    let mut path: Vec<u8> = Vec::new();
    path.extend_from_slice(NETNS_RUN_DIR.to_bytes());
    path.push(b'/');
    path.extend_from_slice(name.to_bytes());
    path.push(b'\0');

    let path = unsafe { CString::from_vec_unchecked(path) };
    if 0 > touch(&path) {
        return -1;
    }

    if 0 > bind_mount(NETNS_SELF, &path) {
        return -1;
    }

    last_err_set(ErrorCode::NoError);
    0
}

/// Deletes a saved netns by name.
pub fn netns_saved_delete(name: &CStr) -> c_int {
    let mut path: Vec<u8> = Vec::new();
    path.extend_from_slice(NETNS_RUN_DIR.to_bytes());
    path.push(b'/');
    path.extend_from_slice(name.to_bytes());
    path.push(b'\0');

    let path = unsafe { CString::from_vec_unchecked(path) };
    if 0 > unsafe { libc::umount2(path.as_ptr(), libc::UMOUNT_NOFOLLOW) } {
        log::error!("Failed to unmount");
        last_err_set(ErrorCode::UnmountFailed);
        return -1;
    }

    if 0 > unsafe { libc::unlink(path.as_ptr()) } {
        log::error!("Failed to unlink");
        last_err_set(ErrorCode::FileDeleteFailed);
        return -1;
    }

    last_err_set(ErrorCode::NoError);
    0
}

/// Returns the nsid of a given namespace, which is saved before.
/// 
/// On failure, zero is returned.
pub fn netns_saved_get(name: &CStr) -> libc::ino_t {
    let mut path: Vec<u8> = Vec::new();
    path.extend_from_slice(NETNS_RUN_DIR.to_bytes());
    path.push(b'/');
    path.extend_from_slice(name.to_bytes());
    path.push(b'\0');

    let path = unsafe { CString::from_vec_unchecked(path) };

    let mut statbuf: MaybeUninit<libc::stat> = MaybeUninit::uninit();
    if 0 > unsafe { libc::stat(path.as_ptr(), statbuf.as_mut_ptr()) } {
        log::error!("Failed to get the nsid of the saved network namespace");
        last_err_set(ErrorCode::FileReadFailed);
        return 0;
    }

    let statbuf = unsafe { statbuf.assume_init() };
    let major = libc::major(statbuf.st_dev);
    let minor = libc::minor(statbuf.st_dev);
    if major != 0 || minor != 4 {
        log::error!("Not a netns file");
        last_err_set(ErrorCode::InvalidData);
        return 0;
    }

    last_err_set(ErrorCode::NoError);
    statbuf.st_ino
}

/// Keeps a reference to the current network namespace as of the creation.
#[derive(Debug)]
#[repr(transparent)]
pub struct NetnsSavepoint {
    fd: c_int,
}

/// Returns true if the savepoint is valid
pub fn netns_savepoint_is_valid(savepoint: &NetnsSavepoint) -> bool {
    savepoint.fd >= 0
}

/// Creates a new netns savepoint
pub fn netns_savepoint_new() -> NetnsSavepoint {
    NetnsSavepoint { fd: unsafe { libc::open(NETNS_SELF.as_ptr(), libc::O_RDONLY, 0) } }
}

/// Closes the savepoint without restoring from it
pub fn netns_savepoint_destroy(savepoint: &NetnsSavepoint) {
    if !netns_savepoint_is_valid(savepoint) {
        return;
    }

    unsafe { libc::close(savepoint.fd) };
    last_err_set(ErrorCode::NoError);
}

/// Restores a netns from the savepoint
pub fn netns_savepoint_restore(savepoint: &NetnsSavepoint) -> c_int {
    if !netns_savepoint_is_valid(savepoint) {
        log::warn!("Invalid netns savepoint");
        last_err_set(ErrorCode::InvalidData);
        return -1;
    }

    if 0 > unsafe { libc::setns(savepoint.fd, libc::CLONE_NEWNET) } {
        log::error!("Failed to restore netns savepoint");
        last_err_set(ErrorCode::NsSetFailed);
        return -1;
    }

    last_err_set(ErrorCode::NoError);
    0
}

#[doc(hidden)]
pub fn demo() {
    let name = assume_cstr(b"rrr-testns\0");

    let orig_nsid = netns_id_get_current();
    assert_ne!(0, orig_nsid);
    println!("Original nsid: {}", orig_nsid);

    let sp = netns_savepoint_new();
    assert!(netns_savepoint_is_valid(&sp));

    let new_nsid = netns_unshare();
    assert_ne!(0, new_nsid);
    assert_eq!(new_nsid, netns_id_get_current());
    println!("New nsid: {}", new_nsid);

    assert_eq!(0, netns_save_current(name));
    assert_eq!(0, netns_savepoint_restore(&sp));
    assert_eq!(orig_nsid, netns_id_get_current());

    netns_savepoint_destroy(&sp);

    assert_eq!(new_nsid, netns_saved_get(name));

    assert_eq!(0, netns_saved_delete(name));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test1() {
        demo();
    }
}
