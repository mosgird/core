//! Locked memory for secrets. This is the only module in the workspace
//! that may use `unsafe`; `scripts/check_unsafe.sh` enforces that.
//!
//! A [`LockedBox`] holds `N` secret bytes in memory that:
//! - is page-aligned and a whole number of pages, so the lock covers it
//!   and nothing else shares its pages;
//! - is locked into RAM, so it is not written to swap (`mlock`,
//!   `VirtualLock`);
//! - on Linux, Android and FreeBSD, is left out of core dumps
//!   (`MADV_DONTDUMP`, `MADV_NOCORE`);
//! - never moves, so no stale copy is left when the box is moved;
//! - is zeroed, then unlocked and freed, on drop.
//!
//! Not yet done, and listed in README.md: guard pages around the
//! allocation, and `mprotect` to make it unreadable between uses.
//!
//! Under Miri and Kani the system calls are skipped, so that both
//! tools can check the allocation, the pointer use and the arithmetic.
//! The system calls themselves are covered by the tests on each
//! platform in CI.

use core::ptr::NonNull;
use std::alloc::{Layout, alloc_zeroed, dealloc};

use zeroize::Zeroize;

/// Why a [`LockedBox`] could not be created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The size, rounded up to whole pages, does not fit a `Layout`.
    TooLarge,
    /// The allocator returned no memory.
    OutOfMemory,
    /// The system refused to lock the memory, for example because the
    /// limit on locked memory (`RLIMIT_MEMLOCK`) is reached.
    LockFailed,
}

/// `N` secret bytes in locked memory. See the module documentation.
///
/// It has no `Clone`, `Debug` or `PartialEq`, for the same reasons as
/// `mosgird_crypto::Secret`.
pub struct LockedBox<const N: usize> {
    ptr: NonNull<[u8; N]>,
    layout: Layout,
}

// SAFETY: a LockedBox owns its allocation exclusively, like a Box, and
// hands out references only through &self and &mut self.
unsafe impl<const N: usize> Send for LockedBox<N> {}
// SAFETY: shared references give only &[u8; N], which is Sync.
unsafe impl<const N: usize> Sync for LockedBox<N> {}

impl<const N: usize> LockedBox<N> {
    /// Allocates `N` zero bytes in locked memory.
    ///
    /// # Errors
    ///
    /// See [`Error`]. Nothing is left allocated on error.
    pub fn new() -> Result<Self, Error> {
        let layout = page_layout(N, page_size())?;
        // SAFETY: the layout has a non-zero size (page_layout rounds up
        // to at least one page).
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(bytes) = NonNull::new(raw) else {
            return Err(Error::OutOfMemory);
        };
        if !os::lock(bytes, layout.size()) {
            // SAFETY: allocated just above with this layout, not yet
            // shared, and all zero, so nothing secret is freed.
            unsafe { dealloc(raw, layout) };
            return Err(Error::LockFailed);
        }
        os::exclude_from_dumps(bytes, layout.size());
        Ok(Self {
            ptr: bytes.cast(),
            layout,
        })
    }

    /// Allocates locked memory and fills it in place with `fill`.
    ///
    /// # Errors
    ///
    /// As for [`LockedBox::new`]. `fill` is not called on error.
    pub fn new_with(fill: impl FnOnce(&mut [u8; N])) -> Result<Self, Error> {
        let mut b = Self::new()?;
        fill(b.expose_mut());
        Ok(b)
    }

    /// Exposes the bytes for the duration of a borrow.
    #[must_use]
    pub fn expose(&self) -> &[u8; N] {
        // SAFETY: ptr points to an initialized, live allocation of at
        // least N bytes, aligned to a page (more than u8 needs), and
        // &self prevents any &mut for the borrow's duration.
        unsafe { self.ptr.as_ref() }
    }

    /// Exposes the bytes mutably for the duration of a borrow.
    #[must_use]
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: as in expose, and &mut self makes the borrow unique.
        unsafe { self.ptr.as_mut() }
    }
}

impl<const N: usize> Drop for LockedBox<N> {
    fn drop(&mut self) {
        let size = self.layout.size();
        let bytes = self.ptr.cast::<u8>();
        // SAFETY: the allocation is live, initialized and `size` bytes
        // long, and &mut self makes this the only reference.
        let all = unsafe { core::slice::from_raw_parts_mut(bytes.as_ptr(), size) };
        // zeroize writes with volatile stores and an optimization
        // barrier, so the wipe is not removed as a dead store before
        // the free.
        #[cfg(not(kani))]
        all.zeroize();
        // Kani cannot model zeroize's inline-assembly barrier. It checks
        // a plain wipe instead, and proves that every byte is zero
        // before the memory is freed.
        #[cfg(kani)]
        {
            all.fill(0);
            assert!(all.iter().all(|&b| b == 0));
        }
        os::unlock(bytes, size);
        // SAFETY: allocated in new with this exact layout, and never
        // freed before, because drop runs once.
        unsafe { dealloc(bytes.as_ptr(), self.layout) };
    }
}

/// The layout of `len` bytes rounded up to whole pages, at least one.
fn page_layout(len: usize, page: usize) -> Result<Layout, Error> {
    let pages = len.div_ceil(page).max(1);
    let size = pages.checked_mul(page).ok_or(Error::TooLarge)?;
    Layout::from_size_align(size, page).map_err(|_| Error::TooLarge)
}

/// The system page size. A fixed 4 KiB under Miri, and 16 bytes under
/// Kani, so that the model checker does not unroll the wipe of a whole
/// page. The rounding logic is the same for any power of two, and
/// `page_layout_is_sound` proves it for real page sizes.
fn page_size() -> usize {
    os::page_size().unwrap_or(4096)
}

#[cfg(any(miri, kani))]
mod os {
    use core::ptr::NonNull;

    pub fn page_size() -> Option<usize> {
        if cfg!(kani) { Some(16) } else { None }
    }
    pub fn lock(_: NonNull<u8>, _: usize) -> bool {
        true
    }
    pub fn unlock(_: NonNull<u8>, _: usize) {}
    pub fn exclude_from_dumps(_: NonNull<u8>, _: usize) {}
}

#[cfg(all(unix, not(any(miri, kani))))]
mod os {
    use core::ptr::NonNull;

    pub fn page_size() -> Option<usize> {
        // SAFETY: sysconf has no preconditions.
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(n).ok().filter(|&p| p.is_power_of_two())
    }

    pub fn lock(p: NonNull<u8>, len: usize) -> bool {
        // SAFETY: [p, p + len) is one live allocation owned by the caller.
        unsafe { libc::mlock(p.as_ptr().cast(), len) == 0 }
    }

    pub fn unlock(p: NonNull<u8>, len: usize) {
        // SAFETY: as in lock. Failure leaves the pages locked until they
        // are freed, which is harmless, so the result is ignored.
        unsafe {
            libc::munlock(p.as_ptr().cast(), len);
        }
    }

    pub fn exclude_from_dumps(p: NonNull<u8>, len: usize) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: page-aligned range of one live allocation. madvise
        // with MADV_DONTDUMP changes only dump behavior, not contents.
        unsafe {
            libc::madvise(p.as_ptr().cast(), len, libc::MADV_DONTDUMP);
        }
        #[cfg(target_os = "freebsd")]
        // SAFETY: as above, with the FreeBSD name for the same advice.
        unsafe {
            libc::madvise(p.as_ptr().cast(), len, libc::MADV_NOCORE);
        }
        // macOS and iOS have no per-range advice. Apps there disable core
        // dumps for the whole process; see README.md.
        let _ = (p, len);
    }
}

#[cfg(all(windows, not(any(miri, kani))))]
mod os {
    use core::ptr::NonNull;
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    pub fn page_size() -> Option<usize> {
        // SAFETY: GetSystemInfo fills the struct and cannot fail.
        let info = unsafe {
            let mut info: SYSTEM_INFO = core::mem::zeroed();
            GetSystemInfo(&raw mut info);
            info
        };
        usize::try_from(info.dwPageSize)
            .ok()
            .filter(|&p| p.is_power_of_two())
    }

    pub fn lock(p: NonNull<u8>, len: usize) -> bool {
        // SAFETY: [p, p + len) is one live allocation owned by the caller.
        unsafe { VirtualLock(p.as_ptr().cast(), len) != 0 }
    }

    pub fn unlock(p: NonNull<u8>, len: usize) {
        // SAFETY: as in lock. Failure is harmless, as on Unix.
        unsafe {
            VirtualUnlock(p.as_ptr().cast(), len);
        }
    }

    pub fn exclude_from_dumps(_: NonNull<u8>, _: usize) {
        // Windows has no per-range exclusion. Apps there configure
        // Windows Error Reporting; see README.md.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_rounds_to_pages() {
        assert_eq!(page_layout(0, 4096).map(|l| l.size()), Ok(4096));
        assert_eq!(page_layout(1, 4096).map(|l| l.size()), Ok(4096));
        assert_eq!(page_layout(4096, 4096).map(|l| l.size()), Ok(4096));
        assert_eq!(page_layout(4097, 4096).map(|l| l.size()), Ok(8192));
        assert_eq!(page_layout(usize::MAX, 4096), Err(Error::TooLarge));
    }

    #[test]
    fn holds_and_changes_bytes() {
        let mut b = LockedBox::<32>::new_with(|buf| buf.fill(5)).unwrap();
        assert_eq!(b.expose(), &[5u8; 32]);
        b.expose_mut()[0] = 6;
        assert_eq!(b.expose()[0], 6);
    }

    #[test]
    fn starts_zeroed_and_is_page_aligned() {
        let b = LockedBox::<100>::new().unwrap();
        assert_eq!(b.expose(), &[0u8; 100]);
        assert_eq!(b.ptr.as_ptr() as usize % page_size(), 0);
    }

    #[test]
    fn moves_do_not_move_the_bytes() {
        let b = LockedBox::<16>::new().unwrap();
        let before = b.expose().as_ptr();
        let moved = Some(b);
        assert_eq!(moved.as_ref().map(|m| m.expose().as_ptr()), Some(before));
    }
}

/// Kani proofs. Run with `cargo kani -p mosgird-core`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Rounding to pages never overflows unchecked, and an accepted
    /// layout always covers the request with whole pages.
    #[kani::proof]
    fn page_layout_is_sound() {
        let len: usize = kani::any();
        let shift: u32 = kani::any_where(|&s| (12..=16).contains(&s));
        let page = 1usize << shift;
        if let Ok(l) = page_layout(len, page) {
            assert!(l.size() >= len);
            assert!(l.size() >= page);
            assert_eq!(l.size() % page, 0);
            assert_eq!(l.align(), page);
        }
    }

    /// Create, write, read and drop with no undefined behavior.
    #[kani::proof]
    fn create_write_drop() {
        let v: u8 = kani::any();
        if let Ok(mut b) = LockedBox::<8>::new() {
            b.expose_mut()[7] = v;
            assert_eq!(b.expose()[7], v);
            assert_eq!(b.expose()[0], 0);
        }
    }
}
