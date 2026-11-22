// covers: crates/mosgird-core/src/secure_mem.rs
//! Behavior of `LockedBox` through its public API: zeroed creation,
//! in-place filling, reads and writes, page alignment, stable addresses,
//! independence of boxes, and use across threads.

use std::thread;

use mosgird_core::secure_mem::{Error, LockedBox};

/// The smallest page size of any supported platform. Every box is aligned
/// to the real page size, which is a multiple of this.
const MIN_PAGE: usize = 4096;

fn address<const N: usize>(b: &LockedBox<N>) -> usize {
    b.expose().as_ptr() as usize
}

#[test]
fn new_box_is_zeroed() {
    let b = LockedBox::<64>::new().unwrap();
    assert_eq!(b.expose(), &[0u8; 64]);
}

#[test]
fn new_box_is_page_aligned() {
    let b = LockedBox::<64>::new().unwrap();
    assert_eq!(address(&b) % MIN_PAGE, 0);
}

#[test]
fn fill_sees_a_zeroed_buffer() {
    let mut seen_zero = false;
    let b = LockedBox::<48>::new_with(|buf| {
        seen_zero = buf.iter().all(|&x| x == 0);
        buf.fill(0x11);
    })
    .unwrap();
    assert!(seen_zero);
    assert_eq!(b.expose(), &[0x11u8; 48]);
}

#[test]
fn fill_runs_once() {
    let mut calls = 0;
    let _b = LockedBox::<8>::new_with(|_| calls += 1).unwrap();
    assert_eq!(calls, 1);
}

#[test]
fn fill_writes_a_pattern() {
    let b = LockedBox::<256>::new_with(|buf| {
        for (i, x) in buf.iter_mut().enumerate() {
            *x = u8::try_from(i).unwrap();
        }
    })
    .unwrap();
    for (i, x) in b.expose().iter().enumerate() {
        assert_eq!(usize::from(*x), i);
    }
}

#[test]
fn writes_are_read_back() {
    let mut b = LockedBox::<32>::new().unwrap();
    b.expose_mut()[0] = 1;
    b.expose_mut()[31] = 2;
    assert_eq!(b.expose()[0], 1);
    assert_eq!(b.expose()[31], 2);
    assert!(b.expose()[1..31].iter().all(|&x| x == 0));
}

#[test]
fn whole_overwrite_is_read_back() {
    let mut b = LockedBox::<100>::new().unwrap();
    *b.expose_mut() = [0x42; 100];
    assert_eq!(b.expose(), &[0x42u8; 100]);
    b.expose_mut().fill(0);
    assert_eq!(b.expose(), &[0u8; 100]);
}

#[test]
fn exact_page_size() {
    let mut b = LockedBox::<4096>::new().unwrap();
    b.expose_mut()[4095] = 9;
    assert_eq!(b.expose()[4095], 9);
    assert_eq!(address(&b) % MIN_PAGE, 0);
}

#[test]
fn larger_than_a_page() {
    let mut b = LockedBox::<9000>::new().unwrap();
    b.expose_mut()[8999] = 3;
    b.expose_mut()[4096] = 4;
    assert_eq!(b.expose()[8999], 3);
    assert_eq!(b.expose()[4096], 4);
    assert_eq!(b.expose()[0], 0);
}

#[test]
fn zero_sized_box() {
    let b = LockedBox::<0>::new().unwrap();
    assert_eq!(b.expose().len(), 0);
}

#[test]
fn one_byte_box() {
    let mut b = LockedBox::<1>::new_with(|buf| buf[0] = 0xff).unwrap();
    assert_eq!(b.expose(), &[0xff]);
    b.expose_mut()[0] = 0;
    assert_eq!(b.expose(), &[0]);
}

#[test]
fn boxes_do_not_share_pages() {
    let a = LockedBox::<16>::new().unwrap();
    let b = LockedBox::<16>::new().unwrap();
    let (x, y) = (address(&a), address(&b));
    assert_ne!(x, y);
    assert!(x.abs_diff(y) >= MIN_PAGE);
}

#[test]
fn boxes_are_independent() {
    let mut a = LockedBox::<16>::new().unwrap();
    let b = LockedBox::<16>::new().unwrap();
    a.expose_mut().fill(7);
    assert_eq!(a.expose(), &[7u8; 16]);
    assert_eq!(b.expose(), &[0u8; 16]);
}

#[test]
fn address_is_stable_across_moves() {
    let b = LockedBox::<16>::new().unwrap();
    let before = address(&b);
    let boxed = Box::new(b);
    assert_eq!(address(&boxed), before);
    let mut list = vec![*boxed];
    assert_eq!(address(&list[0]), before);
    let back = list.pop().unwrap();
    assert_eq!(address(&back), before);
}

#[test]
fn expose_and_expose_mut_are_the_same_bytes() {
    let mut b = LockedBox::<24>::new_with(|buf| buf[5] = 1).unwrap();
    let read = b.expose().as_ptr() as usize;
    let write = b.expose_mut().as_mut_ptr() as usize;
    assert_eq!(read, write);
    assert_eq!(read % MIN_PAGE, 0);
}

#[test]
fn address_is_stable_across_writes() {
    let mut b = LockedBox::<16>::new().unwrap();
    let before = address(&b);
    b.expose_mut().fill(1);
    assert_eq!(address(&b), before);
}

#[test]
fn many_boxes_in_sequence() {
    for i in 0u8..8 {
        let b = LockedBox::<128>::new_with(|buf| buf.fill(i)).unwrap();
        assert_eq!(b.expose(), &[i; 128]);
    }
}

#[test]
fn several_boxes_alive_at_once() {
    let boxes: Vec<LockedBox<64>> = (0u8..4)
        .map(|i| LockedBox::new_with(|buf| buf.fill(i)).unwrap())
        .collect();
    for (i, b) in (0u8..).zip(&boxes) {
        assert_eq!(b.expose(), &[i; 64]);
    }
}

#[test]
fn moves_to_another_thread() {
    let b = LockedBox::<32>::new_with(|buf| buf.fill(5)).unwrap();
    let handle = thread::spawn(move || {
        let mut b = b;
        b.expose_mut()[0] = 6;
        b
    });
    let b = handle.join().unwrap();
    assert_eq!(b.expose()[0], 6);
    assert_eq!(b.expose()[1], 5);
}

#[test]
fn shared_between_threads() {
    let b = LockedBox::<32>::new_with(|buf| buf.fill(9)).unwrap();
    let sums: Vec<u32> = thread::scope(|s| {
        let readers: Vec<_> = (0..2)
            .map(|_| s.spawn(|| b.expose().iter().map(|&x| u32::from(x)).sum()))
            .collect();
        readers.into_iter().map(|r| r.join().unwrap()).collect()
    });
    assert_eq!(sums, vec![288, 288]);
}

#[test]
fn is_send_and_sync() {
    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<LockedBox<32>>();
    send_and_sync::<Error>();
}

#[test]
fn errors_are_comparable() {
    let errors = [Error::TooLarge, Error::OutOfMemory, Error::LockFailed];
    for (i, a) in errors.iter().enumerate() {
        for (j, b) in errors.iter().enumerate() {
            assert_eq!(a == b, i == j);
        }
    }
}
