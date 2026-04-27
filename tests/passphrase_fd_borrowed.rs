//! PASS-02 / D-P5-07 / D-P5-03 / Pitfall #31: resolve_passphrase's fd branch must
//! not take ownership of the caller's fd, so the fd remains valid after the call
//! returns. Also verifies D-P5-03 fd=0 rejection (stdin reserved for payload I/O).

use serial_test::serial;

fn fd_is_open(fd: i32) -> bool {
    // F_GETFD returns -1 with errno=EBADF on a closed fd.
    // SAFETY: fcntl(F_GETFD) has no memory effects.
    let ret = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    ret != -1
}

#[test]
#[serial]
fn fd_remains_open_after_resolve() {
    let mut fds: [libc::c_int; 2] = [0; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe() must succeed");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let payload = b"hunter2\n";
    let n = unsafe { libc::write(write_fd, payload.as_ptr() as *const _, payload.len()) };
    assert_eq!(n, payload.len() as isize);
    unsafe { libc::close(write_fd) };

    let pw = cipherpost::identity::resolve_passphrase(None, None, None, Some(read_fd), false)
        .expect("resolve_passphrase must succeed on a valid fd");
    assert_eq!(pw.expose(), "hunter2", "strip rule must fire on fd read");

    // Load-bearing assertion: the caller's fd is STILL open (Pitfall #31 — the fd
    // branch must borrow, not take ownership).
    assert!(
        fd_is_open(read_fd),
        "resolve_passphrase must not close the caller's fd"
    );

    unsafe { libc::close(read_fd) };
}

#[test]
#[serial]
fn fd_zero_rejected() {
    // D-P5-03: fd 0 reserved for stdin.
    let err = cipherpost::identity::resolve_passphrase(None, None, None, Some(0), false)
        .expect_err("fd 0 must be rejected");
    assert!(
        matches!(err, cipherpost::Error::Config(_)),
        "fd 0 must be rejected as Error::Config; got {err:?}"
    );
}
