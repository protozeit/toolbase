#!/usr/bin/env python

from pwn import *

binary = './bin'
host = '127.0.0.1'
port = 9000
libc_so = '/usr/lib64/libc-2.31.so'

# context.log_level = 'DEBUG'
context.terminal = ['kitty', '-e', 'sh', '-c']

bin = ELF(binary)
libc = ELF(libc_so)

# r = remote(host, port)
r = process(binary); gdb.attach(r); pause()

r.interactive()
