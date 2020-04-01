from struct import *

def db(v):
  return pack("<B", v)

def dw(v):
  return pack("<H", v)

def dd(v):
  return pack("<I", v)

def dq(v):
  return pack("<Q", v)

def rb(v):
  return unpack("<B", v[0])[0]

def rw(v):
  return unpack("<H", v[:2])[0]

def rd(v):
  return unpack("<I", v[:4])[0]

def rq(v):
  return unpack("<Q", v[:8])[0]

with open('virtual_toy', 'rb') as f:
    data = f.read()[0x2120:0x2440]

dwords = []
opcodes = {
    0x0: 'call getc',
    0x1: 'call putc',
    0x2: 'add',
    0x3: 'sub',
    0x4: 'mul',
    0x5: 'div',
    0x6: 'mod',
    0x7: 'and',
    0x8: 'or',
    0x9: 'xor',
    0xa: 'not',
    0xb: 'eq',
    0xc: 'inv',
    0xd: 'rshift',
    0xe: 'lshift',
    0xf: 'jmp',
    0x10: 'safe jmp?',
    0x11: 'lookup',
    0x12: 'pop',
    0x13: 'copy',
    0x14: 'ret pop',
}

for i in xrange(0, len(data), 4):
    dwords.append(rd(data[i:i+4]))

for i, d in enumerate(dwords):
    des = opcode(d)
    print '%4.x -- %.8x: %.8x -- %s' % (i, 0x2120 + i*4, d, s)
