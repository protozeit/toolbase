from pwn import *
import sys

''' Unpolished example of simple AES oracle bug exploit '''

r = remote('crypto.chal.csaw.io', 1003)

blength = 0

r.recvline()
r.sendline('a')
r.recvline()
r.recvline()

print '###################################'
print 'Calculating block length'
print '  '
for i in range(0,100):
     r.sendline('a'*i)
     r.recvline()
     a1 = r.recvline()
     r.sendline('a'*(i+1))
     r.recvline()
     a2 = r.recvline()
     if a1[:128] == a2[:128]:
             print "Flag has max length : " + str(i)
             blength = i
             break

print "block length is "  + str(blength)
flag = 'flag{y0u_k'

for k in range(len(flag)+1,blength):
        pload = 'a'*(blength-k)
        r.sendline(pload)
        r.recvline()
        h1 = r.recvline()[:128]

        for j in range(32,127):
                r.sendline(pload +flag+ chr(j))
                r.recvline()
                hj = r.recvline()[:128]

                if hj[:128] == h1[:128]:
                        flag += chr(j)
                        print flag
                        if '}' in flag: sys.exit()
                        break
