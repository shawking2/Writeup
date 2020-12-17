# Writeup X-MASCTF 
> # Author: Quasar (Team: UIT.ζp33d_0∫_Ψ1m3)
# Challenge Name : ![screenshot](https://github.com/19520611/Writeup/raw/main/xmasCTF/img/doiknowyou1.PNG)
Bài này có điểm số là 45. Đầu mình sẽ đi vào những phân tích cơ bản qua các lệnh file và checksec:
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/doiknowyou$ file chall
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e0e53c0345a73991671f9f6548621739ae38efda, stripped
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/doiknowyou$ checksec chall
[*] '/mnt/c/Users/19520/Music/X-MasCTF/doiknowyou/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
``` 

Mình sẽ dùng IDA pro để xem mã giả c:
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char v4; // [rsp+0h] [rbp-30h]
  __int64 v5; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("Hi there. Do I recognize you?");
  gets(&v4, 0LL);
  if ( v5 != 0xDEADBEEFLL )
  {
    puts("Nope.....I have no idea who you are");
    exit(0);
  }
  puts("X-MAS{Fake flag. You'll get the real one from the server }");
  return 0LL;
}
```
Đọc mã giả bạn sẽ thấy rằng chương trình bị lỗi buffer overflow tại hàm gets. Ở bài này bạn chỉ cần đè 4 bytes tại offset $rbp-0x10 bằng 0xdeadbeef (tức là biến v5 như IDA pro hiển thị) thì khi chạy trên server chỗ "puts("X-MAS{" sẽ in ra flag thật cho chúng ta (gợi ý ở hàm puts):
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/doiknowyou$ python echall.py
[+] Opening connection to challs.xmas.htsp.ro on port 2008: Done
[*] Switching to interactive mode
X-MAS{ah_yes__i_d0_rememb3r_you}
[*] Got EOF while reading in interactive
```
Ban đầu thì mình nghĩ challenge này khá là bưởi nhưng sau đó mình mới biết challenge này còn liên quan đến 1 challenge khác đó là "Ministerul Mediului" (chall này mình giải chưa ra nên ko viết writeup được :) )  
> flag: X-MAS{ah_yes__i_d0_rememb3r_you}

# Challenge Name: ![screenshot](https://github.com/19520611/Writeup/blob/main/xmasCTF/img/naughty2.PNG)
Ta bắt đầu với các bước phân tích cơ bản cách các lệnh file, checksec, seccomp-tools: 
> checksec: 
``` 
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/naughty$ gdb-gef chall
Reading symbols from chall...
(No debugging symbols found in chall)
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded for GDB 10.1 using Python engine 3.9
[*] 3 commands could not be loaded, run `gef missing` to know why.
gef➤  checksec
[+] checksec for '/mnt/c/Users/19520/Music/X-MasCTF/naughty/chall'
Canary                        : ✘
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
gef➤
```
Qua checksec ta thấy được chương trình không bật một trình bảo về nào cả.
> seccomp-tools:
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/naughty$ seccomp-tools dump  ./chall
Tell Santa what you want for XMAS
```
Phân tích qua seccomp-tools thì chương trình này không ngăn chặn ta gọi 1 systemcall nào.
> file:
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/naughty$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d9d6dbd83f78de807736b72dcfba4d4be904bd44, stripped
```
Qua lệnh file cung cấp cho ta thông tin đây là 1 tệp elf 64 bit, nhưng còn 1 điều, bạn hãy chú ý từ cuối cùng ```stripped```. Mình có biết chút ít về stripped, khi 1 chương trình dược biên dịch theo cách thông thường thì gcc sẽ thêm các debugging symbols vào file binary để cho debug đơn giản hơn, nhưng khi biên dịch bằng gcc sử dụng flag ```-s``` (stripped) thì trình biên dịch sẽ gỡ bỏ các debugging symbols làm cho kích cỡ của file sẽ nhỏ hơn và việc debug trở nên khó khăn hơn.

Muốn biết stripped gây khó khăn cho debug như thế nào các bạn hãy mở ```gdb``` lên và gõ lệnh info function:
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/naughty$ gdb-pwndbg chall
Reading symbols from chall...
(No debugging symbols found in chall)
pwndbg: loaded 192 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> info func
All defined functions:

Non-debugging symbols:
0x0000000000400510  puts@plt
0x0000000000400520  fgets@plt
0x0000000000400530  setvbuf@plt
0x0000000000400540  exit@plt
pwndbg>
```
Các bạn có thể thấy các symbols plt hiện thị còn các hàm như main thì lại không hiện ra. Việc này sẽ gây cản trở cho các bạn đặt break point để debug. Sẽ có 1 số cách giúp chúng ta có thể debug được mình sẽ giới thiễu, 1 cách đơn giản (cách này chỉ dùng được khi Pie disable) đó là bạn tìm địa chỉ của hàm main bằng các công cụ như là IDA pro, r2, ... sau đó đặt break point tại địa chỉ đó thì ta có thể debug bình thường: 
> Sử dụng r2 tìm địa chỉ hàm main (bạn nào ko quen dùng tools này thì dùng IDA pro lấy vẫn được nhé):
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/naughty$ r2 chall
[0x00400550]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00400550]> afl
0x00400550    1 42           entry0
0x00400510    1 6            sym.imp.puts
0x00400520    1 6            sym.imp.fgets
0x00400530    1 6            sym.imp.setvbuf
0x00400540    1 6            sym.imp.exit
0x00400630    5 119  -> 62   entry.init0
0x00400600    3 34   -> 29   entry.fini0
0x00400590    4 42   -> 37   fcn.00400590
0x004004e8    3 23           fcn.004004e8
0x00400637    3 159          main
```
Địa chỉ hàm main: 0x00400637. Có được địa chỉ của hàm main rồi thì ta đặc break point rồi debug thôi:
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/naughty$ gdb-pwndbg chall
Reading symbols from chall...
(No debugging symbols found in chall)
pwndbg: loaded 192 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> b*0x00400637
Breakpoint 1 at 0x400637
pwndbg> r
Starting program: /mnt/c/Users/19520/Music/X-MasCTF/naughty/chall
pwndbg>
Breakpoint 1, 0x0000000000400637 in ?? ()

LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────────────────────
*RAX  0x400637 ◂— push   rbp
```
> IDA pro để xem mã giả:
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s; // [rsp+0h] [rbp-30h]
  __int16 v5; // [rsp+2Eh] [rbp-2h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  v5 = 0xE4FFu;
  puts("Tell Santa what you want for XMAS");
  fgets(&s, 71, stdin);
  puts("Nice. Hope you haven't been naughty");
  if ( v5 != 0xE4FFu )
  {
    puts("Oh no....no gifts for you this year :((");
    exit(0);
  }
  return 0LL;
}
```
Mình sẽ mô tả sơ về luồng thực thi chương trình. Chương trình khai báo 2 biến đó là v6 với offset $rbp-0x30 và v5 với offset là rbp-0x2. Ban đầu chương trình sẽ gán v5 = 0xE4FF sau đó cho cho gọi hàm fgets để nhập vào giá trị cho v5 là 71 bytes. sau đó tiếp tục kiểm tra v5 có bằng 0xE4FF hay không nếu không bằng thực hiện lệnh exit(0). 
Nhìn qua thì ta có thể dễ dàng thấy lỗi buffer overflow xảy ra ở fgets khi offset của s bằng $rbp - 0x30  còn fgets cho ta nhật vào đến 71 == 0x47 tức là đọc dư
0x47 - 0x30 = 0x17 (kết quả này đã tính luôn ghì đè biến v5). Với 0x17 thì ta có thể ghì đè được $rbp và return address và còn dư 7 bytes. 





