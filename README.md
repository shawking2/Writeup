# Writeup X-MASCTF 
<span style="color: green"> Author: Quasar (Team: UIT.ζp33d_0∫_Ψ1m3)</span>
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
Ban đầu thì mình nghĩ challenge này khá là bưởi nhưng sau đó mình mới biết ý challenge này còn liên quan đến 1 challenge khác đó là "Ministerul Mediului" (chall này mình giải chưa ra nên ko viết writeup được :) )  > flag: X-MAS{ah_yes__i_d0_rememb3r_you}


