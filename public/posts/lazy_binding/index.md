# 延迟绑定过程分析


延迟绑定过程分析
<!--more-->

# GOT&PLT

got表和plt表都是程序调用外部函数时，定位该函数需要使用到的表

## Global Offset Table(GOT，全局偏移表)

GOT 表的主要功能是 **存储动态链接库（如 `libc.so`）中函数和全局变量的运行时地址**。

GOT表包括两种类型`.got`和`.got.plt`

- .got
	- 存储 **全局变量** 的地址
- .got.plt
	- 存储 **动态库函数** 的地址（如 `printf`、`read`）。
	- 与 **PLT（Procedure Linkage Table）** 配合实现 **延迟绑定（Lazy Binding）**。

### .got.plt的公共表项

有三个公共表项，分别是

- got[0]:`_DYNAMIC`:指向 **动态段（`.dynamic`）** 的地址
- got[1]:`link_map` 指针:动态链接器内部使用的 `link_map` 结构指针（用于符号解析）
- got[2]:`_dl_runtime_resolve`:动态解析函数的地址

got[3]开始就是函数的地址

**示例：x86-64 的 `.got.plt` 布局**

```asm
.got.plt:0000000000403FE8
.got.plt:0000000000403FE8 ; Segment type: Pure data
.got.plt:0000000000403FE8 ; Segment permissions: Read/Write
.got.plt:0000000000403FE8 _got_plt        segment qword public 'DATA' use64
.got.plt:0000000000403FE8                 assume cs:_got_plt
.got.plt:0000000000403FE8                 ;org 403FE8h
.got.plt:0000000000403FE8 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000403FF0 qword_403FF0    dq 0                    ; DATA XREF: sub_401020↑r
.got.plt:0000000000403FF8 qword_403FF8    dq 0                    ; DATA XREF: sub_401020+6↑r
.got.plt:0000000000404000 off_404000      dq offset seccomp_init  ; DATA XREF: _seccomp_init+4↑r
.got.plt:0000000000404008 off_404008      dq offset seccomp_rule_add
.got.plt:0000000000404008                                         ; DATA XREF: _seccomp_rule_add+4↑r
.got.plt:0000000000404010 off_404010      dq offset write         ; DATA XREF: _write+4↑r
.got.plt:0000000000404018 off_404018      dq offset seccomp_load  ; DATA XREF: _seccomp_load+4↑r
.got.plt:0000000000404020 off_404020      dq offset setbuf        ; DATA XREF: _setbuf+4↑r
.got.plt:0000000000404028 off_404028      dq offset close         ; DATA XREF: _close+4↑r
.got.plt:0000000000404030 off_404030      dq offset read          ; DATA XREF: _read+4↑r
.got.plt:0000000000404030 _got_plt        ends
.got.plt:0000000000404030
```

其中

```asm
.got.plt:0000000000403FE8 _GLOBAL_OFFSET_TABLE_ dq offset _DYNAMIC
.got.plt:0000000000403FF0 qword_403FF0    dq 0                    ; DATA XREF: sub_401020↑r
.got.plt:0000000000403FF8 qword_403FF8    dq 0                    ; DATA XREF: sub_401020+6↑r
```

就是公共表项，从上到下依次就是got[0]、got[1]、got[2]

got[1]、got[2]由动态链接器在装载共享模块的时候负责将它们初始化



### link_map

数据结构的定义如下：

```c
struct link_map
{
   /* Shared library's load address. */
   ElfW(Addr) l_addr;
    
   /* Pointer to library's name in the string table. */                                 
   char *l_name;    
   
    /* 
        Dynamic section of the shared object.
        Includes dynamic linking info etc.
        Not interesting to us.  
   */                   
   ElfW(Dyn) *l_ld;   
   
    /* Pointer to previous and next link_map node. */                 
   struct link_map *l_next, *l_prev;   
};
```

首次调用动态函数时，`_dl_runtime_resolve` 通过 `link_map` 解析符号地址。



## Procedure Linkage Table(PLT,进程链接表)

**结构：**

- **PLT0（公共解析逻辑）**
	所有 PLT 条目共享的代码，负责调用 `_dl_runtime_resolve` 解析函数地址。
- **PLT1, PLT2, ...（函数专用条目）**
	每个动态函数（如 `printf`、`read`）有一个 PLT 条目。

**典型 PLT 条目（x86-64）**

```
printf@plt:
    jmp  *GOT[n]       ; 首次调用时，GOT[n] 指向下一行（解析逻辑）
    push 5             ; 符号索引（5 = printf 在 .dynsym 中的下标）
    jmp  PLT0          ; 跳转到公共解析逻辑（_dl_runtime_resolve）
```

# 延迟绑定过程

函数第一次调用时，过程如下图：

{{< image src="/img/lazy_binding/1.png" >}}

1. 跳转到该函数的PLT条目
2. 第一个jmp指令跳往对应函数的.got.plt入口，但是这个时候got表中还没有填充函数的真实地址。
3. 所以从got表跳回到plt表中，继续往下执行push;jmp。跳回后，push的值是对应函数在**.got.plt**入口的偏移
4. 跳到PLT头部，执行push指令，将 **GOT[1]** 的地址（link_map的地址）入栈。
5. 接着jmp到 **GOT[2] **
6.  即dl_runtime_resolve相关的函数对动态函数进行地址解析和重定位
7. 并且把函数真实地址回填到got表中
8. 最后执行函数

非首次调用，过程如下图：

![lazy_binding](/img/lazy_binding/2.png)

之后再调用该函数的时候，plt只有一个跳转指令，找到对应的函数地址之后执行函数。动态调试看了一个整个运行过程，有了一个更深入的的理解。

1. 跳转到该函数的PLT条目
2. 第一个jmp指令跳往对应函数的.got.plt入口
3. 此时的got表被填充为函数的真实地址，跳转到真实地址
4. 执行函数

# 实际分析

这里用gdb动态调试，实际分析一下

## 第一次调用过程：

![lazy_binding](/img/lazy_binding/3.png)

首先函数call了0x401100，0x401100就是read函数的.plt.sec

![lazy_binding](/img/lazy_binding/4.png)

接着step步入

![lazy_binding](/img/lazy_binding/5.png)

可以看到，实际上，程序会先进入.plt.sec执行jmp，再到.plt中执行push;jmp。

![lazy_binding](/img/lazy_binding/8.png)

可以看到这时read函数的.got.plt还没被更改为真实地址，而是指向read函数PLT表项中的push

![lazy_binding](/img/lazy_binding/6.png)

![lazy_binding](/img/lazy_binding/7.png)

执行完dl_runtime_resolve相关的函数，就会进入read的真实地址执行read，同时可以看到，read函数的.got.plt也指向的该函数真实地址

接着就执行read函数

## 非首次调用过程：

![lazy_binding](/img/lazy_binding/9.png)

先call了read函数的.plt.sec

然后s步入

![lazy_binding](/img/lazy_binding/10.png)

`qword ptr [rip + 0x2f26]`就是取出存储在`read`的.got.plt中地址，然后跳转到该地址

> | 指令                              | 行为                                                    |
> | :-------------------------------- | :------------------------------------------------------ |
> | `jmp 0x404040`                    | 直接跳转到 `0x404040`（绝对地址）                       |
> | `jmp [0x403f2c]`                  | 从 `0x403f2c` 读取 8 字节作为目标地址                   |
> | `jmp    qword ptr [rip + 0x2f26]` | 从 `(RIP + 0x2f26)` 读取 8 字节作为目标地址（动态计算） |

然后直接执行read

**所以，非首次调用，got表中存储的就是真实地址**

# 参考文献

[延迟绑定过程分析](https://yjy123123.github.io/2021/12/06/%E5%BB%B6%E8%BF%9F%E7%BB%91%E5%AE%9A%E8%BF%87%E7%A8%8B%E5%88%86%E6%9E%90/)：理论分析

[深入理解plt表、got表和动态链接](https://evilpan.com/2018/04/09/about-got-plt/#got--gotplt)：前置知识

[延迟绑定过程图](https://blog.csdn.net/s5555555___/article/details/136199196)


---

> Author:    
> URL: http://localhost:1313/posts/lazy_binding/  

