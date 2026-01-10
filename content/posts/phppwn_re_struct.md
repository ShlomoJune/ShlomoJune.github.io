+++
date = '2025-08-14T00:34:16+08:00'
draft = true
title = 'phppwn逆向'
categories=['phppwn']

+++

相关结构体修复

<!--more-->

在phppwn逆向的时候，常遇到类似这样的东西：

{{< image src="/img/phppwn/phppwn_re_struct/1.png" width="900px">}}

其实它是对传入参数的类型进行判断，但是看起来并不太直观。

IDA中支持导入C头文件，修复一些结构体

经过修复：

```c
if ( v15->u1.v.type == IS_ARRAY )
    {
      if ( v16->u1.v.type == IS_STRING )
      {
```

这是我用的导入php一些常用结构体到IDA的头文件

> 这个头文件有些地方不太完善，但是用起来没什么大问题

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



导入方式：`File` -> `Load file` ->  `Parse C header file`，然后选择这个头文件导入。

导入后就能看到`Local Types`中有相关的结构体



使用方式：右键需要convert的变量，选择`Convert to struct *...`

其中常用的结构体有：`zval`、`string`、`array`



至于相关变量结构体改成类似`IS_ARRAY`。

右键需要改的数字，选择`Enum`，选择`zend_type`





