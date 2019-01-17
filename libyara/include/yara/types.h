/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef YR_TYPES_H
#define YR_TYPES_H

#include <yara/arena.h>
#include <yara/bitmask.h>
#include <yara/limits.h>
#include <yara/hash.h>
#include <yara/utils.h>
#include <yara/sizedstr.h>
#include <yara/stopwatch.h>
#include <yara/threading.h>


#define DECLARE_REFERENCE(type, name) \
    union { type name; int64_t name##_; } YR_ALIGN(8)



#define NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL      0x01


#define STRING_GFLAGS_REFERENCED        0x01
#define STRING_GFLAGS_HEXADECIMAL       0x02
#define STRING_GFLAGS_NO_CASE           0x04
#define STRING_GFLAGS_ASCII             0x08
#define STRING_GFLAGS_WIDE              0x10
#define STRING_GFLAGS_REGEXP            0x20
#define STRING_GFLAGS_FAST_REGEXP       0x40
#define STRING_GFLAGS_FULL_WORD         0x80
#define STRING_GFLAGS_ANONYMOUS         0x100
#define STRING_GFLAGS_SINGLE_MATCH      0x200
#define STRING_GFLAGS_LITERAL           0x400
#define STRING_GFLAGS_FITS_IN_ATOM      0x800
#define STRING_GFLAGS_NULL              0x1000
#define STRING_GFLAGS_CHAIN_PART        0x2000
#define STRING_GFLAGS_CHAIN_TAIL        0x4000
#define STRING_GFLAGS_FIXED_OFFSET      0x8000
#define STRING_GFLAGS_GREEDY_REGEXP     0x10000
#define STRING_GFLAGS_DOT_ALL           0x20000
#define STRING_GFLAGS_DISABLED          0x40000
#define STRING_GFLAGS_XOR               0x80000

#define STRING_IS_HEX(x) \
    (((x)->g_flags) & STRING_GFLAGS_HEXADECIMAL)

#define STRING_IS_NO_CASE(x) \
    (((x)->g_flags) & STRING_GFLAGS_NO_CASE)

#define STRING_IS_DOT_ALL(x) \
    (((x)->g_flags) & STRING_GFLAGS_DOT_ALL)

#define STRING_IS_ASCII(x) \
    (((x)->g_flags) & STRING_GFLAGS_ASCII)

#define STRING_IS_WIDE(x) \
    (((x)->g_flags) & STRING_GFLAGS_WIDE)

#define STRING_IS_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_REGEXP)

#define STRING_IS_GREEDY_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_GREEDY_REGEXP)

#define STRING_IS_FULL_WORD(x) \
    (((x)->g_flags) & STRING_GFLAGS_FULL_WORD)

#define STRING_IS_ANONYMOUS(x) \
    (((x)->g_flags) & STRING_GFLAGS_ANONYMOUS)

#define STRING_IS_REFERENCED(x) \
    (((x)->g_flags) & STRING_GFLAGS_REFERENCED)

#define STRING_IS_SINGLE_MATCH(x) \
    (((x)->g_flags) & STRING_GFLAGS_SINGLE_MATCH)

#define STRING_IS_FIXED_OFFSET(x) \
    (((x)->g_flags) & STRING_GFLAGS_FIXED_OFFSET)

#define STRING_IS_LITERAL(x) \
    (((x)->g_flags) & STRING_GFLAGS_LITERAL)

#define STRING_IS_FAST_REGEXP(x) \
    (((x)->g_flags) & STRING_GFLAGS_FAST_REGEXP)

#define STRING_IS_CHAIN_PART(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_PART)

#define STRING_IS_CHAIN_TAIL(x) \
    (((x)->g_flags) & STRING_GFLAGS_CHAIN_TAIL)

#define STRING_IS_NULL(x) \
    ((x) == NULL || ((x)->g_flags) & STRING_GFLAGS_NULL)

#define STRING_FITS_IN_ATOM(x) \
    (((x)->g_flags) & STRING_GFLAGS_FITS_IN_ATOM)

#define STRING_IS_DISABLED(x) \
    (((x)->g_flags) & STRING_GFLAGS_DISABLED)

#define STRING_IS_XOR(x) \
    (((x)->g_flags) & STRING_GFLAGS_XOR)

#define STRING_FOUND(x) \
    ((x)->matches[yr_get_tidx()].tail != NULL)

#define STRING_MATCHES(x) \
    ((x)->matches[yr_get_tidx()])


#define RULE_TFLAGS_MATCH                0x01

#define RULE_GFLAGS_PRIVATE              0x01
#define RULE_GFLAGS_GLOBAL               0x02
#define RULE_GFLAGS_REQUIRE_EXECUTABLE   0x04
#define RULE_GFLAGS_REQUIRE_FILE         0x08
#define RULE_GFLAGS_NULL                 0x1000
#define RULE_GFLAGS_DISABLED             0x2000

#define RULE_IS_PRIVATE(x) \
    (((x)->g_flags) & RULE_GFLAGS_PRIVATE)

#define RULE_IS_GLOBAL(x) \
    (((x)->g_flags) & RULE_GFLAGS_GLOBAL)

#define RULE_IS_NULL(x) \
    (((x)->g_flags) & RULE_GFLAGS_NULL)

#define RULE_IS_DISABLED(x) \
    (((x)->g_flags) & RULE_GFLAGS_DISABLED)

#define RULE_MATCHES(x) \
    ((x)->t_flags[yr_get_tidx()] & RULE_TFLAGS_MATCH)


#define META_TYPE_NULL      0
#define META_TYPE_INTEGER   1
#define META_TYPE_STRING    2
#define META_TYPE_BOOLEAN   3

#define META_IS_NULL(x) \
    ((x) != NULL ? (x)->type == META_TYPE_NULL : true)


#define EXTERNAL_VARIABLE_TYPE_NULL           0
#define EXTERNAL_VARIABLE_TYPE_FLOAT          1
#define EXTERNAL_VARIABLE_TYPE_INTEGER        2
#define EXTERNAL_VARIABLE_TYPE_BOOLEAN        3
#define EXTERNAL_VARIABLE_TYPE_STRING         4
#define EXTERNAL_VARIABLE_TYPE_MALLOC_STRING  5

#define EXTERNAL_VARIABLE_IS_NULL(x) \
    ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : true)


typedef struct RE RE;
typedef struct RE_AST RE_AST;
typedef struct RE_NODE RE_NODE;
typedef struct RE_CLASS RE_CLASS;
typedef struct RE_ERROR RE_ERROR;
typedef struct RE_FIBER RE_FIBER;
typedef struct RE_FIBER_LIST RE_FIBER_LIST;
typedef struct RE_FIBER_POOL RE_FIBER_POOL;

typedef struct YR_AC_MATCH YR_AC_MATCH;
typedef struct YR_AC_STATE YR_AC_STATE;
typedef struct YR_AC_AUTOMATON YR_AC_AUTOMATON;
typedef struct YR_AC_MATCH_TABLE_ENTRY YR_AC_MATCH_TABLE_ENTRY;
typedef struct YR_AC_TABLES YR_AC_TABLES;

typedef struct YR_NAMESPACE YR_NAMESPACE;
typedef struct YR_META YR_META;
typedef struct YR_MATCHES YR_MATCHES;
typedef struct YR_STRING YR_STRING;
typedef struct YR_RULE YR_RULE;
typedef struct YR_RULES YR_RULES;
typedef struct YR_RULES_STATS YR_RULES_STATS;
typedef struct YR_EXTERNAL_VARIABLE YR_EXTERNAL_VARIABLE;
typedef struct YR_MATCH YR_MATCH;
typedef struct YR_SCAN_CONTEXT YR_SCAN_CONTEXT;

typedef union YR_VALUE YR_VALUE;

typedef struct YR_OBJECT YR_OBJECT;
typedef struct YR_OBJECT_STRUCTURE YR_OBJECT_STRUCTURE;
typedef struct YR_OBJECT_ARRAY YR_OBJECT_ARRAY;
typedef struct YR_OBJECT_DICTIONARY YR_OBJECT_DICTIONARY;
typedef struct YR_OBJECT_FUNCTION YR_OBJECT_FUNCTION;

typedef struct YR_STRUCTURE_MEMBER YR_STRUCTURE_MEMBER;
typedef struct YR_ARRAY_ITEMS YR_ARRAY_ITEMS;
typedef struct YR_DICTIONARY_ITEMS YR_DICTIONARY_ITEMS;

typedef struct YR_MODULE YR_MODULE;
typedef struct YR_MODULE_IMPORT YR_MODULE_IMPORT;

typedef struct YR_MEMORY_BLOCK YR_MEMORY_BLOCK;
typedef struct YR_MEMORY_BLOCK_ITERATOR YR_MEMORY_BLOCK_ITERATOR;


#pragma pack(push)
#pragma pack(8)


struct YR_NAMESPACE
{
  int32_t t_flags[YR_MAX_THREADS];     // Thread-specific flags
  DECLARE_REFERENCE(char*, name);
};

/* rule的 META 部分 */
struct YR_META
{
  int32_t type;
  YR_ALIGN(8) int64_t integer;

  DECLARE_REFERENCE(const char*, identifier);
  DECLARE_REFERENCE(char*, string);
};


struct YR_MATCHES
{
  int32_t count;

  DECLARE_REFERENCE(YR_MATCH*, head);
  DECLARE_REFERENCE(YR_MATCH*, tail);
};


struct YR_STRING
{
  int32_t g_flags;
  int32_t length;

  DECLARE_REFERENCE(char*, identifier);  /* match string的变量名 */
  DECLARE_REFERENCE(uint8_t*, string);   /* match pattern */
  /* 
   * chained to 一般用于 abcd.{0, 100}efgh 这种带有重复次数的正则表达式 
   * abcd efgh 会分别查询，中间的正则表达式直接忽略. 是否重复了这么多次，
   * 通过matches的偏移量判断, chain_gap_min/chain_gap_max则用来记录这个
   * 正则表达式的offset, 即此例中的0, 100
   */
  DECLARE_REFERENCE(YR_STRING*, chained_to);  
  DECLARE_REFERENCE(YR_RULE*, rule);     /* match rule */

  int32_t chain_gap_min;
  int32_t chain_gap_max;

  int64_t fixed_offset;

  YR_MATCHES matches[YR_MAX_THREADS]; /*这个string所对应的match上下文*/
  YR_MATCHES unconfirmed_matches[YR_MAX_THREADS]; /* 和chained_to 相关 */
};


struct YR_RULE
{
  int32_t g_flags;                  // Global flags
  int32_t t_flags[YR_MAX_THREADS];  // Thread-specific flags

  DECLARE_REFERENCE(const char*, identifier);
  DECLARE_REFERENCE(const char*, tags);
  /*metas 数组 */
  /*META_IS_NULL 通过 metas->type == META_TYPE_NULL判断是否是最后一个meta */
  DECLARE_REFERENCE(YR_META*, metas);   /* meta data of the rule */ 
  /* 
   * rule->strings[last_string].g_flags = STRING_GFLAGS_NULL,
   * 通过此规则来判断string是否是此rule的最后一个string
   */
  DECLARE_REFERENCE(YR_STRING*, strings); /* string的数组 */
  DECLARE_REFERENCE(YR_NAMESPACE*, ns);

  // Number of atoms generated for this rule.
  int32_t num_atoms;

  // Used only when PROFILING_ENABLED is defined. This is the sum of all values
  // in time_cost_per_thread. This is updated once on each call to
  // yr_scanner_scan_xxx.
  volatile int64_t time_cost;

  // Used only when PROFILING_ENABLED is defined. This array holds the time
  // cost for each thread using this structure concurrenlty. This is necessary
  // because a global variable causes too much contention while trying to
  // increment in a synchronized way from multiple threads.
  int64_t time_cost_per_thread[YR_MAX_THREADS];
};


struct YR_EXTERNAL_VARIABLE
{
  int32_t type;

  YR_ALIGN(8) union {
    int64_t i;
    double f;
    char* s;
  } value;

  DECLARE_REFERENCE(const char*, identifier);
};


struct YR_AC_MATCH
{
  uint16_t backtrack;

  DECLARE_REFERENCE(YR_STRING*, string);
  /* forward_code/backward_code 设置了执行码 */
  DECLARE_REFERENCE(const uint8_t*, forward_code);
  DECLARE_REFERENCE(const uint8_t*, backward_code);
  DECLARE_REFERENCE(YR_AC_MATCH*, next);  /* 链表，当状态机找到yr_ac_match时，会一次遍历链表，以找到所有的match */
};


struct YR_AC_MATCH_TABLE_ENTRY
{
  DECLARE_REFERENCE(YR_AC_MATCH*, match);
};


typedef uint32_t                  YR_AC_TRANSITION;
typedef YR_AC_TRANSITION*         YR_AC_TRANSITION_TABLE;
typedef YR_AC_MATCH_TABLE_ENTRY*  YR_AC_MATCH_TABLE;


struct YR_AC_TABLES
{
  YR_AC_TRANSITION* transitions;
  YR_AC_MATCH_TABLE_ENTRY* matches;
};


typedef struct YARA_RULES_FILE_HEADER
{
  DECLARE_REFERENCE(YR_RULE*, rules_list_head);
  DECLARE_REFERENCE(YR_EXTERNAL_VARIABLE*, externals_list_head);
  DECLARE_REFERENCE(const uint8_t*, code_start);
  DECLARE_REFERENCE(YR_AC_MATCH_TABLE, ac_match_table);
  DECLARE_REFERENCE(YR_AC_TRANSITION_TABLE, ac_transition_table);

  // Size of ac_match_table and ac_transition_table in number of items (both
  // tables have the same number of items)
  uint32_t ac_tables_size;

} YARA_RULES_FILE_HEADER;


typedef struct _YR_INIT_RULE_ARGS
{
  DECLARE_REFERENCE(YR_RULE*, rule);
  DECLARE_REFERENCE(const uint8_t*, jmp_addr);

} YR_INIT_RULE_ARGS;


#pragma pack(pop)


//
// Structs defined below are never stored in the compiled rules file
//

struct RE_NODE
{
  int type;

  union {
    int value;
    int count;
    int start;
  };

  union {
    int mask;
    int end;
  };

  int greedy;

  RE_CLASS* re_class;

  RE_NODE* children_head;
  RE_NODE* children_tail;
  RE_NODE* prev_sibling;
  RE_NODE* next_sibling;

  /* 
   * 正则表达式的执行码可以拆分为向前和向后执行两部分, 先执行正向的，再执行反向的
   * 正向反向结合起来就是整个的匹配过程, 但是正向反向的具体拆分是根据正则表达式而来的 
   * 例如: 
   * 1. a[AP]M) 拆分成
   * 正向: M)
   * 反向: a[AP]
   * 2. abc[AP]M) 拆分成
   * 正向: abc[AP]M)
   * 反向: NULL
   * 正向一定会有，而反向则根据情况而定，不一定会有
   */
  /*
   *  例如: a[AP]M)
   *  根据M)构造aho corasick 树
   *  正向:
   *  RE_OPCODE_LITERAL: M
   *  RE_OPCODE_LITERAL: )
   *  RE_OPCODE_MATCH
   *  反向:
   *  RE_OPCODE_CLASS: [AP]
   *  RE_OPCODE_LITERAL: a
   *  RE_OPCODE_MATCH
   *  log如下:
exec forward code:
opcode = 162, a2
literal_match: M
opcode = 162, a2
literal_match: )
opcode = 173, ad
exec backward code:
opcode = 165, a5
opcode = 162, a2
literal_match: b
opcode = 162, a2
literal_match: a
opcode = 173, ad
   */

  uint8_t* forward_code;
  uint8_t* backward_code;  
};


struct RE_CLASS
{
  uint8_t negated;
  uint8_t bitmap[32];
};


struct RE_AST
{
  uint32_t flags;
  RE_NODE* root_node;
};


// Disable warning due to zero length array in Microsoft's compiler

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4200)
#endif

struct RE
{
  uint32_t flags;
  uint8_t code[0];
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif


struct RE_ERROR
{
  char message[384];
};

/* 正则表达式的执行单元 */
struct RE_FIBER
{
  const uint8_t* ip;    // instruction pointer
  int32_t  sp;          // stack pointer
  int32_t  rc;          // repeat counter

  uint16_t stack[RE_MAX_STACK];

  RE_FIBER* prev;
  RE_FIBER* next;
};


struct RE_FIBER_LIST
{
  RE_FIBER* head;
  RE_FIBER* tail;
};


struct RE_FIBER_POOL
{
  int fiber_count;
  RE_FIBER_LIST fibers;
};


struct YR_MATCH
{
  int64_t base;              // Base address for the match
  int64_t offset;            // Offset relative to base for the match
  int32_t match_length;      // Match length
  int32_t data_length;

  // Pointer to a buffer containing a portion of the matched data. The size of
  // the buffer is data_length. data_length is always <= length and is limited
  // to MAX_MATCH_DATA bytes.

  const uint8_t* data;

  // If the match belongs to a chained string chain_length contains the
  // length of the chain. This field is used only in unconfirmed matches.

  int32_t chain_length;

  YR_MATCH* prev;
  YR_MATCH* next;
};


/* aho corasick 树的数据结构 */
struct YR_AC_STATE
{
  uint8_t depth;
  uint8_t input;

  uint32_t t_table_slot;

  YR_AC_STATE* failure;
  YR_AC_STATE* first_child;
  YR_AC_STATE* siblings;
  YR_AC_MATCH* matches;
};


struct YR_AC_AUTOMATON
{
  // Both m_table and t_table have the same number of elements, which is
  // stored in tables_size.
  uint32_t tables_size;

  uint32_t t_table_unused_candidate;

  // Bitmask where each bit indicates if the corresponding slot in m_table
  // and t_table is already in use.
  YR_BITMASK* bitmask;

  YR_AC_TRANSITION_TABLE t_table;
  YR_AC_MATCH_TABLE m_table;
  YR_AC_STATE* root;
};

/*
 * 从原则上来讲，
 * YR_RULES保存的是静态数据，例如rule.
 * YR_SCANNER保存的是动态数据，也就是扫描上下文
 */

struct YR_RULES
{
  unsigned char tidx_mask[YR_BITARRAY_NCHARS(YR_MAX_THREADS)];
  const uint8_t* code_start;  /* hash等函数的执行码????? */

  YR_MUTEX mutex;
  /* 
   * arena 从 compiler->compiled_rules_arena 获得 
   * compiled_rules_arena 是由
   *    0. YARA_RULES_FILE_HEADER
   *    1. code_arena  ====> code_start 从这里获得
   *    2. re_code_arena  ====> 正则表达式 
   *    3. rules_arena   ====> 存放rule (YR_RULE)
   *    4. strings_arena  ====> 匹配字符串(YR_STRING)
   *    5. externals_arena
   *    6. namespace_arena
   *    7. metas_arena
   *    8. sz_arena
   *    9. automaton_arena
   *    10.matches_arena 
   * 合并而成
   */
  YR_ARENA* arena;   
  YR_RULE* rules_list_head;   /* rule 数组, 以gflag &= 0x1000 结束*/

  /*
   * 指针数组, 通过EXTERNAL_VARIABLE_IS_NULL判断是否结束
   * 外部变量是可以在运行时改变的变量，可以应用在rule上.
   * 例如: http_context 可以在http时被设置为'get', 'post', 
   * 对于不同的context，设置不同的filesize
   * external variable 相关的三个函数
   * 1. yr_compiler_define_string_variable
   *    > 将变量加入compiler的object hash table里。 这是一个初始化函数, 必须在编译rule之前调用
   * 2. yr_rules_define_string_variable
   *    > 可以运行时调用，但是它的值为所有thread共享
   * 3. yr_scanner_define_string_variable *    
   *    > 当前thread独有 
   */
  YR_EXTERNAL_VARIABLE* externals_list_head;
  YR_AC_TRANSITION_TABLE ac_transition_table;  /* aho-corasick 状态转换表, 这是一个经典的状态转换表 */
  /* 
   *  静态匹配表, 里面有rule的匹配函数, 每个state会对应一个match_entry 
   *  通过此方式获得: match = rules->ac_match_table[state] 
   *  每个condition，而并非每个rule对应一个match entry 
   *  通过YR_AC_MATCH可以获得string, 通过string可以找到这个string所
   *  在什么地方match的。 YR_STRING->matches[thread_idx]这个list里有保存.
   *  这个list实际所占用的memory保存在scanner->matches_arena; 
   *  因为这个match上下文是动态的
   */
  YR_AC_MATCH_TABLE ac_match_table;  

  // Size of ac_match_table and ac_transition_table in number of items (both
  // tables have the same numbe of items).
  uint32_t ac_tables_size;

  // Used only when PROFILING_ENABLED is defined.
  uint64_t time_cost;
};


struct YR_RULES_STATS
{
  // Total number of rules
  uint32_t rules;

  // Total number of strings across all rules.
  uint32_t strings;

  // Total number of Aho-Corasick matches. Each node in the  Aho-Corasick
  // automaton has a list of YR_AC_MATCH structures (match list) pointing to
  // strings that are potential matches. This field holds the total number of
  // those structures across all nodes in the automaton.
  uint32_t ac_matches;

  // Length of the match list for the root node in the Aho-Corasick automaton.
  uint32_t ac_root_match_list_length;

  // Average number of matches per match list.
  float ac_average_match_list_length;

  // Top 10 longest match lists.
  uint32_t top_ac_match_list_lengths[100];

  // Percentiles of match lists' lengths. If the i-th value in the array is N
  // then i percent of the match lists have N or less items.
  uint32_t ac_match_list_length_pctls[101];

  // Size of Aho-Corasick transition & match tables.
  uint32_t ac_tables_size;
};


typedef const uint8_t* (*YR_MEMORY_BLOCK_FETCH_DATA_FUNC)(
    YR_MEMORY_BLOCK* self);


typedef YR_MEMORY_BLOCK* (*YR_MEMORY_BLOCK_ITERATOR_FUNC)(
    YR_MEMORY_BLOCK_ITERATOR* self);


struct YR_MEMORY_BLOCK
{
  size_t size;
  uint64_t base;

  void* context;

  YR_MEMORY_BLOCK_FETCH_DATA_FUNC fetch_data;
};


struct YR_MEMORY_BLOCK_ITERATOR
{
  void* context;

  YR_MEMORY_BLOCK_ITERATOR_FUNC  first;
  YR_MEMORY_BLOCK_ITERATOR_FUNC  next;
};


typedef int (*YR_CALLBACK_FUNC)(
    int message,
    void* message_data,
    void* user_data);

/*
 * scan context是扫描时需要用到的临时数据, 每个thread一个
 * 但是不仅仅是这个临时数据, 还有rule和string下的matches, 这些都是需要保存的
 * 具体参见_yr_scanner_clean_matches函数中所用到的变量
 */
struct YR_SCAN_CONTEXT
{
  // File size of the file being scanned.
  uint64_t file_size;

  // Entry point of the file being scanned, if the file is PE or ELF.
  uint64_t entry_point;

  // Scanning flags.
  /* SCAN_FLAGS_FAST_MODE/SCAN_FLAGS_PROCESS_MEMORY/SCAN_FLAGS_NO_TRYCACHE */
  int flags;

  // Thread index for the thread using this scan context. The number of threads
  // that can use a YR_RULES object simultaneusly is limited by the YR_MAX_THREADS
  // constant. Each thread using a YR_RULES get assigned a unique thread index
  // in the range [0, YR_MAX_THREADS)
  int tidx;

  // Scan timeout in nanoseconds.
  uint64_t timeout;

  // Pointer to user-provided data passed to the callback function.
  void* user_data;

  // Pointer to the user-provided callback function that is called when an
  // event occurs during the scan (a rule matching, a module being loaded, etc)
  YR_CALLBACK_FUNC callback;

  // Pointer to the YR_RULES object associated to this scan context.
  YR_RULES* rules;

  // Pointer to the YR_STRING causing the most recent scan error.
  YR_STRING* last_error_string;

  // Pointer to the iterator used for scanning
  YR_MEMORY_BLOCK_ITERATOR* iterator;

  // Pointer to a table mapping identifiers to YR_OBJECT structures. This table
  // contains entries for external variables and modules.
  YR_HASH_TABLE* objects_table;

  // Arena used for storing YR_MATCH structures asociated to the matches found.
  YR_ARENA* matches_arena;

  // Arena used for storing pointers to the YR_STRING struct for each matching
  // string. The pointers are used by _yr_scanner_clean_matches.

  /* 
   * 只存放存放指针, 通过此指针可以找到, 每个string的match context 
   * 即便target出现很多次，也只有一个string写入matching_strings_arena
   * 但是string->matches会有多个context
   * string->matches只是存储指针，真正的数据存储在scanner->matches_arena中
   */
  YR_ARENA* matching_strings_arena;

  // Stopwatch used for measuring the time elapsed during the scan.
  YR_STOPWATCH stopwatch;

  // Fiber pool used by yr_re_exec.
  /* 字节码的栈, 用于yr_re_exec */
  RE_FIBER_POOL re_fiber_pool;
};


union YR_VALUE
{
  int64_t i;
  double d;
  void* p;
  YR_OBJECT* o;
  YR_STRING* s;
  SIZED_STRING* ss;
  RE* re;
};


#define OBJECT_COMMON_FIELDS \
    int canary; \
    int8_t type; \
    const char* identifier; \
    YR_OBJECT* parent; \
    void* data;


struct YR_OBJECT
{
  OBJECT_COMMON_FIELDS
  YR_VALUE value;
};


struct YR_OBJECT_STRUCTURE
{
  OBJECT_COMMON_FIELDS
  YR_STRUCTURE_MEMBER* members;
};


struct YR_OBJECT_ARRAY
{
  OBJECT_COMMON_FIELDS
  YR_OBJECT* prototype_item;
  YR_ARRAY_ITEMS* items;
};


struct YR_OBJECT_DICTIONARY
{
  OBJECT_COMMON_FIELDS
  YR_OBJECT* prototype_item;
  YR_DICTIONARY_ITEMS* items;
};


typedef int (*YR_MODULE_FUNC)(
    YR_VALUE* args,
    YR_SCAN_CONTEXT* context,
    YR_OBJECT_FUNCTION* function_obj);


struct YR_OBJECT_FUNCTION
{
  OBJECT_COMMON_FIELDS
  YR_OBJECT* return_obj;

  struct
  {
    const char* arguments_fmt;
    YR_MODULE_FUNC code;
  } prototypes[YR_MAX_OVERLOADED_FUNCTIONS];
};


#define object_as_structure(obj)  ((YR_OBJECT_STRUCTURE*) (obj))
#define object_as_array(obj)      ((YR_OBJECT_ARRAY*) (obj))
#define object_as_dictionary(obj) ((YR_OBJECT_DICTIONARY*) (obj))
#define object_as_function(obj)   ((YR_OBJECT_FUNCTION*) (obj))


struct YR_STRUCTURE_MEMBER
{
  YR_OBJECT* object;
  YR_STRUCTURE_MEMBER* next;
};


struct YR_ARRAY_ITEMS
{
  int count;
  YR_OBJECT* objects[1];
};


struct YR_DICTIONARY_ITEMS
{
  int used;
  int free;

  struct {

    char* key;
    YR_OBJECT* obj;

  } objects[1];
};


#endif
