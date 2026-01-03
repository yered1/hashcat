/**
 * Author......: Pattern-Dictionary Feed Plugin
 * License.....: MIT
 *
 * Pattern-Dictionary Attack Feed for hashcat
 *
 * Usage: hashcat -a 8 -m <hash_type> <hash_file> feeds/feed_pattern_dict.so <pattern> <wordlist>
 *
 * Pattern Syntax:
 *   ?l - lowercase letter (a-z)
 *   ?u - uppercase letter (A-Z)
 *   ?d - digit (0-9)
 *   ?s - special characters (!@#$%^&*...)
 *   ?a - all printable ASCII (?l?u?d?s)
 *   ?h - hex lowercase (0-9a-f)
 *   ?H - hex uppercase (0-9A-F)
 *   ?W - dictionary word placeholder (required, exactly one)
 *
 * Examples:
 *   ?d?d?W?s      -> 00word! 01word@ ... 99word~
 *   ?l?W?d?d      -> aword00 aword01 ... zword99
 *   ?u?u?W?d?d?s  -> AAword00! AAword00@ ... ZZword99~
 *   ?h?h?W        -> 00word 01word ... ffword
 */

#ifndef FEED_PATTERN_DICT_H
#define FEED_PATTERN_DICT_H

#ifndef O_BINARY
#define O_BINARY 0
#endif

// Maximum pattern length (excluding word)
#define PATTERN_MAX_POSITIONS 32

// Character set definitions matching hashcat's mask system
#define CS_LOWER_LEN   26
#define CS_UPPER_LEN   26
#define CS_DIGIT_LEN   10
#define CS_SPECIAL_LEN 33
#define CS_HEX_LOW_LEN 16
#define CS_HEX_UP_LEN  16
#define CS_ALL_LEN     (CS_LOWER_LEN + CS_UPPER_LEN + CS_DIGIT_LEN + CS_SPECIAL_LEN)

// Pattern position types
typedef enum pattern_pos_type
{
  POS_LOWER   = 0,  // ?l
  POS_UPPER   = 1,  // ?u
  POS_DIGIT   = 2,  // ?d
  POS_SPECIAL = 3,  // ?s
  POS_ALL     = 4,  // ?a
  POS_HEX_LOW = 5,  // ?h - hex lowercase
  POS_HEX_UP  = 6,  // ?H - hex uppercase
  POS_WORD    = 7,  // ?W - the dictionary word
  POS_LITERAL = 8,  // literal character

} pattern_pos_type_t;

// A single position in the pattern
typedef struct pattern_position
{
  pattern_pos_type_t type;
  u8   literal_char;      // for POS_LITERAL
  u32  charset_len;       // number of characters in this position's charset
  u8  *charset;           // pointer to charset array

} pattern_position_t;

// Global context for pattern-dictionary feed
typedef struct pd_feed_global
{
  char *pattern;           // the pattern string
  char *wordlist;          // path to wordlist file

  // Parsed pattern
  pattern_position_t positions[PATTERN_MAX_POSITIONS];
  u32 num_positions;       // total positions in pattern
  u32 word_position;       // index of ?W in positions array
  u32 prefix_len;          // number of positions before ?W
  u32 suffix_len;          // number of positions after ?W

  // Character sets
  u8 cs_lower[CS_LOWER_LEN];
  u8 cs_upper[CS_UPPER_LEN];
  u8 cs_digit[CS_DIGIT_LEN];
  u8 cs_special[CS_SPECIAL_LEN];
  u8 cs_hex_low[CS_HEX_LOW_LEN];
  u8 cs_hex_up[CS_HEX_UP_LEN];
  u8 cs_all[CS_ALL_LEN];

  // Wordlist data
  u64  word_count;         // number of words in dictionary
  u64  mask_keyspace;      // combinations from mask positions (excludes word)
  u64  total_keyspace;     // word_count * mask_keyspace

  // Word index - positions of each word start in mmap'd file
  u64 *word_offsets;
  u32 *word_lengths;

  // File info
  u64 file_size;

} pd_feed_global_t;

// Per-thread context
typedef struct pd_feed_thread
{
  HCFILE hcfile;

  void  *fd_mem;           // mmap'd wordlist
  size_t fd_len;

  u64    current_word_idx; // current word index (0 to word_count-1)
  u64    current_mask_idx; // current mask combination index (0 to mask_keyspace-1)
  u64    current_offset;   // overall offset in keyspace

  // Precomputed mask combination state
  u32 mask_indices[PATTERN_MAX_POSITIONS];

} pd_feed_thread_t;

// Plugin interface functions
bool global_init      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx);
void global_term      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx);
u64  global_keyspace  (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx);

bool thread_init      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx);
void thread_term      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx);
int  thread_next      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf);
bool thread_seek      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset);

#endif // FEED_PATTERN_DICT_H
