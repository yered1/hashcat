/**
 * Author......: Pattern-Dictionary Feed Plugin
 * License.....: MIT
 *
 * Pattern-Dictionary Attack Feed for hashcat
 *
 * This feed plugin enables pattern-based dictionary attacks where dictionary
 * words can be embedded within mask patterns. For example, the pattern
 * "?d?d?W?s" will generate candidates like "00password!", "01password@", etc.
 *
 * Usage:
 *   hashcat -a 8 -m <hash_type> <hash_file> feeds/feed_pattern_dict.so <pattern> <wordlist>
 *
 * Pattern Syntax:
 *   ?l - lowercase letter (a-z)
 *   ?u - uppercase letter (A-Z)
 *   ?d - digit (0-9)
 *   ?s - special characters
 *   ?a - all printable ASCII
 *   ?h - hex lowercase (0-9a-f)
 *   ?H - hex uppercase (0-9A-F)
 *   ?W - dictionary word placeholder (exactly one required)
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "convert.h"
#include "filehandling.h"
#include "folder.h"
#include "shared.h"
#include "timer.h"
#include "event.h"
#include "generic.h"
#include "feed_pattern_dict.h"

#if defined (_WIN)
#include "mmap_windows.c"
#else
#include <sys/mman.h>
#endif

const int GENERIC_PLUGIN_VERSION = GENERIC_PLUGIN_VERSION_REQ;

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_AUTOHEX
                                 | GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES;

// Character set definitions
static const u8 CHARSET_LOWER[]   = "abcdefghijklmnopqrstuvwxyz";
static const u8 CHARSET_UPPER[]   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const u8 CHARSET_DIGIT[]   = "0123456789";
static const u8 CHARSET_SPECIAL[] = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static const u8 CHARSET_HEX_LOW[] = "0123456789abcdef";
static const u8 CHARSET_HEX_UP[]  = "0123456789ABCDEF";

static void error_set (generic_global_ctx_t *global_ctx, const char *fmt, ...)
{
  global_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (global_ctx->error_msg, sizeof (global_ctx->error_msg), fmt, ap);

  va_end (ap);
}

static void init_charsets (pd_feed_global_t *ctx)
{
  memcpy (ctx->cs_lower,   CHARSET_LOWER,   CS_LOWER_LEN);
  memcpy (ctx->cs_upper,   CHARSET_UPPER,   CS_UPPER_LEN);
  memcpy (ctx->cs_digit,   CHARSET_DIGIT,   CS_DIGIT_LEN);
  memcpy (ctx->cs_special, CHARSET_SPECIAL, CS_SPECIAL_LEN);
  memcpy (ctx->cs_hex_low, CHARSET_HEX_LOW, CS_HEX_LOW_LEN);
  memcpy (ctx->cs_hex_up,  CHARSET_HEX_UP,  CS_HEX_UP_LEN);

  // Build "all" charset
  u32 offset = 0;
  memcpy (ctx->cs_all + offset, CHARSET_LOWER, CS_LOWER_LEN);
  offset += CS_LOWER_LEN;
  memcpy (ctx->cs_all + offset, CHARSET_UPPER, CS_UPPER_LEN);
  offset += CS_UPPER_LEN;
  memcpy (ctx->cs_all + offset, CHARSET_DIGIT, CS_DIGIT_LEN);
  offset += CS_DIGIT_LEN;
  memcpy (ctx->cs_all + offset, CHARSET_SPECIAL, CS_SPECIAL_LEN);
}

static int parse_pattern (generic_global_ctx_t *global_ctx, pd_feed_global_t *ctx, const char *pattern)
{
  ctx->num_positions = 0;
  ctx->word_position = (u32)-1;
  ctx->prefix_len = 0;
  ctx->suffix_len = 0;

  bool found_word = false;
  size_t len = strlen (pattern);
  size_t i = 0;

  while (i < len)
  {
    if (ctx->num_positions >= PATTERN_MAX_POSITIONS)
    {
      error_set (global_ctx, "Pattern too long: maximum %d positions", PATTERN_MAX_POSITIONS);
      return -1;
    }

    pattern_position_t *pos = &ctx->positions[ctx->num_positions];

    if (pattern[i] == '?')
    {
      if (i + 1 >= len)
      {
        error_set (global_ctx, "Invalid pattern: '?' at end of pattern");
        return -1;
      }

      char spec = pattern[i + 1];
      i += 2;

      switch (spec)
      {
        case 'l':
          pos->type = POS_LOWER;
          pos->charset = ctx->cs_lower;
          pos->charset_len = CS_LOWER_LEN;
          break;

        case 'u':
          pos->type = POS_UPPER;
          pos->charset = ctx->cs_upper;
          pos->charset_len = CS_UPPER_LEN;
          break;

        case 'd':
          pos->type = POS_DIGIT;
          pos->charset = ctx->cs_digit;
          pos->charset_len = CS_DIGIT_LEN;
          break;

        case 's':
          pos->type = POS_SPECIAL;
          pos->charset = ctx->cs_special;
          pos->charset_len = CS_SPECIAL_LEN;
          break;

        case 'a':
          pos->type = POS_ALL;
          pos->charset = ctx->cs_all;
          pos->charset_len = CS_ALL_LEN;
          break;

        case 'h':
          pos->type = POS_HEX_LOW;
          pos->charset = ctx->cs_hex_low;
          pos->charset_len = CS_HEX_LOW_LEN;
          break;

        case 'H':
          pos->type = POS_HEX_UP;
          pos->charset = ctx->cs_hex_up;
          pos->charset_len = CS_HEX_UP_LEN;
          break;

        case 'W':
          if (found_word)
          {
            error_set (global_ctx, "Invalid pattern: only one ?W allowed");
            return -1;
          }
          pos->type = POS_WORD;
          pos->charset = NULL;
          pos->charset_len = 0;
          ctx->word_position = ctx->num_positions;
          found_word = true;
          break;

        case '?':
          // Escaped question mark
          pos->type = POS_LITERAL;
          pos->literal_char = '?';
          pos->charset = &pos->literal_char;
          pos->charset_len = 1;
          break;

        default:
          error_set (global_ctx, "Invalid pattern character: ?%c", spec);
          return -1;
      }
    }
    else
    {
      // Literal character
      pos->type = POS_LITERAL;
      pos->literal_char = (u8)pattern[i];
      pos->charset = &pos->literal_char;
      pos->charset_len = 1;
      i++;
    }

    ctx->num_positions++;
  }

  if (!found_word)
  {
    error_set (global_ctx, "Invalid pattern: ?W (word placeholder) is required");
    return -1;
  }

  // Count prefix and suffix positions
  for (u32 j = 0; j < ctx->num_positions; j++)
  {
    if (j < ctx->word_position)
    {
      ctx->prefix_len++;
    }
    else if (j > ctx->word_position)
    {
      ctx->suffix_len++;
    }
  }

  return 0;
}

static u64 count_words (const u8 *data, size_t data_len)
{
  u64 count = 0;

  for (size_t i = 0; i < data_len; i++)
  {
    if (data[i] == '\n')
    {
      count++;
    }
  }

  // Count last line if it doesn't end with newline
  if (data_len > 0 && data[data_len - 1] != '\n')
  {
    count++;
  }

  return count;
}

static int build_word_index (generic_global_ctx_t *global_ctx, pd_feed_global_t *ctx, const u8 *data, size_t data_len)
{
  // First pass: count words
  ctx->word_count = count_words (data, data_len);

  if (ctx->word_count == 0)
  {
    error_set (global_ctx, "Wordlist is empty");
    return -1;
  }

  // Check for allocation size overflow
  if (ctx->word_count > SIZE_MAX / sizeof (u64))
  {
    error_set (global_ctx, "Wordlist too large: %llu words", (unsigned long long)ctx->word_count);
    return -1;
  }

  // Allocate word index
  ctx->word_offsets = (u64 *)hcmalloc (ctx->word_count * sizeof (u64));

  if (ctx->word_offsets == NULL)
  {
    error_set (global_ctx, "Failed to allocate word offsets");
    return -1;
  }

  ctx->word_lengths = (u32 *)hcmalloc (ctx->word_count * sizeof (u32));

  if (ctx->word_lengths == NULL)
  {
    hcfree (ctx->word_offsets);
    ctx->word_offsets = NULL;
    error_set (global_ctx, "Failed to allocate word lengths");
    return -1;
  }

  // Second pass: record word positions
  u64 word_idx = 0;
  size_t line_start = 0;

  for (size_t i = 0; i < data_len; i++)
  {
    if (data[i] == '\n')
    {
      size_t line_len = i - line_start;

      // Strip trailing \r if present
      if (line_len > 0 && data[line_start + line_len - 1] == '\r')
      {
        line_len--;
      }

      ctx->word_offsets[word_idx] = line_start;
      ctx->word_lengths[word_idx] = (u32)line_len;
      word_idx++;

      line_start = i + 1;
    }
  }

  // Handle last line without newline
  if (line_start < data_len)
  {
    size_t line_len = data_len - line_start;

    if (line_len > 0 && data[line_start + line_len - 1] == '\r')
    {
      line_len--;
    }

    ctx->word_offsets[word_idx] = line_start;
    ctx->word_lengths[word_idx] = (u32)line_len;
  }

  return 0;
}

static u64 calculate_mask_keyspace (pd_feed_global_t *ctx)
{
  u64 keyspace = 1;

  for (u32 i = 0; i < ctx->num_positions; i++)
  {
    if (ctx->positions[i].type != POS_WORD)
    {
      u64 cs_len = ctx->positions[i].charset_len;

      // Check for overflow before multiplying
      if (keyspace > 0 && cs_len > UINT64_MAX / keyspace)
      {
        return UINT64_MAX; // Overflow, return max value
      }

      keyspace *= cs_len;
    }
  }

  return keyspace;
}

static void index_to_mask_indices (pd_feed_global_t *ctx, u64 mask_idx, u32 *indices)
{
  // Convert linear index to per-position indices (like mixed-radix number conversion)
  // Process in reverse order for correct odometer-style iteration

  u64 remaining = mask_idx;

  for (int i = (int)ctx->num_positions - 1; i >= 0; i--)
  {
    if (ctx->positions[i].type == POS_WORD)
    {
      indices[i] = 0;
      continue;
    }

    u32 cs_len = ctx->positions[i].charset_len;
    indices[i] = (u32)(remaining % cs_len);
    remaining /= cs_len;
  }
}

static int generate_candidate (pd_feed_global_t *ctx, pd_feed_thread_t *tctx,
                               const u8 *fd_mem, u8 *out_buf)
{
  u32 out_len = 0;

  // Get current word
  u64 word_idx = tctx->current_word_idx;
  u64 word_off = ctx->word_offsets[word_idx];
  u32 word_len = ctx->word_lengths[word_idx];

  // Generate prefix (positions before ?W)
  for (u32 i = 0; i < ctx->word_position; i++)
  {
    pattern_position_t *pos = &ctx->positions[i];
    out_buf[out_len++] = pos->charset[tctx->mask_indices[i]];
  }

  // Add the word
  if (out_len + word_len > PW_MAX)
  {
    word_len = PW_MAX - out_len;
  }
  memcpy (out_buf + out_len, fd_mem + word_off, word_len);
  out_len += word_len;

  // Generate suffix (positions after ?W)
  for (u32 i = ctx->word_position + 1; i < ctx->num_positions; i++)
  {
    if (out_len >= PW_MAX) break;
    pattern_position_t *pos = &ctx->positions[i];
    out_buf[out_len++] = pos->charset[tctx->mask_indices[i]];
  }

  return (int)out_len;
}

static void advance_position (pd_feed_thread_t *tctx, pd_feed_global_t *ctx)
{
  // Advance mask index first
  tctx->current_mask_idx++;

  if (tctx->current_mask_idx >= ctx->mask_keyspace)
  {
    // Move to next word
    tctx->current_mask_idx = 0;
    tctx->current_word_idx++;
  }

  // Update mask indices for current mask_idx
  if (tctx->current_word_idx < ctx->word_count)
  {
    index_to_mask_indices (ctx, tctx->current_mask_idx, tctx->mask_indices);
  }

  tctx->current_offset++;
}

// ============================================================================
// Plugin Interface Functions
// ============================================================================

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  // Create our context
  pd_feed_global_t *ctx = hcmalloc (sizeof (pd_feed_global_t));

  if (ctx == NULL)
  {
    error_set (global_ctx, "Failed to allocate global context");
    return false;
  }

  memset (ctx, 0, sizeof (pd_feed_global_t));
  global_ctx->gbldata = ctx;

  // Check arguments: we need at least 3 (plugin_path, pattern, wordlist)
  if (global_ctx->workc < 3)
  {
    error_set (global_ctx, "Usage: feeds/feed_pattern_dict.so <pattern> <wordlist>\n"
               "Pattern placeholders: ?l (lower) ?u (upper) ?d (digit) ?s (special) ?a (all) ?h (hex) ?H (HEX) ?W (word)");
    hcfree (ctx);
    global_ctx->gbldata = NULL;
    return false;
  }

  ctx->pattern  = global_ctx->workv[1];
  ctx->wordlist = global_ctx->workv[2];

  // Initialize character sets
  init_charsets (ctx);

  // Parse the pattern
  if (parse_pattern (global_ctx, ctx, ctx->pattern) == -1)
  {
    hcfree (ctx);
    global_ctx->gbldata = NULL;
    return false;
  }

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  pd_feed_global_t *ctx = global_ctx->gbldata;

  if (ctx)
  {
    if (ctx->word_offsets) hcfree (ctx->word_offsets);
    if (ctx->word_lengths) hcfree (ctx->word_lengths);

    hcfree (ctx);
  }

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  pd_feed_global_t *ctx = global_ctx->gbldata;

  // We need to scan the wordlist to count words
  // Use thread 0 for this

  if (thread_init (global_ctx, thread_ctx[0]) == false)
  {
    return 0;
  }

  pd_feed_thread_t *tctx = thread_ctx[0]->thrdata;

  hc_timer_t start;
  hc_timer_set (&start);

  // Build word index from mmap'd file
  if (build_word_index (global_ctx, ctx, (const u8 *)tctx->fd_mem, tctx->fd_len) == -1)
  {
    thread_term (global_ctx, thread_ctx[0]);
    return 0;
  }

  ctx->file_size = tctx->fd_len;

  // Calculate total keyspace
  ctx->mask_keyspace = calculate_mask_keyspace (ctx);

  // Check for overflow before calculating total keyspace
  if (ctx->mask_keyspace > 0 && ctx->word_count > UINT64_MAX / ctx->mask_keyspace)
  {
    ctx->total_keyspace = UINT64_MAX; // Overflow, use max value
  }
  else
  {
    ctx->total_keyspace = ctx->word_count * ctx->mask_keyspace;
  }

  cache_generate_t cache_generate;

  cache_generate.dictfile = ctx->wordlist;
  cache_generate.comp     = ctx->file_size;
  cache_generate.percent  = 100;
  cache_generate.cnt      = ctx->word_count;
  cache_generate.cnt2     = ctx->total_keyspace;
  cache_generate.runtime  = hc_timer_get (start);

  EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));

  thread_term (global_ctx, thread_ctx[0]);

  return ctx->total_keyspace;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  pd_feed_global_t *ctx = global_ctx->gbldata;

  pd_feed_thread_t *tctx = hcmalloc (sizeof (pd_feed_thread_t));

  if (tctx == NULL)
  {
    error_set (global_ctx, "Failed to allocate thread context");
    return false;
  }

  memset (tctx, 0, sizeof (pd_feed_thread_t));
  thread_ctx->thrdata = tctx;

  // Open wordlist file
  if (hc_fopen_raw (&tctx->hcfile, ctx->wordlist, "rb") == false)
  {
    error_set (global_ctx, "%s: %s", ctx->wordlist, strerror (errno));
    hcfree (tctx);
    thread_ctx->thrdata = NULL;
    return false;
  }

  struct stat s;

  if (hc_fstat (&tctx->hcfile, &s) == -1)
  {
    error_set (global_ctx, "%s: %s", ctx->wordlist, strerror (errno));
    hc_fclose (&tctx->hcfile);
    hcfree (tctx);
    thread_ctx->thrdata = NULL;
    return false;
  }

  if (s.st_size == 0)
  {
    error_set (global_ctx, "%s: empty file", ctx->wordlist);
    hc_fclose (&tctx->hcfile);
    hcfree (tctx);
    thread_ctx->thrdata = NULL;
    return false;
  }

  tctx->fd_len = s.st_size;

  // Memory-map the file
  void *fd_mem = mmap (NULL, tctx->fd_len, PROT_READ, MAP_PRIVATE, tctx->hcfile.fd, 0);

  if (fd_mem == MAP_FAILED)
  {
    error_set (global_ctx, "%s: mmap failed", ctx->wordlist);
    hc_fclose (&tctx->hcfile);
    hcfree (tctx);
    thread_ctx->thrdata = NULL;
    return false;
  }

  tctx->fd_mem = fd_mem;

  // Kernel advice for sequential access
  #if !defined (_WIN)
  #ifdef POSIX_MADV_SEQUENTIAL
  posix_madvise (tctx->fd_mem, tctx->fd_len, POSIX_MADV_SEQUENTIAL);
  #endif
  #endif

  // Initialize position
  tctx->current_word_idx = 0;
  tctx->current_mask_idx = 0;
  tctx->current_offset = 0;

  // Initialize mask indices to first combination
  index_to_mask_indices (ctx, 0, tctx->mask_indices);

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  pd_feed_thread_t *tctx = thread_ctx->thrdata;

  if (tctx)
  {
    if (tctx->fd_mem)
    {
      munmap (tctx->fd_mem, tctx->fd_len);
    }

    hc_fclose (&tctx->hcfile);

    hcfree (tctx);
  }

  thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf)
{
  pd_feed_global_t *ctx = global_ctx->gbldata;
  pd_feed_thread_t *tctx = thread_ctx->thrdata;

  // Check if we've exhausted all candidates
  if (tctx->current_word_idx >= ctx->word_count)
  {
    return 0;
  }

  // Generate the current candidate
  int out_len = generate_candidate (ctx, tctx, (const u8 *)tctx->fd_mem, out_buf);

  // Advance to next position
  advance_position (tctx, ctx);

  return out_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  pd_feed_global_t *ctx = global_ctx->gbldata;
  pd_feed_thread_t *tctx = thread_ctx->thrdata;

  if (offset >= ctx->total_keyspace)
  {
    error_set (global_ctx, "Seek offset %llu past keyspace %llu",
               (unsigned long long)offset, (unsigned long long)ctx->total_keyspace);
    return false;
  }

  // Calculate word index and mask index from offset
  // offset = word_idx * mask_keyspace + mask_idx
  tctx->current_word_idx = offset / ctx->mask_keyspace;
  tctx->current_mask_idx = offset % ctx->mask_keyspace;
  tctx->current_offset = offset;

  // Update mask indices
  index_to_mask_indices (ctx, tctx->current_mask_idx, tctx->mask_indices);

  return true;
}
