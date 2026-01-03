# Pattern-Dictionary Attack Feed for hashcat

The Pattern-Dictionary Attack is a powerful attack mode that allows embedding dictionary words within customizable mask patterns. This enables testing passwords that follow common patterns like:

- `Summer2024!` → `?u?l?l?l?l?l?W?s` where word="2024"
- `123password!` → `?d?d?d?W?s`
- `admin@2024` → `?W?s?d?d?d?d`

## Overview

Unlike hybrid attacks (`-a 6` and `-a 7`) which only prepend or append masks to words, the Pattern-Dictionary feed allows placing the word **anywhere** within the pattern, surrounded by any combination of character classes.

## Installation

The feed plugin is included with hashcat and compiles automatically:

```bash
make feeds
```

The plugin is located at: `feeds/feed_pattern_dict.so`

## Usage

```bash
hashcat -a 8 -m <hash_type> <hash_file> feeds/feed_pattern_dict.so '<pattern>' <wordlist>
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-a 8` | Generic attack mode (required for feed plugins) |
| `-m <type>` | Hash type (e.g., 0 for MD5) |
| `<hash_file>` | File containing hashes to crack |
| `<pattern>` | The pattern with placeholders (see below) |
| `<wordlist>` | Path to dictionary file |

## Pattern Syntax

### Placeholders

| Placeholder | Description | Characters |
|-------------|-------------|------------|
| `?l` | Lowercase letters | a-z (26 chars) |
| `?u` | Uppercase letters | A-Z (26 chars) |
| `?d` | Digits | 0-9 (10 chars) |
| `?s` | Special characters | ` !"#$%&'()*+,-./:;<=>?@[\]^_\`{|}~` (33 chars) |
| `?a` | All printable ASCII | ?l + ?u + ?d + ?s (95 chars) |
| `?h` | Hex lowercase | 0-9a-f (16 chars) |
| `?H` | Hex uppercase | 0-9A-F (16 chars) |
| `?b` | Binary | 0x00-0xff (256 chars) |
| `?1` | Custom charset 1 | Defined with `-1` option |
| `?2` | Custom charset 2 | Defined with `-2` option |
| `?3` | Custom charset 3 | Defined with `-3` option |
| `?4` | Custom charset 4 | Defined with `-4` option |
| `?W` | **Dictionary word** | Words from wordlist |
| `??` | Literal `?` | Single ? character |

**Important:** Exactly one `?W` placeholder is required in the pattern.

### Custom Charsets

Custom charsets allow you to define your own character sets by combining built-in charsets or specifying literal characters:

```bash
# Define ?1 as lowercase + digits
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so -1 '?l?d' '?1?1?W' wordlist.txt

# Define ?1 as vowels only
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so -1 'aeiouAEIOU' '?1?W?1' wordlist.txt

# Define multiple custom charsets
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so -1 '?l?d' -2 '!@#$' '?1?W?2' wordlist.txt

# Custom charsets can reference other custom charsets
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so -1 '?l?u' -2 '?1?d' '?2?W' wordlist.txt
```

### Literal Characters

Any character that is not part of a placeholder is treated as a literal:

- `Company?W?d?d?d` → "Company" + word + 3 digits
- `2024?W!` → "2024" + word + "!"

## Examples

### Example 1: Digits before, special after

```bash
# Pattern: 2 digits + word + special character
# Wordlist: rockyou.txt
# Generates: 00password!, 01password@, ..., 99zzzzzz~

hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so '?d?d?W?s' rockyou.txt
```

### Example 2: Common corporate password pattern

```bash
# Pattern: Uppercase + word + year + special
# Generates: Aspring2024!, Bspring2024@, ..., Zwinter2024~

echo -e "spring\nsummer\nfall\nwinter" > seasons.txt
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so '?u?W2024?s' seasons.txt
```

### Example 3: Preview candidates with --stdout

```bash
hashcat -a 8 --stdout feeds/feed_pattern_dict.so '?d?d?W?s' wordlist.txt | head -100
```

### Example 4: Email-style pattern

```bash
# Pattern: word + @ + domain
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so '?W@company.com' usernames.txt
```

### Example 5: Complex password policy

```bash
# Pattern: Uppercase + lowercase + word + 2 digits + 2 special
# Generates: Aapassword00!!, Aapassword00!@, ..., Zztest99~~

hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so '?u?l?W?d?d?s?s' words.txt
```

### Example 6: Custom charset - alphanumeric only

```bash
# Define ?1 as lowercase + digits (no special chars)
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so -1 '?l?d' '?1?1?W?1?1' words.txt
```

### Example 7: Custom charset - specific characters

```bash
# Define ?1 as common password suffixes
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so -1 '!@#$123' '?W?1?1' words.txt
```

### Example 8: Binary charset for raw bytes

```bash
# Use binary charset (?b) for raw byte fuzzing - use with caution, very large keyspace!
# Generates all 256 byte values at each ?b position
hashcat -a 8 -m 0 hashes.txt feeds/feed_pattern_dict.so '?b?W?b' words.txt
```

## Keyspace Calculation

The total keyspace is calculated as:

```
Total Candidates = Word Count × Π(Charset Size for each position)
```

For example, with pattern `?d?d?W?s` and 1000 words:
- `?d` = 10 options
- `?d` = 10 options
- `?W` = 1000 words
- `?s` = 33 options

Total = 10 × 10 × 1000 × 33 = **3,300,000 candidates**

## Performance Tips

1. **Order matters for patterns**: Put high-cardinality placeholders (like `?a`) at the end for better cache performance.

2. **Use smaller charsets when possible**: `?d` (10 chars) is much faster than `?a` (95 chars).

3. **Pre-filter your wordlist**: Remove duplicates and very long words:
   ```bash
   sort -u wordlist.txt | awk 'length <= 20' > filtered.txt
   ```

4. **Use rules for case variations**: Instead of trying both `password` and `Password`, use rules:
   ```bash
   hashcat -a 8 -m 0 -r rules/best64.rule hashes.txt feeds/feed_pattern_dict.so '?d?W?s' words.txt
   ```

## Comparison with Hybrid Attacks

| Feature | Hybrid1 (-a 6) | Hybrid2 (-a 7) | Pattern-Dict |
|---------|----------------|----------------|--------------|
| Mask position | After word | Before word | **Anywhere** |
| Multiple positions | No | No | **Yes** |
| Literal chars | No | No | **Yes** |
| Custom charsets | Yes | Yes | **Yes** |
| Binary charset | No | No | **Yes** |
| Flexibility | Limited | Limited | **High** |

## Use Cases for Penetration Testing

1. **Corporate passwords**: `Company?W?d?d?d?d!`
2. **Date patterns**: `?W?d?d?d?d` (word + year)
3. **Leetspeak variants**: `?d?W?d` (number replacements)
4. **Email addresses**: `?W@domain.com`
5. **PIN patterns**: `?d?d?d?d?W`
6. **Keyboard walks**: `qwerty?W?d?d`

## Troubleshooting

### "?W (word placeholder) is required"
Your pattern must include exactly one `?W` placeholder.

### "only one ?W allowed"
Patterns with multiple `?W` placeholders are not supported.

### "Pattern too long"
Maximum of 32 pattern positions (excluding the word itself).

### "Custom charset ?N not defined"
You're using `?1`, `?2`, `?3`, or `?4` in your pattern but haven't defined it. Add the corresponding option:
```bash
hashcat -a 8 ... feeds/feed_pattern_dict.so -1 '?l?d' '?1?W' wordlist.txt
```

### "Custom charset ?N referenced before definition"
When defining custom charsets that reference other custom charsets, define them in order:
```bash
# Wrong: -2 references ?1 which isn't defined yet
feeds/feed_pattern_dict.so -2 '?1?d' -1 '?l?u' ...

# Correct: define -1 before -2
feeds/feed_pattern_dict.so -1 '?l?u' -2 '?1?d' ...
```

### No output with --stdout
Ensure you have OpenCL/CUDA drivers installed, even for --stdout mode.

## Contributing

The source code is located at:
- `src/feeds/feed_pattern_dict.c` - Main implementation
- `src/feeds/feed_pattern_dict.h` - Header file

## License

MIT License - Same as hashcat
