const std = @import("std");
const algo = @import("algorithms.zig");
const Thread = std.Thread;
const atomic = std.atomic;
const statistic = @import("utils/statistic.zig");

pub const BruteforceConfig = struct {
    wordlist_path: ?[]const u8 = null,
    max_length: usize = 8,
    charset: CharSet = .All,
    max_threads: usize = 4,
    verbose: bool = false,
};

pub const CharSet = enum {
    Lowercase,
    Uppercase,
    Digits,
    Special,
    All,
    Custom,
};

pub const AttackMode = enum {
    Dictionary,
    BruteForce,
    Hybrid,
    MaskAttack,
    RainbowTable,
};

const common_words = [_][]const u8{
    "password",  "123456",    "admin",       "welcome",   "qwerty",
    "letmein",   "monkey",    "dragon",      "baseball",  "football",
    "secret",    "abc123",    "password123", "test",      "123",
    "qwerty123", "1234",      "12345",       "123456789", "iloveyou",
    "adobe123",  "sunshine",  "princess",    "azerty",    "passw0rd",
    "whatever",  "trustno1",  "000000",      "password1", "123123",
    "111111",    "12345678",  "qwerty123",   "1q2w3e4r",  "987654321",
    "myspace1",  "888888",    "fuckyou",     "121212",    "1234qwer",
    "superman",  "marketing", "starwars",    "summer",    "computer",
    "bitcoin",   "master",    "hello",       "freedom",   "shadow",
};

/// Attempts to bruteforce decrypt the input using the specified algorithm
pub fn bruteforce(allocator: std.mem.Allocator, input: []const u8, algo_type_str: []const u8) !?[]u8 {
    // Create default configuration
    const config = BruteforceConfig{};
    return try bruteforceWithConfig(allocator, input, algo_type_str, config);
}

/// Attempts to bruteforce decrypt with specific configuration
pub fn bruteforceWithConfig(allocator: std.mem.Allocator, input: []const u8, algo_type_str: []const u8, config: BruteforceConfig) !?[]u8 {
    const algo_type = algo.AlgorithmType.fromString(algo_type_str) orelse return null;

    switch (algo_type) {
        .Base64 => {
            return try algo.decodeBase64(allocator, input);
        },
        .Base32 => {
            return try algo.decodeBase32(allocator, input);
        },
        .Hex => {
            return try algo.decodeHex(allocator, input);
        },
        .URL => {
            return try algo.decodeURL(allocator, input);
        },
        .JWT => {
            return try algo.decodeJWT(allocator, input);
        },
        .ROT13 => {
            return try algo.rot13(allocator, input);
        },
        .Caesar => {
            return try bruteforceCaesar(allocator, input);
        },
        .Vigenere => {
            return try algo.decryptVigenere(allocator, input);
        },
        // For hashes, do actual bruteforcing
        .MD5, .SHA1, .SHA224, .SHA256, .SHA384, .SHA512, .NTLM, .BCrypt => {

            // First try dictionary attack (faster)
            if (try dictionaryAttack(allocator, input, algo_type, config)) |result| {
                return result;
            }

            // Then try hybrid attack (combinations of words and numbers)
            if (try hybridAttack(allocator, input, algo_type, config)) |result| {
                return result;
            }

            // Last resort: pure brute force with character set
            if (config.max_length <= 6) {
                if (try bruteforceAttack(allocator, input, algo_type, config)) |result| {
                    return result;
                }
            }

            return null;
        },
        else => {
            return null;
        },
    }
}

/// Brute forces Caesar cipher by trying all shifts and using frequency analysis
fn bruteforceCaesar(allocator: std.mem.Allocator, input: []const u8) !?[]u8 {
    const all_shifts = try algo.tryDecryptCaesar(allocator, input);
    defer {
        for (all_shifts) |shift| {
            allocator.free(shift);
        }
        allocator.free(all_shifts);
    }

    if (all_shifts.len == 0) return null;

    // Find the best shift using multiple analysis techniques
    var best_english_score: f64 = -1.0;
    var best_english_index: usize = 0;
    var best_word_count: usize = 0;
    var best_word_index: usize = 0;

    for (all_shifts, 0..) |shift, i| {
        // Count recognizable English words
        var word_count: usize = 0;
        const shift_text = shift;

        // Create a lowercase version for case-insensitive processing
        var lowercase_buf: [1024]u8 = undefined;
        const lowercase_text = if (shift_text.len <= lowercase_buf.len) blk: {
            var j: usize = 0;
            while (j < shift_text.len) : (j += 1) {
                lowercase_buf[j] = std.ascii.toLower(shift_text[j]);
            }
            break :blk lowercase_buf[0..shift_text.len];
        } else shift_text;

        const word_list = [_][]const u8{
            "the",   "and",   "that",  "for",     "you",    "with",
            "this",  "have",  "from",  "are",     "one",    "but",
            "not",   "what",  "all",   "were",    "when",   "your",
            "can",   "said",  "there", "use",     "word",   "how",
            "each",  "she",   "which", "their",   "will",   "other",
            "about", "many",  "then",  "them",    "these",  "would",
            "write", "like",  "some",  "could",   "make",   "time",
            "has",   "look",  "more",  "day",     "into",   "year",
            "come",  "think", "see",   "number",  "person", "over",
            "hello", "world", "quick", "brown",   "fox",    "jumps",
            "lazy",  "dog",   "test",  "example",
        };

        for (word_list) |word| {
            if (std.mem.indexOf(u8, lowercase_text, word)) |_| {
                word_count += 1;
            }
        }

        // Also use statistical scoring based on letter frequency
        const english_score = statistic.scoreEnglishText(shift);

        // Track best scores by both methods
        if (word_count > best_word_count) {
            best_word_count = word_count;
            best_word_index = i;
        }

        if (english_score > best_english_score) {
            best_english_score = english_score;
            best_english_index = i;
        }
    }

    // Choose best result: prefer word detection if significant words found,
    // otherwise use statistical scoring
    const best_index = if (best_word_count >= 2) best_word_index else best_english_index;

    // Return the best match
    const result = try allocator.alloc(u8, all_shifts[best_index].len);
    @memcpy(result, all_shifts[best_index]);
    return result;
}

/// Dictionary attack - try to match against common passwords or custom wordlist
fn dictionaryAttack(allocator: std.mem.Allocator, hash_str: []const u8, hash_type: algo.AlgorithmType, config: BruteforceConfig) !?[]u8 {
    // Try common built-in words
    for (common_words) |word| {
        const computed_hash = switch (hash_type) {
            .MD5 => try algo.md5(allocator, word),
            .SHA1 => try algo.sha1(allocator, word),
            .SHA224 => try algo.sha224(allocator, word),
            .SHA256 => try algo.sha256(allocator, word),
            .SHA384 => try algo.sha384(allocator, word),
            .SHA512 => try algo.sha512(allocator, word),
            .NTLM => try algo.ntlm(allocator, word),
            .BCrypt => continue, // Not supported in this simple implementation
            else => unreachable,
        };
        defer allocator.free(computed_hash);

        if (std.mem.eql(u8, computed_hash, hash_str)) {
            const result = try allocator.alloc(u8, word.len);
            @memcpy(result, word);
            return result;
        }
    }

    // If a custom wordlist is provided, try words from that
    if (config.wordlist_path) |path| {
        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var in_stream = buf_reader.reader();

        var buf: [1024]u8 = undefined;
        while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
            // Trim whitespace
            const word = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (word.len == 0) continue;

            const computed_hash = switch (hash_type) {
                .MD5 => try algo.md5(allocator, word),
                .SHA1 => try algo.sha1(allocator, word),
                .SHA224 => try algo.sha224(allocator, word),
                .SHA256 => try algo.sha256(allocator, word),
                .SHA384 => try algo.sha384(allocator, word),
                .SHA512 => try algo.sha512(allocator, word),
                .NTLM => try algo.ntlm(allocator, word),
                .BCrypt => continue, // Not supported
                else => unreachable,
            };
            defer allocator.free(computed_hash);

            if (std.mem.eql(u8, computed_hash, hash_str)) {
                const result = try allocator.alloc(u8, word.len);
                @memcpy(result, word);
                return result;
            }
        }
    }

    return null;
}

/// Hybrid attack - combine dictionary words with common patterns
fn hybridAttack(
    allocator: std.mem.Allocator,
    hash_str: []const u8,
    hash_type: algo.AlgorithmType,
    _: BruteforceConfig, // Unused parameter renamed to _ to avoid compilation warning
) !?[]u8 {
    // Common suffixes to append to dictionary words
    const common_suffixes = [_][]const u8{ "123", "1234", "12345", "!", "1", "2", "01", "02", "99", "2023", "2024", "2025" };

    var buf: [1024]u8 = undefined;

    // Try each word with common suffixes
    for (common_words) |word| {
        for (common_suffixes) |suffix| {
            const hybrid = try std.fmt.bufPrint(&buf, "{s}{s}", .{ word, suffix });

            const computed_hash = switch (hash_type) {
                .MD5 => try algo.md5(allocator, hybrid),
                .SHA1 => try algo.sha1(allocator, hybrid),
                .SHA224 => try algo.sha224(allocator, hybrid),
                .SHA256 => try algo.sha256(allocator, hybrid),
                .SHA384 => try algo.sha384(allocator, hybrid),
                .SHA512 => try algo.sha512(allocator, hybrid),
                .NTLM => try algo.ntlm(allocator, hybrid),
                .BCrypt => continue, // Not supported
                else => unreachable,
            };
            defer allocator.free(computed_hash);

            if (std.mem.eql(u8, computed_hash, hash_str)) {
                const result = try allocator.alloc(u8, hybrid.len);
                @memcpy(result, hybrid);
                return result;
            }
        }

        // Try common capitalization patterns
        const capitalized = try std.fmt.bufPrint(&buf, "{c}{s}", .{ std.ascii.toUpper(word[0]), word[1..] });

        const computed_hash = switch (hash_type) {
            .MD5 => try algo.md5(allocator, capitalized),
            .SHA1 => try algo.sha1(allocator, capitalized),
            .SHA224 => try algo.sha224(allocator, capitalized),
            .SHA256 => try algo.sha256(allocator, capitalized),
            .SHA384 => try algo.sha384(allocator, capitalized),
            .SHA512 => try algo.sha512(allocator, capitalized),
            .NTLM => try algo.ntlm(allocator, capitalized),
            .BCrypt => continue, // Not supported
            else => unreachable,
        };
        defer allocator.free(computed_hash);

        if (std.mem.eql(u8, computed_hash, hash_str)) {
            const result = try allocator.alloc(u8, capitalized.len);
            @memcpy(result, capitalized);
            return result;
        }
    }

    // Try numeric sequences
    var i: usize = 0;
    while (i < 100000) : (i += 1) {
        const number_str = try std.fmt.bufPrint(&buf, "{d}", .{i});

        const computed_hash = switch (hash_type) {
            .MD5 => try algo.md5(allocator, number_str),
            .SHA1 => try algo.sha1(allocator, number_str),
            .SHA224 => try algo.sha224(allocator, number_str),
            .SHA256 => try algo.sha256(allocator, number_str),
            .SHA384 => try algo.sha384(allocator, number_str),
            .SHA512 => try algo.sha512(allocator, number_str),
            .NTLM => try algo.ntlm(allocator, number_str),
            .BCrypt => continue, // Not supported
            else => unreachable,
        };
        defer allocator.free(computed_hash);

        if (std.mem.eql(u8, computed_hash, hash_str)) {
            const result = try allocator.alloc(u8, number_str.len);
            @memcpy(result, number_str);
            return result;
        }
    }

    return null;
}

/// Pure brute force attack with parallel processing
fn bruteforceAttack(allocator: std.mem.Allocator, hash_str: []const u8, hash_type: algo.AlgorithmType, config: BruteforceConfig) !?[]u8 {
    // Define character set based on configuration
    const charset = getCharset(config.charset);

    // Create a shared context for parallel processing
    const context = try allocator.create(BruteforceContext);
    defer allocator.destroy(context);

    context.* = BruteforceContext{
        .allocator = allocator,
        .hash_str = hash_str,
        .hash_type = hash_type,
        .charset = charset,
        .max_length = config.max_length,
        .found = false,
        .result_password = null,
        .mutex = .{},
    };

    // Determine number of threads - use config or default to system CPU count
    const thread_count = @min(config.max_threads, try Thread.getCpuCount());
    const threads = try allocator.alloc(Thread, thread_count);
    defer allocator.free(threads);

    // Calculate work distribution
    const total_combinations = calculateTotalCombinations(charset.len, config.max_length);
    const chunk_size = total_combinations / thread_count;

    // Spawn worker threads
    for (threads, 0..) |*thread, i| {
        const worker_context = ThreadContext{
            .main_context = context,
            .thread_id = i,
            .thread_count = thread_count,
            .start_index = i * chunk_size,
            .end_index = if (i == thread_count - 1) total_combinations else (i + 1) * chunk_size,
        };

        thread.* = try Thread.spawn(.{}, bruteforceWorker, .{worker_context});
    }

    // Wait for all threads to complete
    for (threads) |thread| {
        thread.join();
    }

    // Check if a match was found
    if (context.found) {
        if (context.result_password) |password| {
            return password;
        }
    }

    return null;
}

/// Context shared among all worker threads
const BruteforceContext = struct {
    allocator: std.mem.Allocator,
    hash_str: []const u8,
    hash_type: algo.AlgorithmType,
    charset: []const u8,
    max_length: usize,
    found: bool,
    result_password: ?[]u8,
    mutex: Thread.Mutex,
};

/// Context for individual worker threads
const ThreadContext = struct {
    main_context: *BruteforceContext,
    thread_id: usize,
    thread_count: usize,
    start_index: usize,
    end_index: usize,
};

/// Worker function for parallel bruteforce
fn bruteforceWorker(context: ThreadContext) void {
    const main_ctx = context.main_context;
    var password_buf: [32]u8 = undefined;
    var current_index = context.start_index;

    // Iterate over assigned combinations
    while (current_index < context.end_index) {
        // Stop if another thread found the password
        if (main_ctx.found) break;

        // Generate password from index
        const password_len = indexToPassword(password_buf[0..], current_index, main_ctx.charset);
        const password = password_buf[0..password_len];

        // Compute hash and compare
        const computed_hash = switch (main_ctx.hash_type) {
            .MD5 => algo.md5(main_ctx.allocator, password) catch continue,
            .SHA1 => algo.sha1(main_ctx.allocator, password) catch continue,
            .SHA256 => algo.sha256(main_ctx.allocator, password) catch continue,
            .SHA512 => algo.sha512(main_ctx.allocator, password) catch continue,
            .NTLM => algo.ntlm(main_ctx.allocator, password) catch continue,
            else => continue,
        };
        defer main_ctx.allocator.free(computed_hash);

        if (std.mem.eql(u8, computed_hash, main_ctx.hash_str)) {
            // We found a match! Lock and update the shared context
            main_ctx.mutex.lock();
            defer main_ctx.mutex.unlock();

            if (!main_ctx.found) { // Double-check to avoid race conditions
                main_ctx.found = true;
                main_ctx.result_password = main_ctx.allocator.dupe(u8, password) catch null;
            }
            break;
        }

        current_index += 1;
    }
}

/// Calculate total number of possible combinations
fn calculateTotalCombinations(charset_len: usize, max_len: usize) usize {
    var total: usize = 0;
    var len: usize = 1;

    while (len <= max_len) : (len += 1) {
        var combinations: usize = 1;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            combinations *= charset_len;
        }
        total += combinations;
    }

    return total;
}

/// Convert a numeric index to a password string using the given charset
fn indexToPassword(buf: []u8, index: usize, charset: []const u8) usize {
    var remaining = index;
    var len: usize = 1;
    var base: usize = 1;

    // Determine password length
    while (remaining >= base * charset.len) {
        remaining -= base * charset.len;
        base *= charset.len;
        len += 1;
    }

    // Generate password characters
    var i: usize = 0;
    var div = remaining;
    while (i < len) : (i += 1) {
        const char_index = div % charset.len;
        buf[len - i - 1] = charset[char_index];
        div /= charset.len;
    }

    return len;
}

/// Get the appropriate character set based on configuration
fn getCharset(charset_type: CharSet) []const u8 {
    return switch (charset_type) {
        .Lowercase => "abcdefghijklmnopqrstuvwxyz",
        .Uppercase => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        .Digits => "0123456789",
        .Special => "!@#$%^&*()-_=+[]{}|;:,.<>?/",
        .All => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/",
        .Custom => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", // Default for custom
    };
}

/// Check if a string contains common English words
fn containsEnglishWords(text: []const u8) bool {
    return statistic.containsEnglishWords(text);
}
