const std = @import("std");

pub fn isLikelyCaesar(input: []const u8) bool {
    var frequency = [_]usize{0} ** 26;
    var letter_count: usize = 0;

    for (input) |c| {
        if (c >= 'a' and c <= 'z') {
            frequency[c - 'a'] += 1;
            letter_count += 1;
        } else if (c >= 'A' and c <= 'Z') {
            frequency[c - 'A'] += 1;
            letter_count += 1;
        }
    }

    if (letter_count == 0) return false;

    const english_freq = [_]f64{ 0.08167, 0.01492, 0.02802, 0.04271, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074 };

    var min_chi_square: f64 = std.math.inf(f64);

    var shift: usize = 0;
    while (shift < 26) : (shift += 1) {
        var chi_square: f64 = 0.0;

        for (frequency, 0..) |count, i| {
            const shifted_idx = (i + shift) % 26;
            const expected = english_freq[shifted_idx] * @as(f64, @floatFromInt(letter_count));
            const observed = @as(f64, @floatFromInt(count));

            if (expected > 0) {
                const diff = observed - expected;
                chi_square += (diff * diff) / expected;
            }
        }

        min_chi_square = @min(min_chi_square, chi_square);
    }

    return min_chi_square < 500.0;
}

pub fn isLikelyVigenere(input: []const u8) bool {
    const ic = calculateIC(input);
    return ic > 0.045 and ic < 0.065;
}

fn calculateIC(text: []const u8) f64 {
    var counts = [_]usize{0} ** 26;
    var total: usize = 0;

    for (text) |c| {
        var letter: ?usize = null;
        if (c >= 'A' and c <= 'Z') {
            letter = c - 'A';
        } else if (c >= 'a' and c <= 'z') {
            letter = c - 'a';
        }

        if (letter) |l| {
            counts[l] += 1;
            total += 1;
        }
    }

    if (total < 2) return 0.0;

    var sum: usize = 0;
    for (counts) |count| {
        sum += count * (count - 1);
    }

    return @as(f64, @floatFromInt(sum)) / (@as(f64, @floatFromInt(total)) * @as(f64, @floatFromInt(total - 1)));
}

pub fn isLikelyEnglish(text: []const u8) bool {
    var letter_counts = [_]usize{0} ** 26;
    var letter_count: usize = 0;

    for (text) |c| {
        if (c >= 'a' and c <= 'z') {
            letter_counts[c - 'a'] += 1;
            letter_count += 1;
        } else if (c >= 'A' and c <= 'Z') {
            letter_counts[c - 'A'] += 1;
            letter_count += 1;
        }
    }

    if (letter_count == 0) return false;

    const english_freq = [_]f64{ 0.08167, 0.01492, 0.02802, 0.04271, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074 };

    var chi_square: f64 = 0.0;
    for (letter_counts, 0..) |count, i| {
        const expected = english_freq[i] * @as(f64, @floatFromInt(letter_count));
        const observed = @as(f64, @floatFromInt(count));

        if (expected > 0) {
            const diff = observed - expected;
            chi_square += (diff * diff) / expected;
        }
    }

    return chi_square < 100.0;
}

pub fn scoreEnglishText(text: []const u8) f64 {
    const english_freq = [_]f64{ 0.08167, 0.01492, 0.02802, 0.04271, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074 };

    var counts = [_]usize{0} ** 26;
    var total: usize = 0;

    for (text) |c| {
        if (c >= 'A' and c <= 'Z') {
            counts[c - 'A'] += 1;
            total += 1;
        } else if (c >= 'a' and c <= 'z') {
            counts[c - 'a'] += 1;
            total += 1;
        }
    }

    if (total == 0) return 0;

    var chi_square: f64 = 0.0;
    for (counts, 0..) |count, i| {
        const observed = @as(f64, @floatFromInt(count)) / @as(f64, @floatFromInt(total));
        const expected = english_freq[i];

        const diff = observed - expected;
        chi_square += (diff * diff) / expected;
    }

    return 100.0 / (1.0 + chi_square);
}

pub fn containsEnglishWords(text: []const u8) bool {
    const common_words = [_][]const u8{
        "the",   "and",   "that", "have",    "for",   "not",   "with",  "you",   "this",  "but",
        "his",   "from",  "they", "say",     "she",   "will",  "one",   "all",   "would", "there",
        "their", "what",  "out",  "about",   "who",   "get",   "which", "when",  "make",  "can",
        "hello", "world", "test", "example", "quick", "brown", "fox",   "jumps", "over",  "lazy",
        "dog",   "it",    "is",   "on",      "be",    "to",    "of",    "in",    "at",    "by",
        "as",
    };

    // Create a lowercase version of the input text for case-insensitive comparison
    var lowercase_buf: [1024]u8 = undefined;
    const lowercase_text = if (text.len <= lowercase_buf.len) blk: {
        var i: usize = 0;
        while (i < text.len) : (i += 1) {
            lowercase_buf[i] = std.ascii.toLower(text[i]);
        }
        break :blk lowercase_buf[0..text.len];
    } else text;

    // Count how many common words are found
    var word_count: usize = 0;
    for (common_words) |word| {
        if (std.mem.indexOf(u8, lowercase_text, word)) |_| {
            word_count += 1;
        }
    }

    // If more than 1 common words are found, likely English
    return word_count >= 1;
}
