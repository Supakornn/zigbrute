const std = @import("std");
const statistic = @import("utils/statistic.zig");

/// Detects the possible encryption/encoding types based on input pattern analysis
pub fn detectEncryptionType(allocator: std.mem.Allocator, input: []const u8) ![]const []const u8 {
    var possible_types = std.ArrayList([]const u8).init(allocator);

    // Hex string detection for hashes (higher priority for specific hash lengths)
    if (isHexString(input)) {
        // Check for specific hash types based on length
        switch (input.len) {
            32 => try possible_types.append("md5"),
            40 => try possible_types.append("sha1"),
            56 => try possible_types.append("sha224"),
            64 => try possible_types.append("sha256"),
            96 => try possible_types.append("sha384"),
            128 => try possible_types.append("sha512"),
            else => {
                if (input.len % 2 == 0) {
                    try possible_types.append("hex");
                }
            },
        }

        // Additional hash detection based on pattern analysis
        if (input.len == 32 and isLikelyNTLM(input)) {
            try possible_types.append("ntlm");
        }

        if (input.len == 40 and hasSaltPrefix(input)) {
            try possible_types.append("salted_hash");
        }

        // BCrypt detection
        if (input.len >= 59 and input.len <= 61 and std.mem.startsWith(u8, input, "$2")) {
            try possible_types.append("bcrypt");
        }
    }

    // Base64 detection (lower priority if we already identified a hash)
    if (isBase64(input) and possible_types.items.len == 0) {
        try possible_types.append("base64");
    }

    // Base32 detection
    if (isBase32(input) and possible_types.items.len == 0) {
        try possible_types.append("base32");
    }

    // URL encoding detection
    if (isURLEncoded(input)) {
        try possible_types.append("url");
    }

    // Binary data detection
    if (isBinary(input)) {
        try possible_types.append("binary");
    }

    // JWT token detection
    if (isJWT(input)) {
        try possible_types.append("jwt");
    }

    // Caesar cipher detection with frequency analysis
    if (possible_types.items.len == 0 and isASCIIPrintable(input)) {
        // Use character frequency analysis to detect Caesar cipher
        if (statistic.isLikelyCaesar(input)) {
            try possible_types.append("caesar");
        }
    }

    // ROT13 is a special case of Caesar with a shift of 13
    if (possible_types.items.len == 0 and isASCIIAlpha(input)) {
        try possible_types.append("rot13");
    }

    // Vigenère cipher detection
    if (possible_types.items.len == 0 and isASCIIAlpha(input)) {
        if (statistic.isLikelyVigenere(input)) {
            try possible_types.append("vigenere");
        }
    }

    // Add substitution cipher as fallback
    if (possible_types.items.len == 0 and isASCIIPrintable(input)) {
        try possible_types.append("substitution");
    }

    // Return the array of possible encryption types
    return possible_types.toOwnedSlice();
}

/// Check if the input string is likely Base64 encoded
fn isBase64(input: []const u8) bool {
    // Base64 uses characters A-Z, a-z, 0-9, +, /, and may end with = padding
    if (input.len % 4 != 0 and !(input.len % 4 == 2 or input.len % 4 == 3)) {
        return false;
    }

    var padding_count: usize = 0;
    for (input) |c| {
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '+', '/' => {},
            '=' => padding_count += 1,
            else => return false,
        }
    }

    // Ensure padding only appears at the end and there are at most 2 padding chars
    if (padding_count > 2) return false;
    if (padding_count > 0) {
        const non_padding_len = input.len - padding_count;
        for (input[0..non_padding_len]) |c| {
            if (c == '=') return false;
        }
        for (input[non_padding_len..]) |c| {
            if (c != '=') return false;
        }
    }

    return true;
}

/// Check if the input string is likely Base32 encoded
fn isBase32(input: []const u8) bool {
    // Base32 uses A-Z and 2-7, with padding
    if (input.len % 8 != 0) {
        return false;
    }

    var padding_count: usize = 0;
    for (input) |c| {
        switch (c) {
            'A'...'Z', '2'...'7' => {},
            '=' => padding_count += 1,
            else => return false,
        }
    }

    // Check if padding is correct
    if (padding_count > 6) return false;

    return true;
}

fn isURLEncoded(input: []const u8) bool {
    // URL encoded strings contain % followed by two hex digits
    var percent_count: usize = 0;

    var i: usize = 0;
    while (i < input.len) : (i += 1) {
        if (input[i] == '%') {
            if (i + 2 >= input.len) return false;

            // Check if next two chars are hex digits
            const is_high_hex = (input[i + 1] >= '0' and input[i + 1] <= '9') or
                (input[i + 1] >= 'A' and input[i + 1] <= 'F') or
                (input[i + 1] >= 'a' and input[i + 1] <= 'f');

            const is_low_hex = (input[i + 2] >= '0' and input[i + 2] <= '9') or
                (input[i + 2] >= 'A' and input[i + 2] <= 'F') or
                (input[i + 2] >= 'a' and input[i + 2] <= 'f');

            if (!is_high_hex or !is_low_hex) return false;

            percent_count += 1;
            i += 2; // Skip the hex digits
        } else if (!((input[i] >= 'A' and input[i] <= 'Z') or
            (input[i] >= 'a' and input[i] <= 'z') or
            (input[i] >= '0' and input[i] <= '9') or
            input[i] == '-' or input[i] == '_' or
            input[i] == '.' or input[i] == '~' or
            input[i] == '+'))
        {
            return false;
        }
    }

    // Must have at least one % to be considered URL encoded
    return percent_count > 0;
}

/// Check if the input string consists only of hexadecimal characters
fn isHexString(input: []const u8) bool {
    for (input) |c| {
        switch (c) {
            '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => return false,
        }
    }
    return true;
}

/// Check if the input might be binary data
fn isBinary(input: []const u8) bool {
    var non_printable_count: usize = 0;

    for (input) |c| {
        if (c < 32 or c > 126) {
            non_printable_count += 1;
        }
    }

    // If more than 20% are non-printable, likely binary
    return non_printable_count > input.len / 5;
}

/// Check if the string is a likely JWT token
fn isJWT(input: []const u8) bool {
    // JWT has structure: header.payload.signature
    var dot_count: usize = 0;
    for (input) |c| {
        if (c == '.') {
            dot_count += 1;
        } else if (!((c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '_' or c == '-'))
        {
            return false;
        }
    }

    return dot_count == 2;
}

/// Check if the hash is likely an NTLM hash based on pattern
fn isLikelyNTLM(input: []const u8) bool {
    // NTLM hashes often have certain patterns, like more uppercase
    // and specific character distributions
    var uppercase_count: usize = 0;
    var digit_count: usize = 0;

    for (input) |c| {
        if (c >= 'A' and c <= 'F') {
            uppercase_count += 1;
        } else if (c >= '0' and c <= '9') {
            digit_count += 1;
        }
    }

    // Heuristic: NTLM often has more uppercase hex and specific digit ratio
    return uppercase_count > input.len / 3 and digit_count > input.len / 4;
}

/// Check if hash might have a salt prefix
fn hasSaltPrefix(input: []const u8) bool {
    // Many salted hashes use format: salt:hash or $salt$hash
    return std.mem.indexOf(u8, input, ":") != null or std.mem.indexOf(u8, input, "$") != null;
}

/// Check if the input string consists only of printable ASCII characters
fn isASCIIPrintable(input: []const u8) bool {
    for (input) |c| {
        if (c < 32 or c > 126) {
            return false;
        }
    }
    return true;
}

/// Check if the input string consists only of alphabetic ASCII characters
fn isASCIIAlpha(input: []const u8) bool {
    for (input) |c| {
        if (!((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'))) {
            return false;
        }
    }
    return true;
}
