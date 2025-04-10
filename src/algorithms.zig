const std = @import("std");

pub const AlgorithmType = enum {
    Base64,
    Base32,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    NTLM,
    BCrypt,
    Caesar,
    ROT13,
    Vigenere,
    Substitution,
    Hex,
    URL,
    JWT,
    Binary,
    SaltedHash,

    pub fn fromString(algo_str: []const u8) ?AlgorithmType {
        if (std.mem.eql(u8, algo_str, "base64")) return .Base64;
        if (std.mem.eql(u8, algo_str, "base32")) return .Base32;
        if (std.mem.eql(u8, algo_str, "md5")) return .MD5;
        if (std.mem.eql(u8, algo_str, "sha1")) return .SHA1;
        if (std.mem.eql(u8, algo_str, "sha224")) return .SHA224;
        if (std.mem.eql(u8, algo_str, "sha256")) return .SHA256;
        if (std.mem.eql(u8, algo_str, "sha384")) return .SHA384;
        if (std.mem.eql(u8, algo_str, "sha512")) return .SHA512;
        if (std.mem.eql(u8, algo_str, "ntlm")) return .NTLM;
        if (std.mem.eql(u8, algo_str, "bcrypt")) return .BCrypt;
        if (std.mem.eql(u8, algo_str, "caesar")) return .Caesar;
        if (std.mem.eql(u8, algo_str, "rot13")) return .ROT13;
        if (std.mem.eql(u8, algo_str, "vigenere")) return .Vigenere;
        if (std.mem.eql(u8, algo_str, "substitution")) return .Substitution;
        if (std.mem.eql(u8, algo_str, "hex")) return .Hex;
        if (std.mem.eql(u8, algo_str, "url")) return .URL;
        if (std.mem.eql(u8, algo_str, "jwt")) return .JWT;
        if (std.mem.eql(u8, algo_str, "binary")) return .Binary;
        if (std.mem.eql(u8, algo_str, "salted_hash")) return .SaltedHash;
        return null;
    }
};

pub fn decodeBase64(allocator: std.mem.Allocator, encoded: []const u8) !?[]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(encoded) catch return null;
    const decoded = try allocator.alloc(u8, decoded_len);

    decoder.decode(decoded, encoded) catch {
        allocator.free(decoded);
        return null;
    };

    return decoded;
}

pub fn encodeBase64(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(input.len);
    const encoded = try allocator.alloc(u8, encoded_len);

    _ = encoder.encode(encoded, input);

    return encoded;
}

pub fn decodeBase32(allocator: std.mem.Allocator, encoded: []const u8) !?[]u8 {
    const decoder = std.base64.standard.Decoder;

    var base32_data = try allocator.alloc(u8, encoded.len);
    defer allocator.free(base32_data);

    for (encoded, 0..) |c, i| {
        base32_data[i] = switch (c) {
            'A'...'Z' => c,
            '2'...'7' => '2' + (c - '2') + 26,
            '=' => '=',
            else => return null,
        };
    }

    const decoded_len = try decoder.calcSizeForSlice(base32_data);
    const decoded = try allocator.alloc(u8, decoded_len);

    decoder.decode(decoded, base32_data) catch {
        allocator.free(decoded);
        return null;
    };

    return decoded;
}

pub fn tryDecryptCaesar(allocator: std.mem.Allocator, input: []const u8) ![][]u8 {
    var results = std.ArrayList([]u8).init(allocator);

    // Try all possible shifts (0-25)
    for (0..26) |shift_int| {
        const shift: u8 = @intCast(shift_int);
        const result = try allocator.alloc(u8, input.len);

        for (input, 0..) |c, i| {
            if (c >= 'A' and c <= 'Z') {
                // Properly decrypt by shifting backward (adding 26 to avoid negative numbers)
                result[i] = 'A' + ((c - 'A' + 26 - shift) % 26);
            } else if (c >= 'a' and c <= 'z') {
                result[i] = 'a' + ((c - 'a' + 26 - shift) % 26);
            } else {
                result[i] = c;
            }
        }

        try results.append(result);
    }

    return results.toOwnedSlice();
}

pub fn rot13(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, input.len);

    for (input, 0..) |c, i| {
        if (c >= 'A' and c <= 'Z') {
            result[i] = 'A' + ((c - 'A' + 13) % 26);
        } else if (c >= 'a' and c <= 'z') {
            result[i] = 'a' + ((c - 'a' + 13) % 26);
        } else {
            result[i] = c;
        }
    }

    return result;
}

pub fn md5(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var hash: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    std.crypto.hash.Md5.hash(input, &hash, .{});

    const hex_output = try allocator.alloc(u8, hash.len * 2);
    _ = std.fmt.bufPrint(hex_output, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

    return hex_output;
}

pub fn sha1(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(input, &hash, .{});

    const hex_output = try allocator.alloc(u8, hash.len * 2);
    _ = std.fmt.bufPrint(hex_output, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

    return hex_output;
}

pub fn sha224(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var hash: [std.crypto.hash.sha2.Sha224.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha224.hash(input, &hash, .{});

    const hex_output = try allocator.alloc(u8, hash.len * 2);
    _ = std.fmt.bufPrint(hex_output, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

    return hex_output;
}

pub fn sha256(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &hash, .{});

    const hex_output = try allocator.alloc(u8, hash.len * 2);
    _ = std.fmt.bufPrint(hex_output, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

    return hex_output;
}

pub fn sha384(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var hash: [std.crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash(input, &hash, .{});

    const hex_output = try allocator.alloc(u8, hash.len * 2);
    _ = std.fmt.bufPrint(hex_output, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

    return hex_output;
}

pub fn sha512(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var hash: [std.crypto.hash.sha2.Sha512.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(input, &hash, .{});

    const hex_output = try allocator.alloc(u8, hash.len * 2);
    _ = std.fmt.bufPrint(hex_output, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

    return hex_output;
}

pub fn decodeHex(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    if (hex_str.len % 2 != 0) return error.InvalidHexString;

    const bytes = try allocator.alloc(u8, hex_str.len / 2);

    var i: usize = 0;
    while (i < hex_str.len) : (i += 2) {
        const high = std.fmt.charToDigit(hex_str[i], 16) catch return error.InvalidHexChar;
        const low = std.fmt.charToDigit(hex_str[i + 1], 16) catch return error.InvalidHexChar;
        bytes[i / 2] = @as(u8, @intCast(high * 16 + low));
    }

    return bytes;
}

pub fn decryptVigenere(allocator: std.mem.Allocator, input: []const u8) !?[]u8 {
    var best_score: f64 = 0;
    var best_result: ?[]u8 = null;

    for (1..11) |key_len| {
        const result = try attemptVigenereDecryptWithKeyLen(allocator, input, key_len);
        defer if (result) |r| allocator.free(r);

        if (result) |decrypted| {
            const score = scoreEnglishText(decrypted);
            if (score > best_score) {
                best_score = score;
                if (best_result) |old| allocator.free(old);
                best_result = try allocator.dupe(u8, decrypted);
            }
        }
    }

    return best_result;
}

fn attemptVigenereDecryptWithKeyLen(allocator: std.mem.Allocator, input: []const u8, key_len: usize) !?[]u8 {
    if (input.len < key_len) return null;

    var columns = try allocator.alloc(std.ArrayList(u8), key_len);
    defer allocator.free(columns);

    for (0..key_len) |i| {
        columns[i] = std.ArrayList(u8).init(allocator);
    }
    defer for (columns) |col| col.deinit();

    for (input, 0..) |c, i| {
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z')) {
            try columns[i % key_len].append(c);
        }
    }

    var shifts = try allocator.alloc(u8, key_len);
    defer allocator.free(shifts);

    for (columns, 0..) |col, i| {
        shifts[i] = try findBestShift(col.items);
    }

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    for (input, 0..) |c, i| {
        if (c >= 'A' and c <= 'Z') {
            const shift = shifts[i % key_len];
            const decrypted = (c - 'A' + 26 - shift) % 26 + 'A';
            try result.append(decrypted);
        } else if (c >= 'a' and c <= 'z') {
            const shift = shifts[i % key_len];
            const decrypted = (c - 'a' + 26 - shift) % 26 + 'a';
            try result.append(decrypted);
        } else {
            try result.append(c);
        }
    }

    // Create a properly typed optional result
    if (result.items.len > 0) {
        const output = try allocator.dupe(u8, result.items);
        return output;
    } else {
        return null;
    }
}

fn findBestShift(text: []const u8) !u8 {
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

    var best_shift: u8 = 0;
    var best_chi_square: f64 = std.math.inf(f64);

    for (0..26) |shift| {
        var chi_square: f64 = 0.0;

        for (0..26) |i| {
            const shifted_idx = (i + shift) % 26;
            const observed = @as(f64, @floatFromInt(counts[i])) / @as(f64, @floatFromInt(total));
            const expected = english_freq[shifted_idx];

            const diff = observed - expected;
            chi_square += (diff * diff) / expected;
        }

        if (chi_square < best_chi_square) {
            best_chi_square = chi_square;
            best_shift = @intCast(shift);
        }
    }

    return best_shift;
}

fn scoreEnglishText(text: []const u8) f64 {
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

pub fn decodeURL(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const high = try std.fmt.charToDigit(input[i + 1], 16);
            const low = try std.fmt.charToDigit(input[i + 2], 16);
            const byte = @as(u8, @intCast(high * 16 + low));
            try result.append(byte);
            i += 3;
        } else if (input[i] == '+') {
            try result.append(' ');
            i += 1;
        } else {
            try result.append(input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

/// Decode JWT token
pub fn decodeJWT(allocator: std.mem.Allocator, input: []const u8) !?[]u8 {
    // Split the JWT into parts using the '.' character
    var iter = std.mem.splitScalar(u8, input, '.');

    // Skip the header (we only care about the payload)
    _ = iter.next() orelse return null;
    const payload_b64 = iter.next() orelse return null;

    // Decode the payload part
    if (try decodeBase64URLSafe(allocator, payload_b64)) |payload| {
        return payload;
    }

    return null;
}

fn decodeBase64URLSafe(allocator: std.mem.Allocator, encoded: []const u8) !?[]u8 {
    var modified = try allocator.alloc(u8, encoded.len);
    defer allocator.free(modified);

    for (encoded, 0..) |c, i| {
        modified[i] = switch (c) {
            '-' => '+',
            '_' => '/',
            else => c,
        };
    }

    var padded: []u8 = undefined;
    const mod = encoded.len % 4;

    if (mod == 0) {
        padded = modified;
    } else {
        const padding_needed = 4 - mod;
        padded = try allocator.alloc(u8, encoded.len + padding_needed);
        defer allocator.free(padded);

        @memcpy(padded[0..encoded.len], modified);
        @memset(padded[encoded.len..], '=');
    }

    return try decodeBase64(allocator, padded);
}

pub fn ntlm(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const utf16_len = input.len * 2;
    const utf16 = try allocator.alloc(u8, utf16_len);
    defer allocator.free(utf16);

    for (input, 0..) |c, i| {
        utf16[i * 2] = c;
        utf16[i * 2 + 1] = 0;
    }

    var hash: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    std.crypto.hash.Md5.hash(utf16, &hash, .{});

    const hex_output = try allocator.alloc(u8, hash.len * 2);
    _ = std.fmt.bufPrint(hex_output, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

    return hex_output;
}
