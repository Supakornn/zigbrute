const std = @import("std");
const testing = std.testing;

pub const algorithms = @import("algorithms.zig");
pub const detector = @import("detector.zig");
pub const bruteforce = @import("bruteforce.zig");

pub export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}

test "base64 encode/decode" {
    const allocator = testing.allocator;
    const test_string = "Hello, World!";

    const encoded = try algorithms.encodeBase64(allocator, test_string);
    defer allocator.free(encoded);

    const decoded = try algorithms.decodeBase64(allocator, encoded) orelse return error.DecodingFailed;
    defer allocator.free(decoded);

    try testing.expectEqualStrings(test_string, decoded);
}

test "md5 hash" {
    const allocator = testing.allocator;
    const input = "test";
    const expected = "098f6bcd4621d373cade4e832627b4f6";

    const hash = try algorithms.md5(allocator, input);
    defer allocator.free(hash);

    try testing.expectEqualStrings(expected, hash);
}
