const std = @import("std");

pub fn promptContinue(reader: anytype, writer: anytype, message: []const u8) !bool {
    var buf: [10]u8 = undefined;

    try writer.print("{s} [y/n]: ", .{message});

    if (try reader.readUntilDelimiterOrEof(buf[0..], '\n')) |user_input| {
        const trimmed = std.mem.trim(u8, user_input, &std.ascii.whitespace);

        if (std.mem.eql(u8, trimmed, "y") or
            std.mem.eql(u8, trimmed, "Y") or
            std.mem.eql(u8, trimmed, "yes") or
            std.mem.eql(u8, trimmed, "Yes") or
            std.mem.eql(u8, trimmed, "YES"))
        {
            return true;
        } else if (std.mem.eql(u8, trimmed, "n") or
            std.mem.eql(u8, trimmed, "N") or
            std.mem.eql(u8, trimmed, "no") or
            std.mem.eql(u8, trimmed, "No") or
            std.mem.eql(u8, trimmed, "NO"))
        {
            return false;
        } else {
            try writer.print("Please enter 'y' or 'n'\n", .{});
            return try promptContinue(reader, writer, message);
        }
    } else {
        return false;
    }
}
