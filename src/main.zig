const std = @import("std");
const detector = @import("detector.zig");
const bruteforce = @import("bruteforce.zig");
const algorithms = @import("algorithms.zig");
const user_prompt = @import("utils/user_prompt.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Parse command line options
    var bruteforce_config = bruteforce.BruteforceConfig{};
    var advanced_mode = false;
    var input: []const u8 = "";
    var save_results_path: ?[]const u8 = null;

    // Check for help flag first before any other processing
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printUsage();
            return;
        }
    }

    // Ensure we have at least one argument for the input
    if (args.len < 2) {
        try printUsage();
        return;
    }

    // The first argument is the input string
    input = args[1];

    // Parse the remaining arguments for options
    for (args[2..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--wordlist=")) {
            const wordlist_path = arg[11..];
            bruteforce_config.wordlist_path = wordlist_path;
            advanced_mode = true;
        } else if (std.mem.startsWith(u8, arg, "--max-length=")) {
            const max_len_str = arg[13..];
            bruteforce_config.max_length = std.fmt.parseInt(usize, max_len_str, 10) catch 8;
            advanced_mode = true;
        } else if (std.mem.startsWith(u8, arg, "--charset=")) {
            const charset_str = arg[10..];
            bruteforce_config.charset = parseCharset(charset_str);
            advanced_mode = true;
        } else if (std.mem.eql(u8, arg, "--threads")) {
            // Determine best thread count automatically
            bruteforce_config.max_threads = std.Thread.getCpuCount() catch 4;
            advanced_mode = true;
        } else if (std.mem.startsWith(u8, arg, "--threads=")) {
            const thread_str = arg[10..];
            bruteforce_config.max_threads = std.fmt.parseInt(usize, thread_str, 10) catch 4;
            advanced_mode = true;
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            bruteforce_config.verbose = true;
        } else if (std.mem.startsWith(u8, arg, "--save=")) {
            save_results_path = arg[7..];
        }
    }

    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();
    try stdout.print("\n== ZigBrute - Automatic Encryption Detector and Bruteforcer ==\n\n", .{});

    // Print configuration if in advanced mode
    if (advanced_mode) {
        try stdout.print("Running in advanced mode with configuration:\n", .{});
        if (bruteforce_config.wordlist_path) |path| {
            try stdout.print("  - Custom wordlist: {s}\n", .{path});
        }
        try stdout.print("  - Max password length: {d}\n", .{bruteforce_config.max_length});
        try stdout.print("  - Character set: {s}\n", .{charsetToString(bruteforce_config.charset)});
        try stdout.print("  - Thread count: {d}\n", .{bruteforce_config.max_threads});
        if (save_results_path) |path| {
            try stdout.print("  - Saving results to: {s}\n", .{path});
        }
        try stdout.print("\n", .{});
    }

    try stdout.print("Input: {s}\n", .{input});
    try stdout.print("Analyzing input...\n", .{});

    const detected_types = try detector.detectEncryptionType(allocator, input);
    defer allocator.free(detected_types);

    if (detected_types.len == 0) {
        try stdout.print("No encryption type detected. The input might be plaintext or an unsupported format.\n", .{});
        return;
    }

    try stdout.print("\nDetected possible encryption types:\n", .{});
    for (detected_types, 0..) |enc_type, i| {
        try stdout.print("  {d}. {s}\n", .{ i + 1, enc_type });
    }

    var tried_types = try allocator.alloc(bool, detected_types.len);
    defer allocator.free(tried_types);
    @memset(tried_types, false);

    var current_type_index: usize = 0;
    var all_types_tried = false;

    // Open results file if path was provided
    var results_file: ?std.fs.File = null;
    defer if (results_file) |*f| f.close();

    if (save_results_path) |path| {
        // Try to open the file for appending, but gracefully handle errors
        results_file = blk: {
            const file = std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch |err| {
                if (err == error.FileNotFound) {
                    // Create file if it doesn't exist
                    const new_file = std.fs.cwd().createFile(path, .{}) catch |create_err| {
                        try stdout.print("\nWarning: Could not create results file: {s}. Error: {s}\n", .{ path, @errorName(create_err) });
                        save_results_path = null;
                        break :blk null;
                    };
                    break :blk new_file;
                } else {
                    try stdout.print("\nWarning: Could not open results file: {s}. Error: {s}\n", .{ path, @errorName(err) });
                    save_results_path = null;
                    break :blk null;
                }
            };

            // Seek to end of file to append
            file.seekFromEnd(0) catch |seek_err| {
                try stdout.print("\nWarning: Could not seek to end of file: {s}. Error: {s}\n", .{ path, @errorName(seek_err) });
                file.close();
                save_results_path = null;
                break :blk null;
            };

            break :blk file;
        };
    }

    while (true) {
        all_types_tried = true;
        for (tried_types) |tried| {
            if (!tried) {
                all_types_tried = false;
                break;
            }
        }

        if (all_types_tried) {
            try stdout.print("\nAll detected encryption types have been tried.\n", .{});

            const retry = try user_prompt.promptContinue(stdin, stdout, "Would you like to try advanced options (different parameters, wordlists, etc.)?");

            if (!retry) {
                try stdout.print("\nExiting ZigBrute.\n", .{});
                break;
            }

            // Let user configure advanced options interactively
            @memset(tried_types, false);

            // Select encryption type
            try stdout.print("\nSelect an encryption type to try with advanced options:\n", .{});
            for (detected_types, 0..) |enc_type, i| {
                try stdout.print("  {d}. {s}\n", .{ i + 1, enc_type });
            }

            try stdout.print("Enter number (1-{d}): ", .{detected_types.len});
            var buf: [10]u8 = undefined;
            if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |user_input| {
                const trimmed = std.mem.trim(u8, user_input, &std.ascii.whitespace);
                const selected = std.fmt.parseInt(usize, trimmed, 10) catch 1;
                current_type_index = @min(selected - 1, detected_types.len - 1);
            } else {
                current_type_index = 0;
            }

            // Configure advanced options
            bruteforce_config = try configureAdvancedOptions(stdin, stdout, allocator);
            advanced_mode = true;
        }

        tried_types[current_type_index] = true;

        const selected_type = detected_types[current_type_index];
        try stdout.print("\nAttempting to bruteforce as {s} (type {d}/{d})...\n", .{ selected_type, current_type_index + 1, detected_types.len });

        // Display progress spinner for long operations
        var progress_thread: ?std.Thread = null;
        var stop_progress = false;

        if (bruteforce_config.verbose) {
            progress_thread = try std.Thread.spawn(.{}, progressSpinner, .{ &stop_progress, stdout });
        }

        // Use the enhanced bruteforce function with config
        const result = try bruteforce.bruteforceWithConfig(allocator, input, selected_type, bruteforce_config);

        // Stop the progress spinner if active
        if (progress_thread) |thread| {
            stop_progress = true;
            thread.join();
        }

        defer if (result) |r| allocator.free(r);

        if (result) |plaintext| {
            try stdout.print("\n✓ Successfully decrypted!\nPlaintext: {s}\n", .{plaintext});

            // Save result to file if requested
            if (results_file) |file| {
                // Get current timestamp
                const timestamp = std.time.timestamp();
                var buf: [64]u8 = undefined;

                // Use a simple date/time format
                const time_str = try std.fmt.bufPrint(&buf, "{d}", .{timestamp});

                try file.writer().print("[Timestamp: {s}] Input: {s}\nType: {s}\nDecrypted: {s}\n\n", .{ time_str, input, selected_type, plaintext });

                try stdout.print("Result saved to file.\n", .{});
            }

            const continue_options = try user_prompt.promptContinue(stdin, stdout, "Success found! Continue to try other encryption types?");

            if (!continue_options) {
                try stdout.print("\nExiting ZigBrute.\n", .{});
                break;
            }
        } else {
            try stdout.print("\n✗ Bruteforce unsuccessful with {s}.\n", .{selected_type});

            // Allow user to try again with different settings
            const try_again = try user_prompt.promptContinue(stdin, stdout, "Try again with different settings for this encryption type?");

            if (try_again) {
                // Keep the same encryption type but update configuration
                bruteforce_config = try configureAdvancedOptions(stdin, stdout, allocator);
                tried_types[current_type_index] = false; // Mark as not tried with new settings
                continue;
            }

            // Find next untried type
            var found_next = false;
            for (tried_types, 0..) |tried, i| {
                if (!tried) {
                    current_type_index = i;
                    found_next = true;
                    break;
                }
            }

            if (!found_next) {
                current_type_index = 0;
            }

            const continue_next = try user_prompt.promptContinue(stdin, stdout, "Continue to try next encryption type?");

            if (!continue_next) {
                try stdout.print("\nExiting ZigBrute.\n", .{});
                break;
            }
        }
    }
}

/// Interactive configuration of advanced bruteforce options
fn configureAdvancedOptions(stdin: std.fs.File.Reader, stdout: std.fs.File.Writer, allocator: std.mem.Allocator) !bruteforce.BruteforceConfig {
    var config = bruteforce.BruteforceConfig{};
    var buf: [1024]u8 = undefined;

    // Max password length
    try stdout.print("Enter maximum password length (1-16, default: 8): ", .{});
    if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |user_input| {
        const trimmed = std.mem.trim(u8, user_input, &std.ascii.whitespace);
        if (trimmed.len > 0) {
            config.max_length = std.fmt.parseInt(usize, trimmed, 10) catch 8;
            config.max_length = @min(config.max_length, 16); // Cap at 16 for reasonable performance
        }
    }

    // Character set
    try stdout.print("\nSelect character set:\n", .{});
    try stdout.print("  1. Lowercase letters [a-z]\n", .{});
    try stdout.print("  2. Uppercase letters [A-Z]\n", .{});
    try stdout.print("  3. Digits [0-9]\n", .{});
    try stdout.print("  4. Special characters [!@#$...]\n", .{});
    try stdout.print("  5. All characters\n", .{});
    try stdout.print("Enter selection (1-5, default: 5): ", .{});

    if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |user_input| {
        const trimmed = std.mem.trim(u8, user_input, &std.ascii.whitespace);
        if (trimmed.len > 0) {
            const charset_option = std.fmt.parseInt(usize, trimmed, 10) catch 5;
            config.charset = switch (charset_option) {
                1 => .Lowercase,
                2 => .Uppercase,
                3 => .Digits,
                4 => .Special,
                else => .All,
            };
        }
    }

    // Threads
    const available_threads = try std.Thread.getCpuCount();
    try stdout.print("\nAvailable CPU cores: {d}\n", .{available_threads});
    try stdout.print("Enter number of threads to use (1-{d}, default: {d}): ", .{ available_threads, @min(4, available_threads) });

    if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |user_input| {
        const trimmed = std.mem.trim(u8, user_input, &std.ascii.whitespace);
        if (trimmed.len > 0) {
            const thread_count = std.fmt.parseInt(usize, trimmed, 10) catch 4;
            config.max_threads = @min(thread_count, available_threads);
        } else {
            config.max_threads = @min(4, available_threads);
        }
    }

    // Custom wordlist
    try stdout.print("\nUse custom wordlist (y/n, default: n)? ", .{});
    if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |user_input| {
        const trimmed = std.mem.trim(u8, user_input, &std.ascii.whitespace);
        if (trimmed.len > 0 and (trimmed[0] == 'y' or trimmed[0] == 'Y')) {
            try stdout.print("Enter wordlist path: ", .{});
            if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |path_input| {
                const path_trimmed = std.mem.trim(u8, path_input, &std.ascii.whitespace);
                if (path_trimmed.len > 0) {
                    const path_copy = try allocator.dupe(u8, path_trimmed);
                    config.wordlist_path = path_copy;
                }
            }
        }
    }

    // Verbose mode
    try stdout.print("\nEnable verbose output (y/n, default: n)? ", .{});
    if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |user_input| {
        const trimmed = std.mem.trim(u8, user_input, &std.ascii.whitespace);
        if (trimmed.len > 0 and (trimmed[0] == 'y' or trimmed[0] == 'Y')) {
            config.verbose = true;
        }
    }

    return config;
}

/// Parse character set from command line argument
fn parseCharset(charset_str: []const u8) bruteforce.CharSet {
    if (std.mem.eql(u8, charset_str, "a-z") or std.mem.eql(u8, charset_str, "lowercase")) {
        return .Lowercase;
    } else if (std.mem.eql(u8, charset_str, "A-Z") or std.mem.eql(u8, charset_str, "uppercase")) {
        return .Uppercase;
    } else if (std.mem.eql(u8, charset_str, "0-9") or std.mem.eql(u8, charset_str, "digits")) {
        return .Digits;
    } else if (std.mem.eql(u8, charset_str, "special")) {
        return .Special;
    } else if (std.mem.eql(u8, charset_str, "all")) {
        return .All;
    } else {
        return .Custom;
    }
}

/// Convert CharSet enum to descriptive string
fn charsetToString(charset: bruteforce.CharSet) []const u8 {
    return switch (charset) {
        .Lowercase => "Lowercase letters [a-z]",
        .Uppercase => "Uppercase letters [A-Z]",
        .Digits => "Digits [0-9]",
        .Special => "Special characters",
        .All => "All characters",
        .Custom => "Custom character set",
    };
}

/// Animated progress spinner for long-running operations
fn progressSpinner(stop: *bool, stdout: std.fs.File.Writer) void {
    const spinner_chars = "⣾⣽⣻⢿⡿⣟⣯⣷";
    var i: usize = 0;

    while (!stop.*) {
        stdout.print("\r[{}] Working...", .{spinner_chars[i]}) catch {};
        i = (i + 1) % spinner_chars.len;
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    stdout.print("\r                  \r", .{}) catch {};
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        \\Usage: zigbrute [input] [options]
        \\
        \\Options:
        \\  --wordlist=PATH    Specify a custom wordlist file
        \\  --max-length=NUM   Maximum password length to try (default: 8)
        \\  --charset=SET      Character set to use: a-z, A-Z, 0-9, special, all
        \\  --threads=NUM      Number of threads to use for parallel bruteforcing
        \\  --verbose          Show detailed progress information
        \\  --save=PATH        Save cracked passwords to a file
        \\  --help             Display this help message
        \\
        \\Examples:
        \\  zigbrute "aGVsbG8gd29ybGQ="                    # Auto-detect and decrypt
        \\  zigbrute "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist=/path/to/wordlist.txt
        \\  zigbrute "5f4dcc3b5aa765d61d8327deb882cf99" --max-length=6 --charset=a-z --threads=8 --save=results.txt
        \\
        \\Supported Encryption/Encoding Types:
        \\  - Base64, Base32
        \\  - URL Encoding
        \\  - Common hashes (MD5, SHA1, SHA256, SHA512, NTLM)
        \\  - JWT tokens
        \\  - Caesar cipher, ROT13
        \\  - Vigenère cipher
        \\  - Substitution ciphers
        \\  - Hex encoding
        \\
    , .{});
}
