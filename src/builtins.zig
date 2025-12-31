// builtins.zig - all shell builtin commands
const std = @import("std");
const Shell = @import("Shell.zig");
const ast = @import("ast.zig");
const parser = @import("parser.zig");

// directory stack for pushd/popd
var dir_stack: std.ArrayList([]const u8) = undefined;
var dir_stack_initialized: bool = false;

fn ensureDirStack(allocator: std.mem.Allocator) void {
    if (!dir_stack_initialized) {
        dir_stack = std.ArrayList([]const u8){};
        dir_stack.ensureTotalCapacity(allocator, 8) catch {};
        dir_stack_initialized = true;
    }
}

pub fn isBuiltin(name: []const u8) bool {
    const builtins = [_][]const u8{
        "echo",    "cd",       "pwd",      "exit",     "export",   "unset",
        "alias",   "unalias",  "source",   ".",        "history",  "type",
        "which",   "set",      "true",     "false",    ":",        "test",
        "[",       "read",     "printf",   "break",    "continue", "return",
        "shift",   "local",    "declare",  "readonly", "jobs",     "fg",
        "bg",      "kill",     "wait",     "trap",     "eval",     "exec",
        "builtin", "command",  "hash",     "help",     "pushd",    "popd",
        "dirs",    "getopts",  "..",       "...",      "-",        "chpw",
    };
    for (builtins) |b| {
        if (std.mem.eql(u8, name, b)) return true;
    }
    return false;
}

// main dispatch function - called from eval.zig
pub fn dispatch(shell: *Shell, cmd_name: []const u8, args: []const []const u8) !?u8 {
    // simple no-arg builtins
    if (std.mem.eql(u8, cmd_name, "true") or std.mem.eql(u8, cmd_name, ":")) return 0;
    if (std.mem.eql(u8, cmd_name, "false")) return 1;
    if (std.mem.eql(u8, cmd_name, "continue")) return 253;
    if (std.mem.eql(u8, cmd_name, "break")) return 254;

    // directory builtins
    if (std.mem.eql(u8, cmd_name, "cd")) return try cd(shell, args);
    if (std.mem.eql(u8, cmd_name, "pwd")) return try pwd(shell, args);
    if (std.mem.eql(u8, cmd_name, "pushd")) return try pushd(shell, args);
    if (std.mem.eql(u8, cmd_name, "popd")) return try popd(shell, args);
    if (std.mem.eql(u8, cmd_name, "dirs")) return try dirs(shell, args);
    if (std.mem.eql(u8, cmd_name, "..")) return try dotdot(shell);
    if (std.mem.eql(u8, cmd_name, "...")) return try dotdotdot(shell);
    if (std.mem.eql(u8, cmd_name, "-")) return try dash(shell);

    // io builtins
    if (std.mem.eql(u8, cmd_name, "echo")) return try echo(shell, args);
    if (std.mem.eql(u8, cmd_name, "printf")) return try printf(shell, args);
    if (std.mem.eql(u8, cmd_name, "read")) return try read(shell, args);

    // test builtin
    if (std.mem.eql(u8, cmd_name, "test") or std.mem.eql(u8, cmd_name, "[")) return try testCmd(shell, args);

    // variable builtins
    if (std.mem.eql(u8, cmd_name, "export")) return try exportVar(shell, args);
    if (std.mem.eql(u8, cmd_name, "unset")) return try unset(shell, args);
    if (std.mem.eql(u8, cmd_name, "local") or std.mem.eql(u8, cmd_name, "declare")) return try local(shell, args);
    if (std.mem.eql(u8, cmd_name, "readonly")) return try readonly(shell, args);
    if (std.mem.eql(u8, cmd_name, "set")) return try set(shell, args);
    if (std.mem.eql(u8, cmd_name, "shift")) return try shift(shell, args);
    if (std.mem.eql(u8, cmd_name, "getopts")) return try getopts(shell, args);

    // alias builtins
    if (std.mem.eql(u8, cmd_name, "alias")) return try alias(shell, args);
    if (std.mem.eql(u8, cmd_name, "unalias")) return try unalias(shell, args);

    // source/eval/exec
    if (std.mem.eql(u8, cmd_name, "source") or std.mem.eql(u8, cmd_name, ".")) return try source(shell, args);
    if (std.mem.eql(u8, cmd_name, "eval")) return try eval(shell, args);
    if (std.mem.eql(u8, cmd_name, "exec")) return try exec(shell, args);

    // info builtins
    if (std.mem.eql(u8, cmd_name, "type") or std.mem.eql(u8, cmd_name, "which")) return try typeCmd(shell, args);
    if (std.mem.eql(u8, cmd_name, "hash")) return try hash(shell, args);
    if (std.mem.eql(u8, cmd_name, "history")) return try history(shell, args);
    if (std.mem.eql(u8, cmd_name, "help")) return try help(shell, args);

    // job control
    if (std.mem.eql(u8, cmd_name, "jobs")) return try jobs(shell, args);
    if (std.mem.eql(u8, cmd_name, "fg")) return try fg(shell, args);
    if (std.mem.eql(u8, cmd_name, "bg")) return try bg(shell, args);
    if (std.mem.eql(u8, cmd_name, "wait")) return try wait(shell, args);
    if (std.mem.eql(u8, cmd_name, "kill")) return try kill(shell, args);
    if (std.mem.eql(u8, cmd_name, "trap")) return try trap(shell, args);

    // shell control
    if (std.mem.eql(u8, cmd_name, "exit")) return try exit(shell, args);
    if (std.mem.eql(u8, cmd_name, "return")) return try returnCmd(shell, args);
    if (std.mem.eql(u8, cmd_name, "builtin")) return try builtinCmd(shell, args);
    if (std.mem.eql(u8, cmd_name, "command")) return try commandCmd(shell, args);

    // zish specific
    if (std.mem.eql(u8, cmd_name, "chpw")) return null; // handled in eval.zig for now (complex)

    return null; // not a builtin
}

// ============ directory builtins ============

fn cd(shell: *Shell, args: []const []const u8) !u8 {
    // save current directory to OLDPWD
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.posix.getcwd(&cwd_buf) catch "";

    const path = if (args.len > 1) blk: {
        const arg = args[1];
        // handle cd -
        if (std.mem.eql(u8, arg, "-")) {
            const oldpwd = shell.variables.get("OLDPWD") orelse
                std.posix.getenv("OLDPWD") orelse {
                try shell.stdout().writeAll("cd: OLDPWD not set\n");
                return 1;
            };
            try shell.stdout().print("{s}\n", .{oldpwd});
            break :blk oldpwd;
        }
        break :blk arg;
    } else blk: {
        break :blk std.posix.getenv("HOME") orelse {
            try shell.stdout().writeAll("cd: HOME not set\n");
            return 1;
        };
    };

    std.posix.chdir(path) catch {
        try shell.stdout().print("cd: {s}: no such file or directory\n", .{path});
        return 1;
    };

    // set OLDPWD after successful cd
    if (cwd.len > 0) {
        try setVar(shell, "OLDPWD", cwd);
    }
    return 0;
}

fn pwd(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.posix.getcwd(&cwd_buf) catch {
        try shell.stdout().writeAll("pwd: cannot get current directory\n");
        return 1;
    };
    try shell.stdout().print("{s}\n", .{cwd});
    return 0;
}

fn dotdot(shell: *Shell) !u8 {
    std.posix.chdir("..") catch {
        try shell.stdout().writeAll("..: cannot go up\n");
        return 1;
    };
    return 0;
}

fn dotdotdot(shell: *Shell) !u8 {
    std.posix.chdir("../..") catch {
        try shell.stdout().writeAll("...: cannot go up\n");
        return 1;
    };
    return 0;
}

fn dash(shell: *Shell) !u8 {
    const oldpwd = shell.variables.get("OLDPWD") orelse
        std.posix.getenv("OLDPWD") orelse {
        try shell.stdout().writeAll("-: OLDPWD not set\n");
        return 1;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.posix.getcwd(&cwd_buf) catch "";

    std.posix.chdir(oldpwd) catch {
        try shell.stdout().print("-: {s}: no such directory\n", .{oldpwd});
        return 1;
    };

    try setVar(shell, "OLDPWD", cwd);
    try shell.stdout().print("{s}\n", .{oldpwd});
    return 0;
}

pub fn pushd(shell: *Shell, args: []const []const u8) !u8 {
    ensureDirStack(shell.allocator);

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.posix.getcwd(&cwd_buf) catch {
        try shell.stdout().writeAll("pushd: cannot get current directory\n");
        return 1;
    };

    if (args.len < 2) {
        if (dir_stack.items.len == 0) {
            try shell.stdout().writeAll("pushd: no other directory\n");
            return 1;
        }
        const top = dir_stack.pop() orelse {
            try shell.stdout().writeAll("pushd: no other directory\n");
            return 1;
        };
        std.posix.chdir(top) catch {
            try shell.stdout().print("pushd: {s}: no such directory\n", .{top});
            dir_stack.append(shell.allocator, top) catch {};
            return 1;
        };
        try dir_stack.append(shell.allocator, try shell.allocator.dupe(u8, cwd));
        try printDirStack(shell);
        return 0;
    }

    const path = args[1];
    std.posix.chdir(path) catch {
        try shell.stdout().print("pushd: {s}: no such directory\n", .{path});
        return 1;
    };

    try dir_stack.append(shell.allocator, try shell.allocator.dupe(u8, cwd));
    try printDirStack(shell);
    return 0;
}

pub fn popd(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    ensureDirStack(shell.allocator);

    if (dir_stack.items.len == 0) {
        try shell.stdout().writeAll("popd: directory stack empty\n");
        return 1;
    }

    const path = dir_stack.pop() orelse {
        try shell.stdout().writeAll("popd: directory stack empty\n");
        return 1;
    };
    defer shell.allocator.free(path);

    std.posix.chdir(path) catch {
        try shell.stdout().print("popd: {s}: no such directory\n", .{path});
        return 1;
    };

    try printDirStack(shell);
    return 0;
}

pub fn dirs(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    ensureDirStack(shell.allocator);
    try printDirStack(shell);
    return 0;
}

fn printDirStack(shell: *Shell) !void {
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.posix.getcwd(&cwd_buf) catch "";
    try shell.stdout().print("{s}", .{cwd});
    var i: usize = dir_stack.items.len;
    while (i > 0) {
        i -= 1;
        try shell.stdout().print(" {s}", .{dir_stack.items[i]});
    }
    try shell.stdout().writeAll("\n");
}

// ============ io builtins ============

fn echo(shell: *Shell, args: []const []const u8) !u8 {
    var interpret_escapes = false;
    var print_newline = true;
    var start: usize = 1;

    // parse flags
    while (start < args.len) {
        const arg = args[start];
        if (arg.len >= 2 and arg[0] == '-') {
            var valid = true;
            for (arg[1..]) |c| {
                switch (c) {
                    'e' => interpret_escapes = true,
                    'n' => print_newline = false,
                    'E' => interpret_escapes = false,
                    else => {
                        valid = false;
                        break;
                    },
                }
            }
            if (valid) {
                start += 1;
                continue;
            }
        }
        break;
    }

    // output args
    for (args[start..], 0..) |arg, i| {
        if (i > 0) try shell.stdout().writeAll(" ");
        if (interpret_escapes) {
            try writeEscaped(shell, arg);
        } else {
            try shell.stdout().writeAll(arg);
        }
    }
    if (print_newline) try shell.stdout().writeAll("\n");
    return 0;
}

fn writeEscaped(shell: *Shell, s: []const u8) !void {
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '\\' and i + 1 < s.len) {
            switch (s[i + 1]) {
                'n' => try shell.stdout().writeByte('\n'),
                't' => try shell.stdout().writeByte('\t'),
                'r' => try shell.stdout().writeByte('\r'),
                '\\' => try shell.stdout().writeByte('\\'),
                '0' => try shell.stdout().writeByte(0),
                else => {
                    try shell.stdout().writeByte(s[i]);
                    try shell.stdout().writeByte(s[i + 1]);
                },
            }
            i += 2;
        } else {
            try shell.stdout().writeByte(s[i]);
            i += 1;
        }
    }
}

fn printf(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) {
        try shell.stdout().writeAll("printf: usage: printf format [arguments]\n");
        return 1;
    }

    const format = args[1];
    var arg_idx: usize = 2;

    var i: usize = 0;
    while (i < format.len) {
        if (format[i] == '\\' and i + 1 < format.len) {
            switch (format[i + 1]) {
                'n' => try shell.stdout().writeByte('\n'),
                't' => try shell.stdout().writeByte('\t'),
                'r' => try shell.stdout().writeByte('\r'),
                '\\' => try shell.stdout().writeByte('\\'),
                else => try shell.stdout().writeByte(format[i + 1]),
            }
            i += 2;
        } else if (format[i] == '%' and i + 1 < format.len) {
            switch (format[i + 1]) {
                's' => {
                    if (arg_idx < args.len) {
                        try shell.stdout().writeAll(args[arg_idx]);
                        arg_idx += 1;
                    }
                    i += 2;
                },
                'd' => {
                    if (arg_idx < args.len) {
                        try shell.stdout().writeAll(args[arg_idx]);
                        arg_idx += 1;
                    }
                    i += 2;
                },
                '%' => {
                    try shell.stdout().writeByte('%');
                    i += 2;
                },
                else => {
                    try shell.stdout().writeByte(format[i]);
                    i += 1;
                },
            }
        } else {
            try shell.stdout().writeByte(format[i]);
            i += 1;
        }
    }
    return 0;
}

fn read(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) {
        try shell.stdout().writeAll("read: usage: read varname\n");
        return 1;
    }

    const varname = args[1];
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    // read char by char until newline
    while (pos < buf.len - 1) {
        var c: [1]u8 = undefined;
        const n = std.posix.read(std.posix.STDIN_FILENO, &c) catch return 1;
        if (n == 0) return 1; // EOF
        if (c[0] == '\n') break;
        buf[pos] = c[0];
        pos += 1;
    }

    try setVar(shell, varname, buf[0..pos]);
    return 0;
}

// ============ test builtin ============

fn testCmd(shell: *Shell, args: []const []const u8) !u8 {
    _ = shell;
    if (args.len < 2) return 1;

    var test_args = args[1..];

    // handle [ ... ] syntax - remove trailing ]
    if (args[0].len == 1 and args[0][0] == '[') {
        if (test_args.len > 0 and std.mem.eql(u8, test_args[test_args.len - 1], "]")) {
            test_args = test_args[0 .. test_args.len - 1];
        }
    }

    if (test_args.len == 0) return 1;

    // unary operators
    if (test_args.len == 2) {
        const op = test_args[0];
        const arg = test_args[1];

        if (std.mem.eql(u8, op, "-n")) return if (arg.len > 0) 0 else 1;
        if (std.mem.eql(u8, op, "-z")) return if (arg.len == 0) 0 else 1;
        if (std.mem.eql(u8, op, "-d")) {
            var dir = std.fs.cwd().openDir(arg, .{}) catch return 1;
            dir.close();
            return 0;
        }
        if (std.mem.eql(u8, op, "-f")) {
            const stat = std.fs.cwd().statFile(arg) catch return 1;
            return if (stat.kind == .file) 0 else 1;
        }
        if (std.mem.eql(u8, op, "-e")) {
            std.fs.cwd().access(arg, .{}) catch return 1;
            return 0;
        }
        if (std.mem.eql(u8, op, "-r") or std.mem.eql(u8, op, "-w") or std.mem.eql(u8, op, "-x")) {
            std.fs.cwd().access(arg, .{}) catch return 1;
            return 0;
        }
        if (std.mem.eql(u8, op, "-s")) {
            const stat = std.fs.cwd().statFile(arg) catch return 1;
            return if (stat.size > 0) 0 else 1;
        }
        if (std.mem.eql(u8, op, "-L") or std.mem.eql(u8, op, "-h")) {
            const stat = std.fs.cwd().statFile(arg) catch return 1;
            return if (stat.kind == .sym_link) 0 else 1;
        }
    }

    // single arg: true if non-empty
    if (test_args.len == 1) {
        return if (test_args[0].len > 0) 0 else 1;
    }

    // binary operators
    if (test_args.len >= 3) {
        const left = test_args[0];
        const op = test_args[1];
        const right = test_args[2];

        // string comparison
        if (std.mem.eql(u8, op, "=") or std.mem.eql(u8, op, "==")) {
            return if (std.mem.eql(u8, left, right)) 0 else 1;
        }
        if (std.mem.eql(u8, op, "!=")) {
            return if (!std.mem.eql(u8, left, right)) 0 else 1;
        }

        // integer comparison
        const l = std.fmt.parseInt(i64, left, 10) catch 0;
        const r = std.fmt.parseInt(i64, right, 10) catch 0;

        if (std.mem.eql(u8, op, "-eq")) return if (l == r) 0 else 1;
        if (std.mem.eql(u8, op, "-ne")) return if (l != r) 0 else 1;
        if (std.mem.eql(u8, op, "-lt")) return if (l < r) 0 else 1;
        if (std.mem.eql(u8, op, "-le")) return if (l <= r) 0 else 1;
        if (std.mem.eql(u8, op, "-gt")) return if (l > r) 0 else 1;
        if (std.mem.eql(u8, op, "-ge")) return if (l >= r) 0 else 1;
    }

    return 1;
}

// ============ variable builtins ============

fn exportVar(shell: *Shell, args: []const []const u8) !u8 {
    for (args[1..]) |arg| {
        if (std.mem.indexOfScalar(u8, arg, '=')) |eq_pos| {
            const name = arg[0..eq_pos];
            const value = arg[eq_pos + 1 ..];
            try setVar(shell, name, value);
        } else {
            try shell.stdout().print("export: {s}: not a valid identifier\n", .{arg});
            return 1;
        }
    }
    return 0;
}

fn unset(shell: *Shell, args: []const []const u8) !u8 {
    for (args[1..]) |arg| {
        if (shell.variables.fetchRemove(arg)) |kv| {
            shell.allocator.free(kv.key);
            shell.allocator.free(kv.value);
        }
    }
    return 0;
}

fn local(shell: *Shell, args: []const []const u8) !u8 {
    for (args[1..]) |arg| {
        if (std.mem.indexOfScalar(u8, arg, '=')) |eq_pos| {
            const name = arg[0..eq_pos];
            const value = arg[eq_pos + 1 ..];
            try setVar(shell, name, value);
        } else {
            try setVar(shell, arg, "");
        }
    }
    return 0;
}

fn readonly(shell: *Shell, args: []const []const u8) !u8 {
    // simplified: just set the variable (no actual readonly enforcement)
    return local(shell, args);
}

fn set(shell: *Shell, args: []const []const u8) !u8 {
    // set -- arg1 arg2 ... sets positional parameters
    if (args.len >= 2 and std.mem.eql(u8, args[1], "--")) {
        // clear existing positional parameters
        var i: usize = 1;
        while (i <= 99) : (i += 1) {
            var num_buf: [16]u8 = undefined;
            const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{i}) catch break;
            if (shell.variables.fetchRemove(num_str)) |kv| {
                shell.allocator.free(kv.key);
                shell.allocator.free(kv.value);
            } else break;
        }
        // set new positional parameters
        for (args[2..], 1..) |arg, idx| {
            var num_buf: [16]u8 = undefined;
            const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{idx}) catch continue;
            try setVar(shell, num_str, arg);
        }
        // set $#
        var count_buf: [16]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{args.len - 2}) catch "0";
        try setVar(shell, "#", count_str);
        return 0;
    }

    // set option [on|off]
    if (args.len < 2) {
        try shell.stdout().writeAll("usage: set <option> [on|off] or set -- args...\n");
        try shell.stdout().writeAll("options: git_prompt, vim\n");
        return 0;
    }

    const option = args[1];
    const value = if (args.len > 2) args[2] else "on";
    const enabled = std.mem.eql(u8, value, "on") or std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "true");

    if (std.mem.eql(u8, option, "git_prompt")) {
        shell.show_git_info = enabled;
    } else if (std.mem.eql(u8, option, "vim")) {
        shell.vim_mode_enabled = enabled;
    } else {
        try shell.stdout().print("set: unknown option: {s}\n", .{option});
        return 1;
    }
    return 0;
}

fn shift(shell: *Shell, args: []const []const u8) !u8 {
    const n: usize = if (args.len > 1)
        std.fmt.parseInt(usize, args[1], 10) catch 1
    else
        1;

    const argc_str = shell.variables.get("#") orelse "0";
    const argc = std.fmt.parseInt(usize, argc_str, 10) catch 0;

    if (n > argc) {
        try shell.stdout().print("shift: {d}: shift count out of range\n", .{n});
        return 1;
    }

    // shift: $2 -> $1, $3 -> $2, etc
    var i: usize = 1;
    while (i <= argc - n) : (i += 1) {
        var src_buf: [16]u8 = undefined;
        var dst_buf: [16]u8 = undefined;
        const src_str = std.fmt.bufPrint(&src_buf, "{d}", .{i + n}) catch continue;
        const dst_str = std.fmt.bufPrint(&dst_buf, "{d}", .{i}) catch continue;

        if (shell.variables.get(src_str)) |value| {
            try setVar(shell, dst_str, value);
        }
    }

    // remove extra parameters
    i = argc - n + 1;
    while (i <= argc) : (i += 1) {
        var num_buf: [16]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{i}) catch continue;
        if (shell.variables.fetchRemove(num_str)) |old| {
            shell.allocator.free(old.key);
            shell.allocator.free(old.value);
        }
    }

    // update $#
    var count_buf: [16]u8 = undefined;
    const new_count = std.fmt.bufPrint(&count_buf, "{d}", .{argc - n}) catch "0";
    try setVar(shell, "#", new_count);

    return 0;
}

fn getopts(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 3) {
        try shell.stdout().writeAll("getopts: usage: getopts optstring name\n");
        return 1;
    }

    const optstring = args[1];
    const varname = args[2];

    const optind_str = shell.variables.get("OPTIND") orelse "1";
    var optind = std.fmt.parseInt(usize, optind_str, 10) catch 1;

    var idx_buf: [16]u8 = undefined;
    const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{optind}) catch return 1;
    const arg = shell.variables.get(idx_str) orelse return 1;

    if (arg.len < 2 or arg[0] != '-') return 1;

    const opt = arg[1];

    var valid = false;
    var needs_arg = false;
    for (optstring, 0..) |c, i| {
        if (c == opt) {
            valid = true;
            if (i + 1 < optstring.len and optstring[i + 1] == ':') {
                needs_arg = true;
            }
            break;
        }
    }

    if (!valid) {
        try setVar(shell, varname, "?");
        try setVar(shell, "OPTARG", "");
        optind += 1;
        try setOptind(shell, optind);
        return 0;
    }

    var opt_buf: [2]u8 = .{ opt, 0 };
    try setVar(shell, varname, opt_buf[0..1]);

    if (needs_arg) {
        if (arg.len > 2) {
            try setVar(shell, "OPTARG", arg[2..]);
            optind += 1;
        } else {
            optind += 1;
            var next_buf: [16]u8 = undefined;
            const next_str = std.fmt.bufPrint(&next_buf, "{d}", .{optind}) catch return 1;
            const next_arg = shell.variables.get(next_str) orelse {
                try shell.stdout().print("getopts: option requires argument -- {c}\n", .{opt});
                return 1;
            };
            try setVar(shell, "OPTARG", next_arg);
            optind += 1;
        }
    } else {
        try setVar(shell, "OPTARG", "");
        optind += 1;
    }

    try setOptind(shell, optind);
    return 0;
}

// ============ alias builtins ============

fn alias(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len == 1) {
        var iter = shell.aliases.iterator();
        while (iter.next()) |entry| {
            try shell.stdout().print("alias {s}='{s}'\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        return 0;
    }

    for (args[1..]) |arg| {
        if (std.mem.indexOfScalar(u8, arg, '=')) |eq_pos| {
            const name = arg[0..eq_pos];
            var value = arg[eq_pos + 1 ..];

            // remove quotes if present
            if (value.len >= 2) {
                if ((value[0] == '\'' and value[value.len - 1] == '\'') or
                    (value[0] == '"' and value[value.len - 1] == '"'))
                {
                    value = value[1 .. value.len - 1];
                }
            }

            const name_copy = try shell.allocator.dupe(u8, name);
            const value_copy = try shell.allocator.dupe(u8, value);

            if (shell.aliases.fetchRemove(name_copy)) |old| {
                shell.allocator.free(old.key);
                shell.allocator.free(old.value);
            }

            try shell.aliases.put(name_copy, value_copy);
        } else {
            if (shell.aliases.get(arg)) |value| {
                try shell.stdout().print("alias {s}='{s}'\n", .{ arg, value });
            } else {
                try shell.stdout().print("alias: {s}: not found\n", .{arg});
                return 1;
            }
        }
    }
    return 0;
}

fn unalias(shell: *Shell, args: []const []const u8) !u8 {
    for (args[1..]) |arg| {
        if (shell.aliases.fetchRemove(arg)) |old| {
            shell.allocator.free(old.key);
            shell.allocator.free(old.value);
        }
    }
    return 0;
}

// ============ source/eval/exec ============

fn source(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) {
        try shell.stdout().print("{s}: filename argument required\n", .{args[0]});
        return 1;
    }
    const filename = args[1];

    const file = std.fs.cwd().openFile(filename, .{}) catch {
        try shell.stdout().print("{s}: {s}: No such file or directory\n", .{ args[0], filename });
        return 1;
    };
    defer file.close();

    const content = file.readToEndAlloc(shell.allocator, 1024 * 1024) catch {
        try shell.stdout().print("{s}: {s}: Error reading file\n", .{ args[0], filename });
        return 1;
    };
    defer shell.allocator.free(content);

    // set positional parameters from remaining args
    for (args[2..], 1..) |arg, i| {
        var num_buf: [16]u8 = undefined;
        const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{i}) catch continue;
        try setVar(shell, num_str, arg);
    }

    var p = parser.Parser.init(content, shell.allocator) catch {
        try shell.stdout().print("{s}: {s}: Parse error\n", .{ args[0], filename });
        return 1;
    };
    defer p.deinit();

    const tree = p.parse() catch {
        try shell.stdout().print("{s}: {s}: Syntax error\n", .{ args[0], filename });
        return 1;
    };

    const eval_mod = @import("eval.zig");
    return try eval_mod.evaluateAst(shell, tree);
}

fn eval(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) return 0;

    var total_len: usize = 0;
    for (args[1..]) |arg| {
        total_len += arg.len + 1;
    }

    const cmd = try shell.allocator.alloc(u8, total_len);
    defer shell.allocator.free(cmd);

    var pos: usize = 0;
    for (args[1..], 0..) |arg, i| {
        @memcpy(cmd[pos..][0..arg.len], arg);
        pos += arg.len;
        if (i < args.len - 2) {
            cmd[pos] = ' ';
            pos += 1;
        }
    }

    var p = parser.Parser.init(cmd[0..pos], shell.allocator) catch return 1;
    defer p.deinit();

    const tree = p.parse() catch {
        try shell.stdout().writeAll("eval: parse error\n");
        return 1;
    };

    const eval_mod = @import("eval.zig");
    return try eval_mod.evaluateAst(shell, tree);
}

fn exec(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) {
        try shell.stdout().writeAll("exec: usage: exec command [arguments]\n");
        return 1;
    }

    const cmd_name = args[1];
    const full_path = shell.lookupCommand(cmd_name) orelse cmd_name;

    var argv_buf: [256]?[*:0]const u8 = undefined;
    var arg_count: usize = 0;

    for (args[1..]) |arg| {
        if (arg_count >= 255) break;
        const duped = try shell.allocator.dupeZ(u8, arg);
        argv_buf[arg_count] = duped.ptr;
        arg_count += 1;
    }
    argv_buf[arg_count] = null;

    const argv = argv_buf[0..arg_count :null];
    const envp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));

    const path_z = try shell.allocator.dupeZ(u8, full_path);
    std.posix.execvpeZ(path_z.ptr, argv, envp) catch {
        shell.stdout().print("exec: {s}: command not found\n", .{cmd_name}) catch {};
        std.posix.exit(126);
    };
    unreachable;
}

// ============ info builtins ============

fn typeCmd(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) {
        try shell.stdout().writeAll("type: usage: type name [name ...]\n");
        return 1;
    }

    var ret: u8 = 0;
    for (args[1..]) |name| {
        if (shell.aliases.get(name)) |value| {
            try shell.stdout().print("{s} is aliased to '{s}'\n", .{ name, value });
            continue;
        }

        if (shell.functions.get(name)) |_| {
            try shell.stdout().print("{s} is a shell function\n", .{name});
            continue;
        }

        if (isBuiltin(name)) {
            try shell.stdout().print("{s} is a shell builtin\n", .{name});
            continue;
        }

        if (shell.lookupCommand(name)) |path| {
            try shell.stdout().print("{s} is {s}\n", .{ name, path });
            continue;
        }

        try shell.stdout().print("type: {s}: not found\n", .{name});
        ret = 1;
    }
    return ret;
}

fn hash(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) {
        var iter = shell.path_cache.iterator();
        while (iter.next()) |entry| {
            try shell.stdout().print("{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        return 0;
    }

    const arg = args[1];
    if (std.mem.eql(u8, arg, "-r")) {
        var iter = shell.path_cache.iterator();
        while (iter.next()) |entry| {
            shell.allocator.free(entry.key_ptr.*);
            shell.allocator.free(entry.value_ptr.*);
        }
        shell.path_cache.clearRetainingCapacity();
        return 0;
    }

    for (args[1..]) |name| {
        if (shell.lookupCommand(name)) |path| {
            try shell.stdout().print("{s}={s}\n", .{ name, path });
        } else {
            try shell.stdout().print("hash: {s}: not found\n", .{name});
        }
    }
    return 0;
}

fn history(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    const h = shell.history orelse {
        try shell.stdout().writeAll("history: not available\n");
        return 1;
    };

    for (h.entries.items, 1..) |entry, i| {
        const cmd = h.getCommand(entry);
        try shell.stdout().print("{d}  {s}\n", .{ i, cmd });
    }
    return 0;
}

fn help(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    try shell.stdout().writeAll(
        \\zish builtins:
        \\  cd, pwd, pushd, popd, dirs    directory navigation
        \\  echo, printf, read            i/o
        \\  export, unset, set, local     variables
        \\  alias, unalias                aliases
        \\  source, eval, exec            execution
        \\  type, hash, history           info
        \\  jobs, fg, bg, wait, kill      job control
        \\  test, [, true, false          conditionals
        \\  shift, getopts                argument handling
        \\
    );
    return 0;
}

// ============ job control ============

fn jobs(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    try shell.stdout().writeAll("jobs: no job control (not implemented)\n");
    return 0;
}

fn fg(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    try shell.stdout().writeAll("fg: no job control (not implemented)\n");
    return 1;
}

fn bg(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    try shell.stdout().writeAll("bg: no job control (not implemented)\n");
    return 1;
}

fn wait(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    // wait for any child
    const result = std.posix.waitpid(-1, 0);
    if (result.pid > 0) {
        try shell.stdout().print("[done] {d}\n", .{result.pid});
    }
    return 0;
}

fn kill(shell: *Shell, args: []const []const u8) !u8 {
    if (args.len < 2) {
        try shell.stdout().writeAll("kill: usage: kill [-signal] pid\n");
        return 1;
    }

    var sig: u8 = 15; // SIGTERM default
    var pid_start: usize = 1;

    // check for -l (list signals)
    if (std.mem.eql(u8, args[1], "-l")) {
        try shell.stdout().writeAll("HUP INT QUIT ILL TRAP ABRT IOT BUS FPE KILL USR1 SEGV USR2 PIPE ALRM\n");
        try shell.stdout().writeAll("TERM STKFLT CHLD CLD CONT STOP TSTP TTIN TTOU URG XCPU XFSZ VTALRM PROF\n");
        try shell.stdout().writeAll("WINCH IO POLL PWR SYS RT<N> RTMIN+<N> RTMAX-<N>\n");
        return 0;
    }

    // parse signal
    if (args[1][0] == '-') {
        const sig_str = args[1][1..];
        sig = std.fmt.parseInt(u8, sig_str, 10) catch blk: {
            // named signals
            if (std.mem.eql(u8, sig_str, "HUP")) break :blk 1;
            if (std.mem.eql(u8, sig_str, "INT")) break :blk 2;
            if (std.mem.eql(u8, sig_str, "QUIT")) break :blk 3;
            if (std.mem.eql(u8, sig_str, "KILL")) break :blk 9;
            if (std.mem.eql(u8, sig_str, "TERM")) break :blk 15;
            if (std.mem.eql(u8, sig_str, "STOP")) break :blk 19;
            if (std.mem.eql(u8, sig_str, "CONT")) break :blk 18;
            try shell.stdout().print("kill: invalid signal: {s}\n", .{sig_str});
            return 1;
        };
        pid_start = 2;
    }

    for (args[pid_start..]) |pid_str| {
        const pid = std.fmt.parseInt(std.posix.pid_t, pid_str, 10) catch {
            try shell.stdout().print("kill: invalid pid: {s}\n", .{pid_str});
            return 1;
        };
        const result = std.os.linux.kill(pid, sig);
        if (result != 0) {
            try shell.stdout().print("kill: {d}: operation not permitted\n", .{pid});
            return 1;
        }
    }
    return 0;
}

fn trap(shell: *Shell, args: []const []const u8) !u8 {
    _ = args;
    try shell.stdout().writeAll("trap: not implemented\n");
    return 1;
}

// ============ shell control ============

fn exit(shell: *Shell, args: []const []const u8) !u8 {
    const code: u8 = if (args.len > 1)
        std.fmt.parseInt(u8, args[1], 10) catch 0
    else
        shell.last_exit_code;

    shell.running = false;
    return code;
}

fn returnCmd(shell: *Shell, args: []const []const u8) !u8 {
    _ = shell;
    // return value for function
    if (args.len > 1) {
        return std.fmt.parseInt(u8, args[1], 10) catch 0;
    }
    return 0;
}

fn builtinCmd(shell: *Shell, args: []const []const u8) !u8 {
    // run builtin directly, bypassing alias lookup
    _ = shell;
    if (args.len < 2) return 0;
    // TODO: implement proper builtin dispatch
    return 0;
}

fn commandCmd(shell: *Shell, args: []const []const u8) !u8 {
    // run command directly, bypassing alias/function lookup
    // just return null to let eval.zig handle external command
    _ = shell;
    _ = args;
    return 127; // fall through to external command
}

// ============ helpers ============

fn setVar(shell: *Shell, name: []const u8, value: []const u8) !void {
    const name_copy = try shell.allocator.dupe(u8, name);
    const value_copy = try shell.allocator.dupe(u8, value);

    if (shell.variables.fetchRemove(name_copy)) |old| {
        shell.allocator.free(old.key);
        shell.allocator.free(old.value);
    }
    try shell.variables.put(name_copy, value_copy);
}

fn setOptind(shell: *Shell, optind: usize) !void {
    var buf: [16]u8 = undefined;
    const str = std.fmt.bufPrint(&buf, "{d}", .{optind}) catch "1";
    try setVar(shell, "OPTIND", str);
}
