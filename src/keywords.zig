// keywords.zig - Shell keywords and builtins for zish
// Centralized list for lexer, highlighter, and completion

const std = @import("std");

pub const shell_keywords = [_][]const u8{
    "break",
    "case",
    "coproc",
    "do",
    "done",
    "elif",
    "else",
    "esac",
    "exec",
    "exit",
    "fi",
    "for",
    "function",
    "if",
    "in",
    "return",
    "select",
    "then",
    "time",
    "trap",
    "until",
    "while",
};

/// Standard bash builtin names for syntax highlighting.
/// NOTE: This includes builtins zish hasn't implemented yet.
/// For runtime dispatch, use builtins.isBuiltin() instead.
pub const shell_builtins = [_][]const u8{
    "alias",
    "bg",
    "bind",
    "builtin",
    "caller",
    "cd",
    "chdir",
    "command",
    "declare",
    "echo",
    "enable",
    "eval",
    "export",
    "false",
    "fg",
    "getopts",
    "hash",
    "help",
    "history",
    "jobs",
    "kill",
    "let",
    "local",
    "logout",
    "mapfile",
    "popd",
    "printf",
    "pushd",
    "pwd",
    "read",
    "readarray",
    "readonly",
    "set",
    "shift",
    "source",
    "stop",
    "suspend",
    "test",
    "times",
    "true",
    "type",
    "typeset",
    "ulimit",
    "unalias",
    "unset",
    "wait",
    "which",
};

pub fn isKeyword(word: []const u8) bool {
    for (shell_keywords) |kw| {
        if (std.mem.eql(u8, word, kw)) return true;
    }
    return false;
}

pub fn isBuiltin(word: []const u8) bool {
    for (shell_builtins) |b| {
        if (std.mem.eql(u8, word, b)) return true;
    }
    return false;
}
