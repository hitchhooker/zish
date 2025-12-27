// completion.zig - Tab completion logic for zish
const std = @import("std");
const Shell = @import("Shell.zig");
const tty = @import("tty.zig");
const git = @import("git.zig");
const editor = @import("editor.zig");
const input_mod = @import("input.zig");

pub const WordResult = struct {
    word: []const u8,
    start: usize,
    end: usize,
};

pub const CycleDirection = input_mod.CycleDirection;

/// Extract word at cursor position from command string
pub fn extractWordAtCursor(cmd: []const u8, cursor: usize) ?WordResult {
    if (cmd.len == 0) return null;

    var start = cursor;
    var end = cursor;

    while (start > 0 and cmd[start - 1] != ' ') start -= 1;
    while (end < cmd.len and cmd[end] != ' ') end += 1;

    return WordResult{ .word = cmd[start..end], .start = start, .end = end };
}

pub fn handleTabCompletion(self: *Shell) !void {
    if (self.edit_buf.len == 0) return;

    const cmd = self.edit_buf.slice();
    const word_result = extractWordAtCursor(cmd, self.edit_buf.cursor) orelse return;
    const word = word_result.word;
    const word_end = word_result.end;

    // check for git-aware completion
    if (try tryGitCompletion(self, cmd, word_result)) return;

    // check if we're completing a command (first word or after pipe/semicolon, no path separators)
    const is_command_position = blk: {
        if (std.mem.indexOf(u8, word, "/") != null) break :blk false;
        if (word_result.start == 0) break :blk true;
        // check if preceded by | or ; or && or ||
        var i = word_result.start;
        while (i > 0 and (cmd[i - 1] == ' ' or cmd[i - 1] == '\t')) i -= 1;
        if (i > 0 and (cmd[i - 1] == '|' or cmd[i - 1] == ';')) break :blk true;
        if (i > 1 and cmd[i - 2] == '&' and cmd[i - 1] == '&') break :blk true;
        break :blk false;
    };
    if (is_command_position and word.len > 0) {
        if (try tryCommandCompletion(self, word_result)) return;
    }

    // check for variable completion ($VAR)
    if (word.len > 0 and word[0] == '$') {
        if (try tryVariableCompletion(self, word_result)) return;
    }

    // determine base directory and search pattern
    var expanded_dir_buf: [4096]u8 = undefined;
    const search_dir: []const u8 = if (std.mem.lastIndexOf(u8, word, "/")) |last_slash| blk: {
        if (last_slash == 0) {
            break :blk "/";
        } else {
            const dir_part = word[0..last_slash];
            if (std.mem.startsWith(u8, dir_part, "~")) {
                const home = std.process.getEnvVarOwned(self.allocator, "HOME") catch break :blk dir_part;
                defer self.allocator.free(home);
                const rest = dir_part[1..];
                const expanded_len = home.len + rest.len;
                if (expanded_len < expanded_dir_buf.len) {
                    @memcpy(expanded_dir_buf[0..home.len], home);
                    @memcpy(expanded_dir_buf[home.len..expanded_len], rest);
                    break :blk expanded_dir_buf[0..expanded_len];
                }
            }
            break :blk dir_part;
        }
    } else if (std.mem.eql(u8, word, "~")) blk: {
        const home = std.process.getEnvVarOwned(self.allocator, "HOME") catch break :blk ".";
        defer self.allocator.free(home);
        if (home.len < expanded_dir_buf.len) {
            @memcpy(expanded_dir_buf[0..home.len], home);
            break :blk expanded_dir_buf[0..home.len];
        }
        break :blk ".";
    } else ".";

    const pattern = if (std.mem.lastIndexOf(u8, word, "/")) |last_slash|
        word[last_slash + 1 ..]
    else if (std.mem.eql(u8, word, "~"))
        ""
    else
        word;

    // find matches
    var matches = try std.ArrayList([]const u8).initCapacity(self.allocator, 16);
    defer {
        for (matches.items) |match| self.allocator.free(match);
        matches.deinit(self.allocator);
    }

    // collect existing arguments to filter out
    var existing_args = try std.ArrayList([]const u8).initCapacity(self.allocator, 16);
    defer existing_args.deinit(self.allocator);

    var arg_start: usize = 0;
    var in_arg = false;
    for (cmd, 0..) |c, idx| {
        if (c == ' ' or c == '\t' or c == '\n') {
            if (in_arg and idx > arg_start) {
                if (arg_start != word_result.start) {
                    existing_args.append(self.allocator, cmd[arg_start..idx]) catch {};
                }
            }
            in_arg = false;
        } else {
            if (!in_arg) {
                arg_start = idx;
                in_arg = true;
            }
        }
    }
    if (in_arg and arg_start != word_result.start and self.edit_buf.len > arg_start) {
        existing_args.append(self.allocator, cmd[arg_start..self.edit_buf.len]) catch {};
    }

    const dir = std.fs.cwd().openDir(search_dir, .{ .iterate = true }) catch return;
    var iter = dir.iterate();
    const show_hidden = pattern.len > 0 and pattern[0] == '.';
    while (try iter.next()) |entry| {
        // skip dotfiles unless pattern starts with .
        if (!show_hidden and entry.name.len > 0 and entry.name[0] == '.') continue;
        if (std.mem.startsWith(u8, entry.name, pattern)) {
            var already_exists = false;
            for (existing_args.items) |existing| {
                const existing_name = if (std.mem.lastIndexOf(u8, existing, "/")) |slash|
                    existing[slash + 1 ..]
                else
                    existing;

                if (std.mem.eql(u8, entry.name, existing_name)) {
                    already_exists = true;
                    break;
                }
                if (entry.kind == .directory) {
                    const with_slash = std.fmt.allocPrint(self.allocator, "{s}/", .{entry.name}) catch continue;
                    defer self.allocator.free(with_slash);
                    if (std.mem.eql(u8, with_slash, existing_name)) {
                        already_exists = true;
                        break;
                    }
                }
            }

            if (!already_exists) {
                const full_name = if (entry.kind == .directory)
                    try std.fmt.allocPrint(self.allocator, "{s}/", .{entry.name})
                else
                    try self.allocator.dupe(u8, entry.name);
                try matches.append(self.allocator, full_name);
            }
        }
    }

    if (matches.items.len == 0) {
        return;
    } else if (matches.items.len == 1) {
        const match = matches.items[0];
        const comp_str = match[pattern.len..];
        self.edit_buf.cursor = @intCast(word_end);
        _ = self.edit_buf.insertSlice(comp_str);
        // add trailing space for files (not directories)
        if (!std.mem.endsWith(u8, match, "/")) {
            _ = self.edit_buf.insertSlice(" ");
        }
        try self.renderLine();
    } else {
        // multiple matches - first try common prefix completion
        var common_prefix_len: usize = matches.items[0].len;
        for (matches.items[1..]) |match| {
            var i: usize = 0;
            while (i < common_prefix_len and i < match.len and matches.items[0][i] == match[i]) : (i += 1) {}
            common_prefix_len = i;
        }

        if (common_prefix_len > pattern.len) {
            const common_prefix = matches.items[0][0..common_prefix_len];
            const comp_str = common_prefix[pattern.len..];
            self.edit_buf.cursor = @intCast(word_end);
            const inserted = self.edit_buf.insertSlice(comp_str);
            if (inserted > 0) {
                try self.renderLine();
            }
            return;
        }

        // common prefix equals pattern - enter completion mode
        exitCompletionMode(self);

        for (matches.items) |match| {
            const owned = try self.allocator.dupe(u8, match);
            try self.completion_matches.append(self.allocator, owned);
        }

        self.completion_mode = true;
        self.completion_index = self.completion_matches.items.len;
        self.completion_word_start = word_result.start;
        self.completion_word_end = word_end;
        self.completion_original_len = self.edit_buf.len;
        self.completion_pattern_len = pattern.len;

        try displayCompletions(self);
    }
}

fn tryVariableCompletion(self: *Shell, word_result: WordResult) !bool {
    const word = word_result.word;
    if (word.len < 1 or word[0] != '$') return false;

    const pattern = word[1..]; // skip the $

    var matches = try std.ArrayList([]const u8).initCapacity(self.allocator, 32);
    defer {
        for (matches.items) |m| self.allocator.free(m);
        matches.deinit(self.allocator);
    }

    // get shell variables
    var var_iter = self.variables.iterator();
    while (var_iter.next()) |entry| {
        const name = entry.key_ptr.*;
        if (std.mem.startsWith(u8, name, pattern)) {
            const full = std.fmt.allocPrint(self.allocator, "${s}", .{name}) catch continue;
            matches.append(self.allocator, full) catch {
                self.allocator.free(full);
                continue;
            };
        }
    }

    if (matches.items.len == 0) return false;

    std.mem.sort([]const u8, matches.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    if (matches.items.len == 1) {
        const match = matches.items[0];
        const comp_str = match[word.len..];
        self.edit_buf.cursor = @intCast(word_result.end);
        _ = self.edit_buf.insertSlice(comp_str);
        try self.renderLine();
        return true;
    } else {
        return try showCompletionMatches(self, &matches, word_result, word);
    }
}

// must match isBuiltin() in eval.zig
const builtins = [_][]const u8{
    "echo",  "cd",      "pwd",      "exit",   "export",   "unset",
    "alias", "unalias", "source",   ".",      "history",  "type",
    "which", "set",     "true",     "false",  ":",        "test",
    "[",     "read",    "printf",   "break",  "continue", "return",
    "shift", "local",   "declare",  "readonly","jobs",    "fg",
    "bg",    "kill",    "wait",     "trap",   "eval",     "exec",
    "builtin","command","hash",     "help",
};

fn tryCommandCompletion(self: *Shell, word_result: WordResult) !bool {
    const pattern = word_result.word;

    var matches = try std.ArrayList([]const u8).initCapacity(self.allocator, 32);
    defer {
        for (matches.items) |m| self.allocator.free(m);
        matches.deinit(self.allocator);
    }

    var seen = std.StringHashMap(void).init(self.allocator);
    defer seen.deinit();

    // add matching builtins first
    for (builtins) |builtin| {
        if (std.mem.startsWith(u8, builtin, pattern)) {
            const name = self.allocator.dupe(u8, builtin) catch continue;
            seen.put(name, {}) catch {
                self.allocator.free(name);
                continue;
            };
            matches.append(self.allocator, name) catch {
                self.allocator.free(name);
                continue;
            };
        }
    }

    // search PATH directories for matching executables
    const path_env = std.process.getEnvVarOwned(self.allocator, "PATH") catch {
        if (matches.items.len > 0) {
            return if (matches.items.len == 1)
                try applySingleCompletion(self, matches.items[0], word_result)
            else
                try showCompletionMatches(self, &matches, word_result, pattern);
        }
        return false;
    };
    defer self.allocator.free(path_env);

    var path_iter = std.mem.splitScalar(u8, path_env, ':');
    while (path_iter.next()) |path_dir| {
        if (path_dir.len == 0) continue;

        const dir = std.fs.cwd().openDir(path_dir, .{ .iterate = true }) catch continue;
        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .file and entry.kind != .sym_link) continue;
            if (!std.mem.startsWith(u8, entry.name, pattern)) continue;
            if (seen.contains(entry.name)) continue;

            // check if executable
            const full_path = std.fs.path.join(self.allocator, &.{ path_dir, entry.name }) catch continue;
            defer self.allocator.free(full_path);

            const stat = std.fs.cwd().statFile(full_path) catch continue;
            if (stat.mode & 0o111 == 0) continue;

            const name = self.allocator.dupe(u8, entry.name) catch continue;
            seen.put(name, {}) catch {
                self.allocator.free(name);
                continue;
            };
            matches.append(self.allocator, name) catch {
                self.allocator.free(name);
                continue;
            };
        }
    }

    if (matches.items.len == 0) return false;

    // sort matches alphabetically
    std.mem.sort([]const u8, matches.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    if (matches.items.len == 1) {
        return try applySingleCompletion(self, matches.items[0], word_result);
    } else {
        return try showCompletionMatches(self, &matches, word_result, pattern);
    }
}

fn tryGitCompletion(self: *Shell, cmd: []const u8, word_result: WordResult) !bool {
    if (!std.mem.startsWith(u8, cmd, "git ")) return false;
    if (!git.isRepo()) return false;

    const after_git = cmd[4..];
    var parts = std.mem.splitScalar(u8, after_git, ' ');
    const subcommand = parts.next() orelse return false;

    var matches = try std.ArrayList([]const u8).initCapacity(self.allocator, 32);
    defer {
        for (matches.items) |m| self.allocator.free(m);
        matches.deinit(self.allocator);
    }

    const pattern = word_result.word;

    if (std.mem.eql(u8, subcommand, "add") or
        std.mem.eql(u8, subcommand, "restore") or
        std.mem.eql(u8, subcommand, "diff"))
    {
        if (git.getStatus(self.allocator)) |s| {
            var status = s;
            defer status.deinit();

            for (status.modified.items) |file| {
                if (std.mem.startsWith(u8, file, pattern)) {
                    matches.append(self.allocator, self.allocator.dupe(u8, file) catch continue) catch {};
                }
            }
            for (status.deleted.items) |file| {
                if (std.mem.startsWith(u8, file, pattern)) {
                    matches.append(self.allocator, self.allocator.dupe(u8, file) catch continue) catch {};
                }
            }
            for (status.untracked.items) |file| {
                if (std.mem.startsWith(u8, file, pattern)) {
                    matches.append(self.allocator, self.allocator.dupe(u8, file) catch continue) catch {};
                }
            }
        }
    } else if (std.mem.eql(u8, subcommand, "checkout") or
        std.mem.eql(u8, subcommand, "switch") or
        std.mem.eql(u8, subcommand, "merge") or
        std.mem.eql(u8, subcommand, "rebase"))
    {
        try getGitBranches(self, &matches, pattern);
    } else if (std.mem.eql(u8, subcommand, "branch")) {
        var has_delete = false;
        while (parts.next()) |part| {
            if (std.mem.eql(u8, part, "-d") or std.mem.eql(u8, part, "-D") or
                std.mem.eql(u8, part, "--delete"))
            {
                has_delete = true;
                break;
            }
        }
        if (has_delete) {
            try getGitBranches(self, &matches, pattern);
        }
    } else {
        return false;
    }

    if (matches.items.len == 0) return false;

    if (matches.items.len == 1) {
        return try applySingleCompletion(self, matches.items[0], word_result);
    } else {
        return try showCompletionMatches(self, &matches, word_result, pattern);
    }
}

fn getGitBranches(self: *Shell, matches: *std.ArrayList([]const u8), pattern: []const u8) !void {
    const refs_dir = std.fs.cwd().openDir(".git/refs/heads", .{ .iterate = true }) catch return;
    var dir = refs_dir;
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .file and std.mem.startsWith(u8, entry.name, pattern)) {
            const branch = try self.allocator.dupe(u8, entry.name);
            try matches.append(self.allocator, branch);
        }
    }
}

fn applySingleCompletion(self: *Shell, match: []const u8, word_result: WordResult) !bool {
    const pattern = word_result.word;
    const word_end = word_result.end;
    const comp_str = match[pattern.len..];

    self.edit_buf.cursor = @intCast(word_end);
    _ = self.edit_buf.insertSlice(comp_str);
    try self.renderLine();
    return true;
}

fn showCompletionMatches(self: *Shell, matches: *std.ArrayList([]const u8), word_result: WordResult, pattern: []const u8) !bool {
    if (matches.items.len == 0) return false;

    var common_prefix_len: usize = matches.items[0].len;
    for (matches.items[1..]) |match| {
        var i: usize = 0;
        while (i < common_prefix_len and i < match.len and matches.items[0][i] == match[i]) : (i += 1) {}
        common_prefix_len = i;
    }

    if (common_prefix_len > pattern.len) {
        const common_prefix = matches.items[0][0..common_prefix_len];
        const comp_str = common_prefix[pattern.len..];
        self.edit_buf.cursor = @intCast(word_result.end);
        const inserted = self.edit_buf.insertSlice(comp_str);
        if (inserted > 0) {
            try self.renderLine();
        }
        return true;
    }

    // enter completion mode
    exitCompletionMode(self);

    for (matches.items) |match| {
        const owned = try self.allocator.dupe(u8, match);
        try self.completion_matches.append(self.allocator, owned);
    }

    self.completion_mode = true;
    self.completion_index = self.completion_matches.items.len;
    self.completion_word_start = word_result.start;
    self.completion_word_end = word_result.end;
    self.completion_original_len = self.edit_buf.len;
    self.completion_pattern_len = pattern.len;

    try displayCompletions(self);
    return true;
}

pub fn exitCompletionMode(self: *Shell) void {
    if (!self.completion_mode) return;

    for (self.completion_matches.items) |match| {
        self.allocator.free(match);
    }
    self.completion_matches.clearRetainingCapacity();

    self.completion_mode = false;
    self.completion_index = 0;
    self.completion_pattern_len = 0;
    self.completion_menu_lines = 0;
    self.completion_displayed = false;
}

pub fn handleCompletionCycle(self: *Shell, direction: CycleDirection) !void {
    if (self.completion_matches.items.len == 0) return;

    const old_index = self.completion_index;
    const nothing_selected = old_index >= self.completion_matches.items.len;

    switch (direction) {
        .forward => {
            if (nothing_selected) {
                self.completion_index = 0;
            } else {
                self.completion_index = (self.completion_index + 1) % self.completion_matches.items.len;
            }
        },
        .backward => {
            if (nothing_selected) {
                self.completion_index = self.completion_matches.items.len - 1;
            } else if (self.completion_index == 0) {
                self.completion_index = self.completion_matches.items.len - 1;
            } else {
                self.completion_index -= 1;
            }
        },
    }

    try applyCompletion(self, self.completion_pattern_len);

    if (self.completion_displayed) {
        try updateCompletionHighlight(self, old_index);
    } else {
        try displayCompletions(self);
    }
}

fn applyCompletion(self: *Shell, pattern_len: usize) !void {
    if (self.completion_matches.items.len == 0) return;

    const match = self.completion_matches.items[self.completion_index];
    const comp_str = match[pattern_len..];

    self.edit_buf.len = @intCast(self.completion_original_len);
    self.edit_buf.cursor = @intCast(self.completion_word_end);
    _ = self.edit_buf.insertSlice(comp_str);
}

pub fn displayCompletions(self: *Shell) !void {
    if (self.completion_matches.items.len == 0) return;

    const term_width = self.terminal_width;
    const term_height = self.terminal_height;
    const max_menu_height = if (term_height > 3) term_height - 3 else 1;

    if (term_width < 80) {
        try self.stdout().writeByte('\n');

        const items_to_show = @min(self.completion_matches.items.len, max_menu_height);
        const start_idx = if (self.completion_matches.items.len > items_to_show) blk: {
            const half_window = items_to_show / 2;
            if (self.completion_index < half_window) {
                break :blk 0;
            } else if (self.completion_index + half_window >= self.completion_matches.items.len) {
                break :blk self.completion_matches.items.len - items_to_show;
            } else {
                break :blk self.completion_index - half_window;
            }
        } else 0;

        const end_idx = @min(start_idx + items_to_show, self.completion_matches.items.len);

        for (self.completion_matches.items[start_idx..end_idx], start_idx..) |match, i| {
            if (i == self.completion_index and self.completion_index < self.completion_matches.items.len) {
                try self.stdout().print("{f}{s}{f}\n", .{ tty.Style.reverse, match, tty.Style.reset });
            } else {
                try self.stdout().print("{s}\n", .{match});
            }
        }

        if (end_idx < self.completion_matches.items.len) {
            try self.stdout().print("... ({} more)\n", .{self.completion_matches.items.len - end_idx});
            self.completion_menu_lines = items_to_show + 1;
        } else if (start_idx > 0) {
            try self.stdout().print("... ({} hidden above)\n", .{start_idx});
            self.completion_menu_lines = items_to_show + 1;
        } else {
            self.completion_menu_lines = items_to_show;
        }

        try self.renderLine();
        self.completion_displayed = true;
        return;
    }

    try self.stdout().writeByte('\n');

    const max_item_width: usize = 30;
    var max_len: usize = 0;
    for (self.completion_matches.items) |match| {
        const display_len = @min(match.len, max_item_width);
        if (display_len > max_len) max_len = display_len;
    }
    const col_width = max_len + 2;
    const max_line_width: usize = 120;
    const effective_width = @min(term_width, max_line_width);
    const cols = @max(1, effective_width / col_width);

    const total_menu_lines = (self.completion_matches.items.len + cols - 1) / cols;
    const menu_lines = @min(total_menu_lines, max_menu_height);
    self.completion_menu_lines = menu_lines;

    const max_items = menu_lines * cols;
    const items_to_show = @min(self.completion_matches.items.len, max_items);

    for (self.completion_matches.items[0..items_to_show], 0..) |match, i| {
        const display_name = if (match.len > max_item_width) match[0 .. max_item_width - 1] else match;
        const truncated = match.len > max_item_width;

        if (i == self.completion_index and self.completion_index < self.completion_matches.items.len) {
            try self.stdout().print("{f}{s}", .{ tty.Style.reverse, display_name });
            if (truncated) try self.stdout().writeByte('~');
            try self.stdout().print("{f}", .{tty.Style.reset});
        } else {
            try self.stdout().print("{s}", .{display_name});
            if (truncated) try self.stdout().writeByte('~');
        }

        const actual_len = if (truncated) max_item_width else match.len;
        const padding = col_width - actual_len;
        var j: usize = 0;
        while (j < padding) : (j += 1) {
            try self.stdout().writeByte(' ');
        }

        if ((i + 1) % cols == 0 or i == items_to_show - 1) {
            try self.stdout().writeByte('\n');
        }
    }

    if (items_to_show < self.completion_matches.items.len) {
        try self.stdout().print("... ({} more matches)\n", .{self.completion_matches.items.len - items_to_show});
        self.completion_menu_lines += 1;
    }

    try self.renderLine();
    self.completion_displayed = true;
}

pub fn updateCompletionHighlight(self: *Shell, old_index: usize) !void {
    const term_width = self.terminal_width;

    if (old_index >= self.completion_matches.items.len) {
        const max_item_width: usize = 30;
        var max_len: usize = 0;
        for (self.completion_matches.items) |match| {
            const display_len = @min(match.len, max_item_width);
            if (display_len > max_len) max_len = display_len;
        }
        const col_width = max_len + 2;
        const max_line_width: usize = 120;
        const effective_width = @min(term_width, max_line_width);
        const cols = @max(1, effective_width / col_width);

        const new_row = self.completion_index / cols;
        const new_col = self.completion_index % cols;

        const lines_up = self.completion_menu_lines + 1;
        try self.stdout().print("\x1b[{d}A", .{lines_up});
        try self.stdout().print("\x1b[{d}B", .{new_row + 1});
        const new_col_pos = new_col * col_width;
        try self.stdout().print("\x1b[{d}G", .{new_col_pos + 1});
        try self.stdout().print("{f}{s}{f}", .{ tty.Style.reverse, self.completion_matches.items[self.completion_index], tty.Style.reset });

        const current_row = new_row + 1;
        const rows_to_bottom = self.completion_menu_lines - current_row;
        if (rows_to_bottom > 0) {
            try self.stdout().print("\x1b[{d}B", .{rows_to_bottom});
        }
        try self.stdout().print("\x1b[{d}B", .{1});

        try self.stdout().writeAll("\r\x1b[K");
        try self.renderLine();
        return;
    }

    if (term_width < 80) {
        try self.stdout().writeAll("\r");
        if (self.completion_menu_lines > 0) {
            try self.stdout().print("\x1b[{d}A", .{self.completion_menu_lines});
        }
        try self.stdout().writeAll("\x1b[J");
        try displayCompletions(self);
        return;
    }

    const max_item_width: usize = 30;
    var max_len: usize = 0;
    for (self.completion_matches.items) |match| {
        const display_len = @min(match.len, max_item_width);
        if (display_len > max_len) max_len = display_len;
    }
    const col_width = max_len + 2;
    const max_line_width: usize = 120;
    const effective_width = @min(term_width, max_line_width);
    const cols = @max(1, effective_width / col_width);

    const old_row = old_index / cols;
    const old_col = old_index % cols;
    const new_row = self.completion_index / cols;
    const new_col = self.completion_index % cols;

    const lines_up = self.completion_menu_lines + 1;
    try self.stdout().print("\x1b[{d}A", .{lines_up});

    try self.stdout().print("\x1b[{d}B", .{old_row + 1});
    const old_col_pos = old_col * col_width;
    try self.stdout().print("\x1b[{d}G", .{old_col_pos + 1});
    try self.stdout().print("{s}", .{self.completion_matches.items[old_index]});

    if (new_row > old_row) {
        try self.stdout().print("\x1b[{d}B", .{new_row - old_row});
    } else if (old_row > new_row) {
        try self.stdout().print("\x1b[{d}A", .{old_row - new_row});
    }
    const new_col_pos = new_col * col_width;
    try self.stdout().print("\x1b[{d}G", .{new_col_pos + 1});
    try self.stdout().print("{f}{s}{f}", .{ tty.Style.reverse, self.completion_matches.items[self.completion_index], tty.Style.reset });

    const current_row = new_row + 1;
    const rows_to_bottom = self.completion_menu_lines - current_row;
    if (rows_to_bottom > 0) {
        try self.stdout().print("\x1b[{d}B", .{rows_to_bottom});
    }
    try self.stdout().print("\x1b[{d}B", .{1});

    try self.stdout().writeAll("\r\x1b[K");
    try self.renderLine();
}
