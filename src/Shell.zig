const Shell = @This();

const std = @import("std");
const types = @import("types.zig");
const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const ast = @import("ast.zig");
const glob = @import("glob.zig");
const hist = @import("history.zig");
const tty = @import("tty.zig");
const input_mod = @import("input.zig");
const completion_mod = @import("completion.zig");
const eval = @import("eval.zig");
const git = @import("git.zig");
const editor = @import("editor.zig");
const vim = @import("vim.zig");

// Re-export from input module (for compatibility)
const VimMode = input_mod.VimMode;
const WordBoundary = input_mod.WordBoundary;
const HistoryDirection = input_mod.HistoryDirection;
const SearchDirection = input_mod.SearchDirection;
const MoveCursorAction = input_mod.MoveCursorAction;
const DeleteAction = input_mod.DeleteAction;
const YankAction = input_mod.YankAction;
const PasteAction = input_mod.PasteAction;
const InsertAtPosition = input_mod.InsertAtPosition;
const VimModeAction = input_mod.VimModeAction;
const Action = input_mod.Action;
const CycleDirection = input_mod.CycleDirection;

// Control key constants
const CTRL_C = input_mod.CTRL_C;
const CTRL_T = input_mod.CTRL_T;
const CTRL_L = input_mod.CTRL_L;
const CTRL_D = input_mod.CTRL_D;
const CTRL_B = input_mod.CTRL_B;

// global shell instance for signal handler
var global_shell: ?*Shell = null;

// ansi color codes for zsh-like colorful prompt
const Colors = struct {
    const default_color = tty.Color.reset;
    const path = tty.Color.cyan;
    const userhost = tty.Color.green;
    const normal_mode = tty.Color.red;
    const insert_mode = tty.Color.yellow;
};

allocator: std.mem.Allocator,
running: bool,
history: ?*hist.History,
vim_mode: VimMode,
vim_mode_enabled: bool,
history_index: i32,
history_search_prefix_len: usize,
original_termios: ?std.posix.termios = null,
aliases: std.StringHashMap([]const u8),
variables: std.StringHashMap([]const u8),
functions: std.StringHashMap(*const ast.AstNode), // name -> body AST
last_exit_code: u8 = 0,
// when true, external commands exec directly instead of fork+exec (for pipeline children)
in_pipeline: bool = false,

// new modular editor
edit_buf: editor.EditBuffer = .{},
term_view: editor.TermView,
vi: vim.Vim = .{},

// vim clipboard for yank/paste operations (legacy, now in vi.yank_buf)
clipboard: []u8,
clipboard_len: usize = 0,
// search state
search_mode: bool = false,
search_buffer: []u8,
search_len: usize = 0,
// paste mode (bracketed paste)
paste_mode: bool = false,
// completion state
completion_mode: bool = false,
completion_matches: std.ArrayList([]const u8),
completion_index: usize = 0,
completion_word_start: usize = 0,
completion_word_end: usize = 0,
completion_original_len: usize = 0,
completion_pattern_len: usize = 0,
completion_menu_lines: usize = 0,
completion_displayed: bool = false,

// git info display (set via .zishrc: set git_prompt on)
show_git_info: bool = false,

// track displayed command lines for proper clearing
displayed_cmd_lines: usize = 1,
// track terminal cursor row (within our displayed content)
// this may differ from logical cursor during paste
terminal_cursor_row: usize = 0,

// terminal resize handling
terminal_resized: bool = false,
terminal_width: usize = 80,
terminal_height: usize = 24,
last_resize_time: i64 = 0,

stdout_writer: std.fs.File.Writer,
log_file: ?std.fs.File = null,

// PATH lookup cache - maps command name -> full path
path_cache: std.StringHashMap([]const u8),

pub fn init(allocator: std.mem.Allocator) !*Shell {
    return initWithOptions(allocator, true);
}

pub fn initNonInteractive(allocator: std.mem.Allocator) !*Shell {
    return initWithOptions(allocator, false);
}

fn initWithOptions(allocator: std.mem.Allocator, load_config: bool) !*Shell {
    const shell = try allocator.create(Shell);

    // only load history for interactive mode
    const history = if (load_config)
        hist.History.init(allocator, null) catch null
    else
        null;

    const clipboard_buffer = try allocator.alloc(u8, types.MAX_COMMAND_LENGTH);
    const search_buffer = try allocator.alloc(u8, 256); // search queries are usually short

    const writer_buffer = try allocator.alloc(u8, types.MAX_COMMAND_LENGTH + types.MAX_PROMPT_LENGTH);

    shell.* = .{
        .allocator = allocator,
        .running = false,
        .history = history,
        .vim_mode = .insert,
        .vim_mode_enabled = true,
        .history_index = -1,
        .history_search_prefix_len = 0,
        .original_termios = null,
        .aliases = std.StringHashMap([]const u8).init(allocator),
        .variables = std.StringHashMap([]const u8).init(allocator),
        .functions = std.StringHashMap(*const ast.AstNode).init(allocator),
        // new modular editor
        .edit_buf = .{},
        .term_view = editor.TermView.init(std.posix.STDERR_FILENO),
        .vi = .{},
        .clipboard = clipboard_buffer,
        .clipboard_len = 0,
        .search_mode = false,
        .search_buffer = search_buffer,
        .search_len = 0,
        .completion_mode = false,
        .completion_matches = std.ArrayList([]const u8){ .items = &.{}, .capacity = 0 },
        .completion_index = 0,
        .completion_word_start = 0,
        .completion_word_end = 0,
        .completion_original_len = 0,
        .completion_pattern_len = 0,
        .completion_menu_lines = 0,
        .completion_displayed = false,
        .stdout_writer = .init(.stdout(), writer_buffer),
        .path_cache = std.StringHashMap([]const u8).init(allocator),
    };

    // don't enable raw mode here - will be enabled by run() for interactive mode
    // this prevents issues with child processes in non-interactive mode

    // load config only for interactive mode
    if (load_config) {
        shell.loadConfig() catch {}; // don't fail if no config file
    }

    return shell;
}

pub fn deinit(self: *Shell) void {
    // restore terminal mode before cleanup
    self.disableRawMode();

    // restore default cursor style
    self.setCursorStyle(.default) catch {};

    // cleanup aliases
    var it = self.aliases.iterator();
    while (it.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
        self.allocator.free(entry.value_ptr.*);
    }
    self.aliases.deinit();

    // cleanup variables
    var var_it = self.variables.iterator();
    while (var_it.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
        self.allocator.free(entry.value_ptr.*);
    }
    self.variables.deinit();

    // cleanup functions
    var fn_it = self.functions.iterator();
    while (fn_it.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
        entry.value_ptr.*.destroy(self.allocator); // free AST
    }
    self.functions.deinit();

    if (self.history) |h| h.deinit();

    // cleanup completion matches
    for (self.completion_matches.items) |match| {
        self.allocator.free(match);
    }
    self.completion_matches.deinit(self.allocator);

    // cleanup path cache
    var path_it = self.path_cache.iterator();
    while (path_it.next()) |entry| {
        self.allocator.free(entry.key_ptr.*);
        self.allocator.free(entry.value_ptr.*);
    }
    self.path_cache.deinit();

    self.allocator.free(self.clipboard);
    self.allocator.free(self.search_buffer);
    self.allocator.free(self.stdout().buffer);
    self.allocator.destroy(self);
}
/// Get command slice (prefers edit_buf)
fn getCommand(self: *Shell) []const u8 {
    return self.edit_buf.slice();
}

fn clearCommand(self: *Shell) void {
    self.edit_buf.clear();
}

/// Render using TermView
pub fn renderLine(self: *Shell) !void {
    var prompt_buf: [256]u8 = undefined;
    const prompt = self.buildPrompt(&prompt_buf);
    try self.term_view.render(&self.edit_buf, prompt.slice, prompt.visible_len);
}

const PromptInfo = struct {
    slice: []const u8,
    visible_len: u16,
};

fn buildPrompt(self: *Shell, buf: *[256]u8) PromptInfo {
    // get mode indicator
    const mode_str = self.vi.modeIndicatorColored();

    // get user
    const user = std.process.getEnvVarOwned(self.allocator, "USER") catch "?";
    defer if (!std.mem.eql(u8, user, "?")) self.allocator.free(user);

    // get hostname
    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = std.posix.gethostname(&hostname_buf) catch "localhost";

    // get cwd
    var cwd_buf: [256]u8 = undefined;
    const cwd = std.posix.getcwd(&cwd_buf) catch "?";

    // simplify home path
    const home = std.process.getEnvVarOwned(self.allocator, "HOME") catch null;
    defer if (home) |h| self.allocator.free(h);

    var path_buf: [256]u8 = undefined;
    const display_path = if (home) |h| blk: {
        if (std.mem.startsWith(u8, cwd, h)) {
            if (std.mem.eql(u8, cwd, h)) {
                break :blk "~";
            } else {
                break :blk std.fmt.bufPrint(&path_buf, "~{s}", .{cwd[h.len..]}) catch cwd;
            }
        }
        break :blk cwd;
    } else cwd;

    // color codes
    const green = "\x1b[32m"; // user@host
    const cyan = "\x1b[36m"; // path
    const reset = "\x1b[0m";

    // format: [M] user@host path $
    const len = std.fmt.bufPrint(buf, "{s} {s}{s}@{s}{s} {s}{s}{s} $ ", .{
        mode_str,
        green, user, hostname, reset,
        cyan, display_path, reset,
    }) catch return .{ .slice = "$ ", .visible_len = 2 };

    // calculate visible length (mode indicator is 3-4 chars visible)
    const mode_visible: u16 = if (self.vi.mode == .visual_line) 4 else 3;
    const rest_visible = @as(u16, @intCast(user.len + 1 + hostname.len + 1 + display_path.len + 3)); // @ + space + " $ "

    return .{
        .slice = buf[0..len.len],
        .visible_len = mode_visible + 1 + rest_visible, // +1 for space after mode
    };
}

/// Look up a command in PATH, using cache when possible
pub fn lookupCommand(self: *Shell, cmd_name: []const u8) ?[]const u8 {
    // don't cache absolute/relative paths
    if (cmd_name.len > 0 and (cmd_name[0] == '/' or cmd_name[0] == '.')) {
        return null;
    }

    // check cache first
    if (self.path_cache.get(cmd_name)) |cached_path| {
        // verify file still exists and is executable
        const file = if (std.fs.path.isAbsolute(cached_path))
            std.fs.openFileAbsolute(cached_path, .{})
        else
            std.fs.cwd().openFile(cached_path, .{});
        if (file) |f| {
            f.close();
            return cached_path;
        } else |_| {
            // file no longer exists, remove from cache
            if (self.path_cache.fetchRemove(cmd_name)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
            }
            return self.searchPath(cmd_name);
        }
    }

    return self.searchPath(cmd_name);
}

fn searchPath(self: *Shell, cmd_name: []const u8) ?[]const u8 {
    // Check shell variables first (for exported PATH), then fall back to system env
    const path_env = self.variables.get("PATH") orelse (std.posix.getenv("PATH") orelse return null);

    var path_iter = std.mem.splitScalar(u8, path_env, ':');
    while (path_iter.next()) |dir| {
        if (dir.len == 0) continue;

        // build full path: dir + "/" + cmd_name
        const full_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, cmd_name }) catch continue;

        // check if file exists and is executable
        const file = (if (std.fs.path.isAbsolute(full_path))
            std.fs.openFileAbsolute(full_path, .{})
        else
            std.fs.cwd().openFile(full_path, .{})) catch {
            self.allocator.free(full_path);
            continue;
        };
        const stat = file.stat() catch {
            file.close();
            self.allocator.free(full_path);
            continue;
        };
        file.close();
        // check execute bit
        if ((stat.mode & 0o111) == 0) {
            self.allocator.free(full_path);
            continue;
        }

        // found it - cache and return
        const key_copy = self.allocator.dupe(u8, cmd_name) catch {
            self.allocator.free(full_path);
            return null;
        };

        self.path_cache.put(key_copy, full_path) catch {
            self.allocator.free(key_copy);
            self.allocator.free(full_path);
            return null;
        };

        return full_path;
    }

    return null;
}

pub fn run(self: *Shell) !void {
    self.running = true;

    // enable raw mode for interactive input handling
    try self.enableRawMode();

    // setup signal handler for terminal resize
    self.setupResizeHandler();

    // initialize terminal dimensions
    const initial_size = self.getTerminalSize();
    self.terminal_width = initial_size.width;
    self.terminal_height = initial_size.height;

    // set initial cursor style based on vim mode
    const initial_cursor = if (self.vim_mode_enabled and self.vim_mode == .normal)
        CursorStyle.block
    else
        CursorStyle.bar;
    try self.setCursorStyle(initial_cursor);

    try self.renderLine();

    var last_action: Action = .none;

    while (self.running) {
        // handle terminal resize
        if (self.terminal_resized) {
            self.terminal_resized = false;
            try self.handleResize();
        }

        try self.log(last_action);
        last_action = try self.readNextAction();
        try self.handleAction(last_action);
        try self.stdout().flush();
    }
}

pub inline fn stdout(self: *Shell) *std.Io.Writer {
    return &self.stdout_writer.interface;
}

// cursor styles for vim modes
const CursorStyle = enum {
    block, // normal mode
    bar, // insert mode
    default, // restore terminal default

    fn escapeCode(self: CursorStyle) []const u8 {
        return switch (self) {
            .block => "\x1b[2 q", // steady block cursor
            .bar => "\x1b[6 q", // steady bar cursor
            .default => "\x1b[0 q", // reset to default
        };
    }
};

fn setCursorStyle(_: *Shell, style: CursorStyle) !void {
    // Write to stderr so it doesn't interfere with pipelines
    _ = std.posix.write(std.posix.STDERR_FILENO, style.escapeCode()) catch {};
}

const TerminalSize = struct {
    width: usize,
    height: usize,
};

fn getTerminalSize(_: *Shell) TerminalSize {
    const TIOCGWINSZ = if (@hasDecl(std.posix.system, "T")) std.posix.system.T.IOCGWINSZ else 0x5413;

    const winsize = extern struct {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    };

    var ws: winsize = undefined;
    const result = std.posix.system.ioctl(std.posix.STDOUT_FILENO, TIOCGWINSZ, @intFromPtr(&ws));

    if (result == 0 and ws.ws_col > 0 and ws.ws_row > 0) {
        return .{ .width = ws.ws_col, .height = ws.ws_row };
    }

    return .{ .width = 80, .height = 24 }; // fallback if ioctl fails
}

fn handleSigwinch(_: c_int) callconv(.c) void {
    if (global_shell) |shell| {
        shell.terminal_resized = true;
    }
}

fn setupResizeHandler(self: *Shell) void {
    global_shell = self;

    const SIGWINCH = if (@hasDecl(std.posix.SIG, "WINCH")) std.posix.SIG.WINCH else 28;

    const empty_mask: std.posix.sigset_t = std.mem.zeroes(std.posix.sigset_t);

    var act = std.posix.Sigaction{
        .handler = .{ .handler = handleSigwinch },
        .mask = empty_mask,
        .flags = 0,
    };

    std.posix.sigaction(SIGWINCH, &act, null);
}

fn handleResize(self: *Shell) !void {
    // get current terminal size
    const new_size = self.getTerminalSize();

    // check if dimensions actually changed
    if (new_size.width == self.terminal_width and new_size.height == self.terminal_height) {
        return; // spurious SIGWINCH, nothing changed
    }

    // debounce rapid resizes
    const now = std.time.milliTimestamp();
    const debounce_ms = 50; // wait 50ms between redraws
    if (now - self.last_resize_time < debounce_ms) {
        // schedule another check by keeping the flag set
        self.terminal_resized = true;
        return;
    }
    self.last_resize_time = now;

    const old_width = self.terminal_width;
    const old_height = self.terminal_height;

    // update stored dimensions
    self.terminal_width = new_size.width;
    self.terminal_height = new_size.height;

    if (self.completion_mode and self.completion_displayed) {
        // smart clearing: only clear if we're shrinking or need to reflow
        if (new_size.width < old_width or new_size.height < old_height) {
            // terminal shrank, need full clear
            if (self.completion_menu_lines > 0) {
                try self.stdout().print("\x1b[{d}A", .{self.completion_menu_lines});
            }
            try self.stdout().writeAll("\x1b[J");
        } else {
            // terminal grew, just reposition
            if (self.completion_menu_lines > 0) {
                try self.stdout().print("\x1b[{d}A", .{self.completion_menu_lines});
            }
            try self.stdout().writeAll("\x1b[J");
        }

        // redraw with new dimensions
        try completion_mod.displayCompletions(self);
    } else {
        // just redraw the current line
        try self.renderLine();
    }
}

fn log(self: *Shell, last_action: Action) !void {
    if (self.log_file) |file| {
        var buff: [1024 * 256]u8 = undefined;
        const slice = try std.fmt.bufPrint(
            buff[0..],
            "\x1b[H\x1b[J" ++
                "State:\n" ++
                "\tcursor: {}\n" ++
                "\tvim_mode: {s}\n" ++
                "\tvim_mode_enabled: {}\n" ++
                "\thistory_index: {}\n" ++
                "\tbuf_len: {}\n" ++
                "\tsearch_mode: {}\n" ++
                "\tsearch_len: {}\n" ++
                "\tcommand: '{s}'\n" ++
                "\tsearch_buffer: '{s}'\n" ++
                "\tlast_action: '{}'\n",
            .{
                self.edit_buf.cursor, @tagName(self.vim_mode),
                self.vim_mode_enabled, self.history_index,
                self.edit_buf.len,
                self.search_mode, self.search_len,
                self.edit_buf.slice(), self.search_buffer[0..self.search_len],
                last_action,
            },
        );
        try file.writeAll(slice);
    }
}

fn handleAction(self: *Shell, action: Action) !void {
    switch (action) {
        .none => {},

        .cancel => {
            completion_mod.exitCompletionMode(self);
            // print ^C like bash does
            try self.stdout().writeAll("^C\n");
            try self.stdout().flush();
            // signal we're on a fresh line
            self.term_view.finishLine();
            self.displayed_cmd_lines = 1;
            self.terminal_cursor_row = 0;
            // clear and render new prompt
            self.clearCommand();
            self.paste_mode = false;
            self.history_index = -1;
            self.history_search_prefix_len = 0;
            self.vi.mode = .insert;
            self.vim_mode = .insert; // legacy compat
            try self.renderLine();
            try self.setCursorStyle(.bar);
        },

        .exit_shell => {
            self.running = false;
            try self.stdout().writeByte('\n');
        },

        .toggle_bookmark => {
            const h = self.history orelse return;

            if (self.history_index >= 0 and self.history_index < @as(i32, @intCast(h.entries.items.len))) {
                // Bookmark history entry we're viewing
                const idx: usize = @intCast(self.history_index);
                const is_now_bookmarked = !h.isEntryBookmarked(idx);
                h.toggleBookmark(idx) catch {};
                // Show indicator and redraw to clear it
                try self.stdout().writeAll(if (is_now_bookmarked) " *" else " -");
                try self.stdout().flush();
                std.Thread.sleep(80 * std.time.ns_per_ms);
                try self.renderLine();
            } else if (self.edit_buf.len > 0) {
                // Bookmark current command being typed
                const cmd = self.edit_buf.slice();
                // Add to history and bookmark it
                h.addCommand(cmd, 0) catch {};
                const cmd_hash = std.hash.Wyhash.hash(0, cmd);
                if (h.hash_map.get(cmd_hash)) |idx| {
                    h.toggleBookmark(idx) catch {};
                    try self.stdout().writeAll(" *");
                    try self.stdout().flush();
                    std.Thread.sleep(80 * std.time.ns_per_ms);
                    try self.renderLine();
                }
            }
        },

        .input_char => |char| {
            // exit completion mode when typing
            completion_mod.exitCompletionMode(self);

            if (self.search_mode) {
                // Add to search buffer
                if (self.search_len < self.search_buffer.len) {
                    self.search_buffer[self.search_len] = char;
                    self.search_len += 1;
                    try self.stdout().writeByte(char);
                }
            } else {
                // Use new edit_buf for insertion
                if (!self.edit_buf.insert(char)) return;

                // Update history prefix if in navigation mode
                if (self.history_index != -1) {
                    self.history_search_prefix_len = self.edit_buf.len;
                }

                // Update display (skip during paste mode - redraw at paste end)
                if (!self.paste_mode) {
                    try self.renderLine();
                }
            }
        },

        .backspace => {
            if (self.search_mode) {
                if (self.search_len > 0) {
                    self.search_len -= 1;
                    try self.stdout().writeAll("\x08 \x08");
                }
            } else {
                if (self.edit_buf.delete()) {
                    // Update history prefix if in navigation mode
                    if (self.history_index != -1) {
                        self.history_search_prefix_len = self.edit_buf.len;
                    }
                    try self.renderLine();
                }
            }
        },

        .delete => |delete_action| {
            switch (delete_action) {
                .char_under_cursor => {
                    if (self.edit_buf.deleteForward()) {
                        if (self.history_index != -1) {
                            self.history_search_prefix_len = self.edit_buf.len;
                        }
                        try self.renderLine();
                    }
                },
                .to_line_end => {
                    // Delete to end of line (D in vim)
                    const start = self.edit_buf.cursor;
                    self.edit_buf.moveLineEnd();
                    const end = self.edit_buf.cursor;
                    if (end > start) {
                        // yank to vim register
                        const len = end - start;
                        @memcpy(self.vi.yank_buf[0..len], self.edit_buf.text[start..end]);
                        self.vi.yank_len = @intCast(len);
                        // delete
                        self.edit_buf.cursor = start;
                        var i: usize = 0;
                        while (i < len) : (i += 1) _ = self.edit_buf.deleteForward();
                        if (self.history_index != -1) {
                            self.history_search_prefix_len = self.edit_buf.len;
                        }
                        try self.renderLine();
                    }
                },
                .char_at => |pos| {
                    if (pos < self.edit_buf.len) {
                        const old_cursor = self.edit_buf.cursor;
                        self.edit_buf.cursor = @intCast(pos);
                        _ = self.edit_buf.deleteForward();
                        self.edit_buf.cursor = if (old_cursor > pos) old_cursor - 1 else old_cursor;
                        if (self.history_index != -1) {
                            self.history_search_prefix_len = self.edit_buf.len;
                        }
                        try self.renderLine();
                    }
                },
            }
        },

        .execute_command => {
            if (self.search_mode) {
                // In search mode, treat enter as exit search
                try self.handleAction(.{ .exit_search_mode = true });
            } else {
                completion_mod.exitCompletionMode(self);

                const command = std.mem.trim(u8, self.edit_buf.slice(), " \t\n\r");

                // Check for line continuation (trailing backslash)
                if (command.len > 0 and command[command.len - 1] == '\\') {
                    // Check it's not an escaped backslash (\\)
                    const is_escaped = command.len >= 2 and command[command.len - 2] == '\\';
                    if (!is_escaped) {
                        // Line continuation - insert newline and continue editing
                        _ = self.edit_buf.insert('\n');
                        try self.stdout().writeByte('\n');
                        try self.stdout().writeAll("> ");
                        try self.stdout().flush();
                        return;
                    }
                }

                try self.stdout().writeByte('\n');
                try self.stdout().flush();

                if (command.len > 0) {
                    self.last_exit_code = try self.executeCommand(command);

                    // Add to history
                    if (self.history) |h| {
                        h.addCommand(command, self.last_exit_code) catch {};
                    }
                }

                // flush any command output before rendering new prompt
                try self.stdout().flush();

                self.clearCommand();
                self.history_index = -1;
                self.history_search_prefix_len = 0;
                self.vi.mode = .insert;
                self.vim_mode = .insert; // legacy compat
                self.term_view.finishLine();
                self.displayed_cmd_lines = 1;
                self.terminal_cursor_row = 0;
                try self.setCursorStyle(.bar);

                if (self.running)
                    try self.renderLine();
            }
        },

        .redraw_line => try self.renderLine(),

        .clear_screen => {
            try self.stdout().writeAll("\x1b[2J\x1b[H");
            try self.stdout().flush();
            self.term_view.finishLine();
            self.displayed_cmd_lines = 1;
            self.terminal_cursor_row = 0;
            try self.renderLine();
        },

        .vim_mode => |mode_action| {
            switch (mode_action) {
                .set_mode => |mode| {
                    self.vim_mode = mode;
                    self.vi.mode = if (mode == .normal) .normal else .insert;
                    if (mode == .normal) self.paste_mode = false;
                },
                .toggle_enabled => {
                    self.vim_mode_enabled = !self.vim_mode_enabled;
                },
                .toggle_mode => {
                    self.vim_mode = if (self.vim_mode == .normal) .insert else .normal;
                    self.vi.mode = if (self.vim_mode == .normal) .normal else .insert;
                    if (self.vim_mode == .normal) self.paste_mode = false;
                },
                .enter_visual => |vtype| {
                    self.vi.mode = if (vtype == .line) .visual_line else .visual;
                    self.vi.visual_start = self.edit_buf.cursor;
                },
            }
            // update cursor style to match vim mode
            const cursor = if (self.vim_mode_enabled and self.vim_mode == .normal)
                CursorStyle.block
            else
                CursorStyle.bar;
            try self.setCursorStyle(cursor);
            // force redraw - prompt changed even if text didn't
            self.term_view.last_hash = 0xDEADBEEF;
            return self.renderLine();
        },

        .tap_complete => {
            if (self.completion_mode) {
                try completion_mod.handleCompletionCycle(self,.forward);
            } else {
                try completion_mod.handleTabCompletion(self);
            }
        },

        .cycle_complete => |direction| {
            if (self.completion_mode) {
                try completion_mod.handleCompletionCycle(self,direction);
            } else {
                try completion_mod.handleTabCompletion(self);
            }
        },

        .move_cursor => |move| {
            try self.handleCursorMovement(move);
        },

        .history_nav => |direction| {
            try self.handleHistoryNavigation(direction);
        },

        .enter_search_mode => |direction| {
            self.search_mode = true;
            self.search_len = 0;
            const search_char: u8 = if (direction == .forward) '/' else '?';
            try self.stdout().writeByte(search_char);
        },

        .exit_search_mode => |execute| {
            self.search_mode = false;

            if (execute and self.search_len > 0 and self.history != null) {
                const search_term = self.search_buffer[0..self.search_len];
                const matches = self.history.?.fuzzySearch(search_term, self.allocator) catch {
                    try self.renderLine();
                    return;
                };
                defer self.allocator.free(matches);

                if (matches.len > 0) {
                    const entry_idx = matches[0].entry_index;
                    const entry = self.history.?.entries.items[entry_idx];
                    const cmd = self.history.?.getCommand(entry);
                    self.edit_buf.set(cmd);
                                    }
            }

            self.search_len = 0;
            try self.renderLine();
        },

        .yank => |yank_action| {
            switch (yank_action) {
                .line => {
                    // yank to vim register
                    const slice = self.edit_buf.slice();
                    @memcpy(self.vi.yank_buf[0..slice.len], slice);
                    self.vi.yank_len = @intCast(slice.len);
                },
                .selection => |sel| {
                    if (sel.end > sel.start and sel.end <= self.edit_buf.len) {
                        const len = sel.end - sel.start;
                        @memcpy(self.vi.yank_buf[0..len], self.edit_buf.text[sel.start..sel.end]);
                        self.vi.yank_len = @intCast(len);
                    }
                },
            }
        },

        .paste => |paste_action| {
            if (self.vi.yank_len == 0) return;

            // position cursor for paste
            if (paste_action == .after_cursor and self.edit_buf.cursor < self.edit_buf.len) {
                _ = self.edit_buf.moveRight();
            }

            // insert yanked text
            _ = self.edit_buf.insertSlice(self.vi.yank_buf[0..self.vi.yank_len]);
                        try self.renderLine();
        },

        .insert_at_position => |pos_type| {
            switch (pos_type) {
                .cursor => {},
                .after_cursor => _ = self.edit_buf.moveRight(),
                .line_start => self.edit_buf.moveLineStart(),
                .line_end => self.edit_buf.moveLineEnd(),
            }
            self.vi.mode = .insert;
            self.vim_mode = .insert;
            try self.setCursorStyle(.bar);
            try self.renderLine();
        },

        .open_line => |direction| {
            switch (direction) {
                .below => {
                    // o - open line below: go to end of line, insert newline
                    self.edit_buf.moveLineEnd();
                    _ = self.edit_buf.insert('\n');
                },
                .above => {
                    // O - open line above: go to start of line, insert newline, move back
                    self.edit_buf.moveLineStart();
                    _ = self.edit_buf.insert('\n');
                    _ = self.edit_buf.moveLeft();
                },
            }
            self.vi.mode = .insert;
            self.vim_mode = .insert;
            try self.setCursorStyle(.bar);
            try self.renderLine();
        },

        .undo => {
            self.clearCommand();
            try self.renderLine();
        },

        .enter_paste_mode => {
            self.paste_mode = true;
        },

        .exit_paste_mode => {
            self.paste_mode = false;
            try self.stdout().flush(); // sync before render
            try self.renderLine();
        },
    }
}

fn handleCursorMovement(self: *Shell, move_action: MoveCursorAction) !void {
    const old_pos = self.edit_buf.cursor;
    const max_pos = self.edit_buf.len;
    const cmd = self.edit_buf.slice();

    // Handle line up/down specially - may need history fallback
    switch (move_action) {
        .line_up => {
            // Check if buffer has newlines - if so, try line navigation first
            const has_newlines = std.mem.indexOfScalar(u8, cmd, '\n') != null;

            if (has_newlines) {
                // Check if we're on the first line (no newline before cursor)
                const on_first_line = std.mem.lastIndexOfScalar(u8, cmd[0..old_pos], '\n') == null;
                if (on_first_line) {
                    // Already on first line, fall back to history
                    self.vi.preferred_col_set = false; // reset preferred col on history nav
                    try self.handleHistoryNavigation(.up);
                    try self.renderLine();
                } else {
                    // Use vim's moveUp which tracks preferred column
                    self.vi.moveUp(&self.edit_buf);
                    try self.renderLine();
                }
            } else {
                // No newlines in buffer, just do history navigation
                self.vi.preferred_col_set = false;
                try self.handleHistoryNavigation(.up);
                try self.renderLine();
            }
            return;
        },
        .line_down => {
            // Check if buffer has newlines - if so, try line navigation first
            const has_newlines = std.mem.indexOfScalar(u8, cmd, '\n') != null;

            if (has_newlines) {
                // Check if we're on the last line (no newline after cursor)
                const on_last_line = std.mem.indexOfScalar(u8, cmd[old_pos..], '\n') == null;
                if (on_last_line) {
                    // Already on last line, fall back to history
                    self.vi.preferred_col_set = false;
                    try self.handleHistoryNavigation(.down);
                    try self.renderLine();
                } else {
                    // Use vim's moveDown which tracks preferred column
                    self.vi.moveDown(&self.edit_buf);
                    try self.renderLine();
                }
            } else {
                // No newlines in buffer, just do history navigation
                self.vi.preferred_col_set = false;
                try self.handleHistoryNavigation(.down);
                try self.renderLine();
            }
            return;
        },
        else => {},
    }

    // Horizontal movement resets preferred column for j/k navigation
    self.vi.preferred_col_set = false;

    // Calculate new position (clamped to valid range)
    const new_pos = switch (move_action) {
        .relative => |steps| blk: {
            const new = @as(isize, @intCast(self.edit_buf.cursor)) + steps;
            break :blk @as(usize, @intCast(@max(0, @min(new, @as(isize, @intCast(max_pos))))));
        },
        .absolute => |pos| @min(pos, max_pos),
        .to_line_start => self.findCurrentLineStart(cmd, old_pos),
        .to_line_end => self.findCurrentLineEnd(cmd, old_pos),
        .word_forward => |boundary| self.findWordForward(boundary),
        .word_backward => |boundary| self.findWordBackward(boundary),
        .line_up, .line_down => unreachable,
    };

    if (new_pos == old_pos) return;

    self.edit_buf.cursor = @intCast(new_pos);
    
    // For multiline content, use renderLine for proper positioning
    if (std.mem.indexOfScalar(u8, cmd, '\n') != null) {
        try self.stdout().flush(); // sync buffers before term_view render
        try self.renderLine();
    } else {
        const steps = if (new_pos > old_pos)
            new_pos - old_pos
        else
            old_pos - new_pos;

        if (new_pos > old_pos) {
            try self.stdout().print("\x1b[{d}C", .{steps});
        } else {
            try self.stdout().print("\x1b[{d}D", .{steps});
        }
    }
}

fn findLinePosition(self: *Shell, cmd: []const u8, pos: usize, going_up: bool) struct { found: bool, pos: usize } {
    _ = self;

    // Find current line start and column
    var line_start: usize = 0;
    var i: usize = 0;
    while (i < pos) : (i += 1) {
        if (cmd[i] == '\n') {
            line_start = i + 1;
        }
    }
    const col = pos - line_start;

    if (going_up) {
        // Find previous line
        if (line_start == 0) return .{ .found = false, .pos = 0 };

        // Find start of previous line
        var prev_line_start: usize = 0;
        if (line_start >= 2) {
            i = line_start - 2; // skip the newline before current line
            while (i > 0) : (i -= 1) {
                if (cmd[i] == '\n') {
                    prev_line_start = i + 1;
                    break;
                }
            }
        }

        // Find end of previous line
        const prev_line_end = line_start - 1;
        const prev_line_len = prev_line_end - prev_line_start;

        // Target position on previous line
        const target_col = @min(col, prev_line_len);
        return .{ .found = true, .pos = prev_line_start + target_col };
    } else {
        // Find next line
        var next_line_start: usize = 0;
        i = pos;
        while (i < cmd.len) : (i += 1) {
            if (cmd[i] == '\n') {
                next_line_start = i + 1;
                break;
            }
        }

        if (next_line_start == 0 or next_line_start >= cmd.len) {
            return .{ .found = false, .pos = 0 };
        }

        // Find end of next line
        var next_line_end = cmd.len;
        i = next_line_start;
        while (i < cmd.len) : (i += 1) {
            if (cmd[i] == '\n') {
                next_line_end = i;
                break;
            }
        }

        const next_line_len = next_line_end - next_line_start;
        const target_col = @min(col, next_line_len);
        return .{ .found = true, .pos = next_line_start + target_col };
    }
}

fn findCurrentLineStart(self: *Shell, cmd: []const u8, pos: usize) usize {
    _ = self;
    if (pos == 0) return 0;
    var i = pos - 1;
    while (i > 0) : (i -= 1) {
        if (cmd[i] == '\n') return i + 1;
    }
    if (cmd[0] == '\n') return 1;
    return 0;
}

fn findCurrentLineEnd(self: *Shell, cmd: []const u8, pos: usize) usize {
    _ = self;
    var i = pos;
    while (i < cmd.len) : (i += 1) {
        if (cmd[i] == '\n') return i;
    }
    return cmd.len;
}

fn findWordForward(self: *Shell, boundary: WordBoundary) usize {
    const buf = self.edit_buf.slice();
    var pos = self.edit_buf.cursor;
    const max = self.edit_buf.len;

    if (pos >= max) return max;

    return switch (boundary) {
        .word => blk: {
            // Skip current word (alphanumeric + underscore)
            while (pos < max and isWordChar(buf[pos])) : (pos += 1) {}
            // Skip whitespace
            while (pos < max and isWhitespace(buf[pos])) : (pos += 1) {}
            break :blk pos;
        },
        .WORD => blk: {
            // Skip non-whitespace
            while (pos < max and !isWhitespace(buf[pos])) : (pos += 1) {}
            // Skip whitespace
            while (pos < max and isWhitespace(buf[pos])) : (pos += 1) {}
            break :blk pos;
        },
        .word_end => blk: {
            // Move forward one if we're on the last char of a word
            if (pos < max and isWordChar(buf[pos]) and
                (pos + 1 >= max or !isWordChar(buf[pos + 1])))
            {
                pos += 1;
            }
            // Skip whitespace
            while (pos < max and isWhitespace(buf[pos])) : (pos += 1) {}
            // Move to end of word
            while (pos < max and isWordChar(buf[pos])) : (pos += 1) {}
            // Back up one to be ON the last character
            if (pos > self.edit_buf.cursor) pos -= 1;
            break :blk pos;
        },
        .WORD_end => blk: {
            // Move forward one if we're on the last char of a WORD
            if (pos < max and !isWhitespace(buf[pos]) and
                (pos + 1 >= max or isWhitespace(buf[pos + 1])))
            {
                pos += 1;
            }
            // Skip whitespace
            while (pos < max and isWhitespace(buf[pos])) : (pos += 1) {}
            // Move to end of WORD
            while (pos < max and !isWhitespace(buf[pos])) : (pos += 1) {}
            // Back up one to be ON the last character
            if (pos > self.edit_buf.cursor) pos -= 1;
            break :blk pos;
        },
    };
}

fn findWordBackward(self: *Shell, boundary: WordBoundary) usize {
    const buf = self.edit_buf.slice();
    if (self.edit_buf.cursor == 0) return 0;

    var pos = self.edit_buf.cursor - 1;

    return switch (boundary) {
        .word, .word_end => blk: {
            // Skip whitespace
            while (pos > 0 and isWhitespace(buf[pos])) : (pos -= 1) {}
            // Skip to beginning of word
            while (pos > 0 and isWordChar(buf[pos - 1])) : (pos -= 1) {}
            break :blk pos;
        },
        .WORD, .WORD_end => blk: {
            // Skip whitespace
            while (pos > 0 and isWhitespace(buf[pos])) : (pos -= 1) {}
            // Skip to beginning of WORD
            while (pos > 0 and !isWhitespace(buf[pos - 1])) : (pos -= 1) {}
            break :blk pos;
        },
    };
}

fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n';
}

fn readNextAction(self: *Shell) !Action {
    var temp_buf: [1]u8 = undefined;
    const count = try std.fs.File.stdin().read(temp_buf[0..]);
    const char = temp_buf[0];

    if (count == 0) return .none;

    // Always check for escape sequences (arrow keys, Ctrl+arrows, paste end, etc.)
    if (char == '\x1b') {
        return escapeSequenceAction();
    }

    // In paste mode (and insert mode), buffer content for editing
    // In normal mode, don't capture chars as input even if paste_mode is stuck
    if (self.paste_mode and (!self.vim_mode_enabled or self.vim_mode == .insert)) {
        if (char == CTRL_C) {
            self.paste_mode = false;
            return .cancel;
        }
        // Store newlines for multiline editing
        if (char == '\n' or char == '\r') {
            return .{ .input_char = '\n' };
        }
        if (char >= 32 and char <= 126) {
            return .{ .input_char = char };
        }
        return .none;
    }

    if (self.search_mode) {
        return self.getSearchModeAction(char);
    }

    // Check if vim mode is enabled
    if (self.vim_mode_enabled) {
        return switch (self.vim_mode) {
            .normal => normalModeAction(char),
            .insert => insertModeAction(char),
        };
    } else {
        return insertModeAction(char);
    }
}

fn insertModeAction(char: u8) Action {
    return switch (char) {
        '\n' => .execute_command,
        CTRL_C => .cancel,
        CTRL_T => .{ .vim_mode = .toggle_enabled },
        CTRL_L => .clear_screen,
        CTRL_D => .exit_shell,
        CTRL_B => .toggle_bookmark,
        '\t' => .tap_complete,
        8, 127 => .backspace,
        32...126 => .{ .input_char = char },
        else => .none,
    };
}

fn normalModeAction(char: u8) Action {
    return switch (char) {
        'h' => .{ .move_cursor = .{ .relative = -1 } },
        'l' => .{ .move_cursor = .{ .relative = 1 } },
        '0' => .{ .move_cursor = .to_line_start },
        '$' => .{ .move_cursor = .to_line_end },

        'w' => .{ .move_cursor = .{ .word_forward = .word } },
        'W' => .{ .move_cursor = .{ .word_forward = .WORD } },
        'b' => .{ .move_cursor = .{ .word_backward = .word } },
        'B' => .{ .move_cursor = .{ .word_backward = .WORD } },
        'e' => .{ .move_cursor = .{ .word_forward = .word_end } },
        'E' => .{ .move_cursor = .{ .word_forward = .WORD_end } },

        'j' => .{ .move_cursor = .line_down },
        'k' => .{ .move_cursor = .line_up },

        'i' => .{ .vim_mode = .{ .set_mode = .insert } },

        'a' => .{ .insert_at_position = .after_cursor },
        'A' => .{ .insert_at_position = .line_end },
        'I' => .{ .insert_at_position = .line_start },

        'o' => .{ .open_line = .below },
        'O' => .{ .open_line = .above },

        'x' => .{ .delete = .char_under_cursor },
        'D' => .{ .delete = .to_line_end },

        'p' => .{ .paste = .after_cursor },
        'P' => .{ .paste = .before_cursor },

        'y' => .{ .yank = .line },

        'u' => .undo,

        '/' => .{ .enter_search_mode = .forward },
        '?' => .{ .enter_search_mode = .backward },

        'v' => .{ .vim_mode = .{ .enter_visual = .char } },
        'V' => .{ .vim_mode = .{ .enter_visual = .line } },

        '\n' => .execute_command,

        CTRL_C => .cancel,
        CTRL_T => .{ .vim_mode = .toggle_enabled },

        else => .none,
    };
}

fn escapeSequenceAction() !Action {
    const stdin_fd = std.posix.STDIN_FILENO;
    var temp_buf: [2]u8 = undefined;

    // Set non-blocking temporarily via system call
    const F_GETFL = 3;
    const F_SETFL = 4;
    const O_NONBLOCK = 0x800;

    const flags_raw = std.posix.system.fcntl(stdin_fd, F_GETFL, @as(usize, 0));
    const flags: usize = if (@TypeOf(flags_raw) == c_int) @intCast(flags_raw) else flags_raw;
    _ = std.posix.system.fcntl(stdin_fd, F_SETFL, flags | O_NONBLOCK);
    defer _ = std.posix.system.fcntl(stdin_fd, F_SETFL, flags);

    // Try to read - if nothing there (EAGAIN), it's just ESC
    const result = std.posix.system.read(stdin_fd, &temp_buf, temp_buf.len);
    if (result <= 0) {
        return .{ .vim_mode = .{ .set_mode = .normal } };
    }
    const bytes_read: usize = @intCast(result);

    if (temp_buf[0] != '[') {
        return .{ .vim_mode = .{ .set_mode = .normal } };
    }

    // Need at least 2 bytes for a valid escape sequence
    // If incomplete, treat as just ESC (vim normal mode)
    if (bytes_read < 2) return .{ .vim_mode = .{ .set_mode = .normal } };

    const cmd_byte = temp_buf[1];

    return switch (cmd_byte) {
        'A' => .{ .history_nav = .up }, // Up arrow
        'B' => .{ .history_nav = .down }, // Down arrow
        'C' => .{ .move_cursor = .{ .relative = 1 } }, // Right arrow
        'D' => .{ .move_cursor = .{ .relative = -1 } }, // Left arrow
        'Z' => .{ .cycle_complete = .backward }, // Shift+Tab
        'H' => .{ .move_cursor = .to_line_start }, // Home key
        'F' => .{ .move_cursor = .to_line_end }, // End key
        '1' => try handleExtendedEscapeSequence(stdin_fd, flags), // Ctrl+arrows, Home, End
        '2' => try handleBracketedPaste(stdin_fd, flags), // Bracketed paste
        '3' => try readTildeSequence(stdin_fd, flags, .{ .delete = .char_under_cursor }), // Delete key
        '4' => try readTildeSequence(stdin_fd, flags, .{ .move_cursor = .to_line_end }), // End key
        '7' => try readTildeSequence(stdin_fd, flags, .{ .move_cursor = .to_line_start }), // Home key
        '8' => try readTildeSequence(stdin_fd, flags, .{ .move_cursor = .to_line_end }), // End key
        '?' => { consumeEscapeSequence(stdin_fd); return .none; }, // DA response, consume and ignore
        else => .none,
    };
}

/// consume remaining bytes of an escape sequence until terminator (letter or ~)
fn consumeEscapeSequence(stdin_fd: std.posix.fd_t) void {
    var buf: [1]u8 = undefined;
    while (true) {
        const n = std.posix.system.read(stdin_fd, &buf, 1);
        if (n <= 0) break;
        const c = buf[0];
        // escape sequences end with a letter or ~
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or c == '~') break;
    }
}

fn readTildeSequence(stdin_fd: std.posix.fd_t, flags: usize, action: Action) !Action {
    var buf: [1]u8 = undefined;
    const result = std.posix.system.read(stdin_fd, &buf, 1);
    if (result <= 0) return .none;
    if (buf[0] == '~') return action;
    _ = flags;
    return .none;
}

fn handleExtendedEscapeSequence(stdin_fd: std.posix.fd_t, flags: usize) !Action {
    var temp_buf: [1]u8 = undefined;
    _ = flags;

    // Read the next character (semicolon or tilde)
    var result = std.posix.system.read(stdin_fd, &temp_buf, 1);
    if (result <= 0) return .none;

    const semicolon = temp_buf[0];

    // handle ESC[1~ (Home key in some terminals)
    if (semicolon == '~') {
        return .{ .move_cursor = .to_line_start };
    }

    // expect semicolon for modified keys
    if (semicolon != ';') return .none;

    // read modifier (5 = Ctrl)
    result = std.posix.system.read(stdin_fd, &temp_buf, 1);
    if (result <= 0 or temp_buf[0] != '5') return .none;

    // read direction key
    result = std.posix.system.read(stdin_fd, &temp_buf, 1);
    if (result <= 0) return .none;

    return switch (temp_buf[0]) {
        'C' => .{ .move_cursor = .{ .word_forward = .WORD } },      // Ctrl+Right
        'D' => .{ .move_cursor = .{ .word_backward = .WORD } },     // Ctrl+Left
        'A' => .{ .move_cursor = .to_line_start },                   // Ctrl+Up
        'B' => .{ .move_cursor = .to_line_end },                     // Ctrl+Down
        'H' => .{ .move_cursor = .to_line_start },                   // Ctrl+Home
        'F' => .{ .move_cursor = .to_line_end },                     // Ctrl+End
        else => .none,
    };
}

fn handleBracketedPaste(stdin_fd: std.posix.fd_t, flags: usize) !Action {
    _ = flags;

    // Sequence is ESC[200~ or ESC[201~
    // We've already read ESC[2, now read the rest: '0', '0'/'1', '~'

    var buf: [3]u8 = undefined;
    const result = std.posix.system.read(stdin_fd, &buf, 3);
    if (result < 3) return .none;

    // First char should be '0'
    if (buf[0] != '0') return .none;
    // Third char should be '~'
    if (buf[2] != '~') return .none;

    // Check for '0~' (paste start: 200~) or '1~' (paste end: 201~)
    return switch (buf[1]) {
        '0' => .enter_paste_mode,
        '1' => .exit_paste_mode,
        else => .none,
    };
}

fn getSearchModeAction(self: *Shell, char: u8) Action {
    return switch (char) {
        '\n' => .{ .exit_search_mode = true },
        '\x1b' => .{ .exit_search_mode = false },
        8, 127 => blk: {
            if (self.search_len > 0) {
                break :blk .backspace;
            }
            break :blk .none;
        },
        32...126 => .{ .input_char = char },
        else => .none,
    };
}

pub fn enableRawMode(self: *Shell) !void {
    const stdin_fd = std.posix.STDIN_FILENO;

    // get current terminal attributes
    var termios = std.posix.tcgetattr(stdin_fd) catch return;

    // save original for restoration
    self.original_termios = termios;

    // modify terminal attributes for raw mode
    // disable canonical mode and echo
    termios.lflag.ICANON = false;
    termios.lflag.ECHO = false;
    termios.lflag.ISIG = false; // disable ctrl+c/ctrl+z signals

    // set minimum characters to read and timeout
    termios.cc[@intFromEnum(std.posix.V.MIN)] = 1; // read 1 char at a time
    termios.cc[@intFromEnum(std.posix.V.TIME)] = 0; // no timeout

    // apply the changes
    std.posix.tcsetattr(stdin_fd, .NOW, termios) catch return;

    // enable bracketed paste mode (write to stderr to avoid capture by redirects)
    _ = std.posix.write(std.posix.STDERR_FILENO, "\x1b[?2004h") catch {};
}

pub fn disableRawMode(self: *Shell) void {
    // disable bracketed paste mode (write to stderr to avoid capture by redirects)
    _ = std.posix.write(std.posix.STDERR_FILENO, "\x1b[?2004l") catch {};

    if (self.original_termios) |original| {
        const stdin_fd = std.posix.STDIN_FILENO;
        std.posix.tcsetattr(stdin_fd, .NOW, original) catch {};
    }
}

fn handleHistoryNavigation(self: *Shell, direction: HistoryDirection) !void {
    const h = self.history orelse return;

    switch (direction) {
        .up => {
            // Save current command if we're starting history navigation
            if (self.history_index == -1) {
                self.history_index = @intCast(h.entries.items.len);
                // Save prefix for prefix-based search
                self.history_search_prefix_len = self.edit_buf.len;
            }

            // Move up in history with optional prefix filtering
            if (self.history_index > 0) {
                if (self.history_search_prefix_len > 0) {
                    // Prefix search - find previous matching entry
                    const prefix = self.edit_buf.text[0..self.history_search_prefix_len];
                    var idx = self.history_index - 1;
                    while (idx >= 0) : (idx -= 1) {
                        const entry = h.entries.items[@intCast(idx)];
                        const cmd = h.getCommand(entry);
                        if (cmd.len >= prefix.len and std.mem.eql(u8, cmd[0..prefix.len], prefix)) {
                            self.history_index = idx;
                            try self.loadHistoryEntry(h);
                            break;
                        }
                        if (idx == 0) break;
                    }
                } else {
                    // No prefix - simple navigation
                    self.history_index -= 1;
                    try self.loadHistoryEntry(h);
                }
            }
        },
        .down => {
            // Can't go down if not in history navigation
            if (self.history_index == -1) return;

            if (self.history_search_prefix_len > 0) {
                // Prefix search - find next matching entry
                const prefix = self.edit_buf.text[0..self.history_search_prefix_len];
                var idx = self.history_index + 1;
                const max_idx: i32 = @intCast(h.entries.items.len);
                while (idx < max_idx) : (idx += 1) {
                    const entry = h.entries.items[@intCast(idx)];
                    const cmd = h.getCommand(entry);
                    if (cmd.len >= prefix.len and std.mem.eql(u8, cmd[0..prefix.len], prefix)) {
                        self.history_index = idx;
                        try self.loadHistoryEntry(h);
                        break;
                    }
                } else {
                    // No more matches - restore prefix
                    self.history_index = -1;
                    self.edit_buf.len = @intCast(self.history_search_prefix_len);
                    self.edit_buf.cursor = @intCast(self.history_search_prefix_len);
                                        self.history_search_prefix_len = 0;
                }
            } else {
                self.history_index += 1;

                // Reached the end - clear command (back to empty current line)
                if (self.history_index >= @as(i32, @intCast(h.entries.items.len))) {
                    self.history_index = -1;
                    self.clearCommand();
                } else {
                    try self.loadHistoryEntry(h);
                }
            }
        },
    }

    // Redraw the line with new content
    try self.renderLine();
}

fn loadHistoryEntry(self: *Shell, h: *hist.History) !void {
    const entry = h.entries.items[@intCast(self.history_index)];
    const history_cmd = h.getCommand(entry);

    // Set edit buffer to history command
    self.edit_buf.set(history_cmd);
    }

fn loadConfig(self: *Shell) !void {
    // get home directory
    const home = std.process.getEnvVarOwned(self.allocator, "HOME") catch return;
    defer self.allocator.free(home);

    // construct ~/.zishrc path
    const config_path = try std.fmt.allocPrint(self.allocator, "{s}/.zishrc", .{home});
    defer self.allocator.free(config_path);

    // check if file exists
    std.fs.cwd().access(config_path, .{}) catch return;

    // source the config file using the source builtin
    const source_cmd = try std.fmt.allocPrint(self.allocator, "source {s}", .{config_path});
    defer self.allocator.free(source_cmd);

    _ = self.executeCommand(source_cmd) catch {};
}

pub fn executeCommand(self: *Shell, command: []const u8) !u8 {
    const trimmed = std.mem.trim(u8, command, " \t\r\n");
    if (trimmed.len == 0) return 0;

    // TODO: alias expansion should be done at parse time for full script
    // for now just pass the full script to the parser
    const exit_code = try self.executeCommandInternal(trimmed);
    self.last_exit_code = exit_code;
    return exit_code;
}
/// Result of variable expansion - either borrowed (no alloc) or owned (needs free)
pub const ExpandResult = struct {
    slice: []const u8,
    owned: bool,

    pub fn deinit(self: ExpandResult, allocator: std.mem.Allocator) void {
        if (self.owned) {
            allocator.free(self.slice);
        }
    }
};

/// Expand variables without allocation when possible
// Expansion character lookup table - SectorLambda-inspired
const expansion_char_table: [256]bool = blk: {
    var table = [_]bool{false} ** 256;
    table['$'] = true;
    table['`'] = true;
    break :blk table;
};

pub fn expandVariablesZ(self: *Shell, input: []const u8) !ExpandResult {
    // Fast path: if no special chars, return slice directly (no alloc!)
    if (input.len > 0 and input[0] == '~') {
        // Tilde needs expansion
    } else {
        // Single pass check using lookup table
        var needs_expansion = false;
        for (input) |c| {
            if (expansion_char_table[c]) {
                needs_expansion = true;
                break;
            }
        }
        if (!needs_expansion) {
            return .{ .slice = input, .owned = false };
        }
    }

    // Need expansion - allocate
    const expanded = try self.expandVariablesAlloc(input);
    return .{ .slice = expanded, .owned = true };
}

pub fn expandVariables(self: *Shell, input: []const u8) ![]const u8 {
    // Legacy API - always returns owned slice for compatibility
    // Use lookup table for fast check
    if (input.len == 0 or input[0] != '~') {
        var needs_expansion = false;
        for (input) |c| {
            if (expansion_char_table[c]) {
                needs_expansion = true;
                break;
            }
        }
        if (!needs_expansion) {
            return try self.allocator.dupe(u8, input);
        }
    }

    return self.expandVariablesAlloc(input);
}

fn expandVariablesAlloc(self: *Shell, input: []const u8) ![]const u8 {

    // Simple variable expansion - replace $VAR with variable value
    var result = try std.ArrayList(u8).initCapacity(self.allocator, input.len);
    defer result.deinit(self.allocator);

    var i: usize = 0;

    // Tilde expansion at start of input
    if (input.len > 0 and input[0] == '~') {
        if (input.len == 1 or input[1] == '/') {
            const home = std.process.getEnvVarOwned(self.allocator, "HOME") catch "";
            defer if (home.len > 0) self.allocator.free(home);
            try result.appendSlice(self.allocator, home);
            i = 1; // skip the ~
        }
    }

    while (i < input.len) {
        if (input[i] == '$' and i + 1 < input.len) {
            // Found variable expansion
            i += 1; // skip $

            // Handle special single-character variables first
            if (i < input.len and input[i] == '?') {
                var exit_code_buf: [8]u8 = undefined;
                const exit_code_str = std.fmt.bufPrint(&exit_code_buf, "{d}", .{self.last_exit_code}) catch "0";
                try result.appendSlice(self.allocator, exit_code_str);
                i += 1; // consume the ?
                continue;
            }

            // Check for $((arithmetic)) first
            if (i + 1 < input.len and input[i] == '(' and input[i+1] == '(') {
                i += 2; // skip ((
                const expr_start = i;

                // Find matching ))
                var paren_count: u32 = 2;
                while (i < input.len and paren_count > 0) {
                    if (input[i] == '(') {
                        paren_count += 1;
                    } else if (input[i] == ')') {
                        paren_count -= 1;
                        if (paren_count == 0) break;
                    }
                    i += 1;
                }

                if (paren_count == 0) {
                    const expr = input[expr_start..i-1];
                    i += 1; // consume final ) (first one was consumed in loop)

                    // Evaluate arithmetic expression
                    const arith_result = try self.evaluateArithmetic(expr);
                    var buf: [32]u8 = undefined;
                    const result_str = std.fmt.bufPrint(&buf, "{d}", .{arith_result}) catch "0";
                    try result.appendSlice(self.allocator, result_str);
                    continue;
                }
            }

            // Handle command substitution $(command)
            if (i < input.len and input[i] == '(') {
                i += 1; // skip (
                const cmd_start = i;

                // Find matching closing paren
                var paren_count: u32 = 1;
                while (i < input.len and paren_count > 0) {
                    switch (input[i]) {
                        '(' => paren_count += 1,
                        ')' => paren_count -= 1,
                        else => {},
                    }
                    if (paren_count > 0) i += 1;
                }

                if (paren_count == 0) {
                    const command = input[cmd_start..i];
                    i += 1; // consume )

                    // Execute command and capture output
                    const cmd_output = self.executeCommandAndCapture(command) catch "";
                    try result.appendSlice(self.allocator, std.mem.trimRight(u8, cmd_output, "\n\r"));
                    continue;
                } else {
                    // Unmatched parens, treat as regular text
                    try result.append(self.allocator, '$');
                    try result.append(self.allocator, '(');
                    i = cmd_start;
                    continue;
                }
            }

            // Handle ${VAR} and ${VAR:-default} syntax
            if (i < input.len and input[i] == '{') {
                i += 1; // skip {

                // Check for ${#VAR} length expansion
                if (i < input.len and input[i] == '#') {
                    i += 1; // skip #
                    const name_start = i;
                    while (i < input.len and input[i] != '}') {
                        i += 1;
                    }
                    const var_name = input[name_start..i];
                    if (i < input.len and input[i] == '}') i += 1;

                    // Get variable value and compute length
                    var var_len: usize = 0;
                    if (self.variables.get(var_name)) |value| {
                        var_len = value.len;
                    } else if (std.process.getEnvVarOwned(self.allocator, var_name)) |val| {
                        var_len = val.len;
                        self.allocator.free(val);
                    } else |_| {}

                    var len_buf: [20]u8 = undefined;
                    const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{var_len}) catch "0";
                    try result.appendSlice(self.allocator, len_str);
                    continue;
                }

                const name_start = i;

                // Find end of variable name or modifier
                while (i < input.len and input[i] != '}' and input[i] != ':' and input[i] != '-' and input[i] != '+' and input[i] != '?') {
                    i += 1;
                }

                const var_name = input[name_start..i];

                // Check for modifier
                var modifier: u8 = 0;
                var has_colon = false;
                var default_value: []const u8 = "";

                if (i < input.len and input[i] == ':') {
                    has_colon = true;
                    i += 1;
                }

                if (i < input.len and (input[i] == '-' or input[i] == '+' or input[i] == '?')) {
                    modifier = input[i];
                    i += 1;

                    // Find the default/alternate value up to closing }
                    const val_start = i;
                    var brace_depth: u32 = 1;
                    while (i < input.len and brace_depth > 0) {
                        if (input[i] == '{') brace_depth += 1;
                        if (input[i] == '}') brace_depth -= 1;
                        if (brace_depth > 0) i += 1;
                    }
                    default_value = input[val_start..i];
                }

                // Skip closing }
                if (i < input.len and input[i] == '}') i += 1;

                // Look up variable value
                var var_value: ?[]const u8 = null;
                var owned_value: ?[]const u8 = null;
                defer if (owned_value) |v| self.allocator.free(v);

                if (self.variables.get(var_name)) |value| {
                    var_value = value;
                } else {
                    const env_value = std.process.getEnvVarOwned(self.allocator, var_name) catch null;
                    if (env_value) |val| {
                        owned_value = val;
                        var_value = val;
                    }
                }

                // Apply modifier
                const is_set = var_value != null;
                const is_empty = if (var_value) |v| v.len == 0 else true;
                const use_default = if (has_colon) !is_set or is_empty else !is_set;

                switch (modifier) {
                    '-' => {
                        // ${VAR:-default} or ${VAR-default}
                        if (use_default) {
                            // Recursively expand the default value
                            const expanded_default = try self.expandVariablesAlloc(default_value);
                            defer self.allocator.free(expanded_default);
                            try result.appendSlice(self.allocator, expanded_default);
                        } else if (var_value) |v| {
                            try result.appendSlice(self.allocator, v);
                        }
                    },
                    '+' => {
                        // ${VAR:+alternate} or ${VAR+alternate}
                        if (!use_default) {
                            const expanded_alt = try self.expandVariablesAlloc(default_value);
                            defer self.allocator.free(expanded_alt);
                            try result.appendSlice(self.allocator, expanded_alt);
                        }
                    },
                    '?' => {
                        // ${VAR:?error} or ${VAR?error}
                        if (use_default) {
                            try self.stdout().print("zish: {s}: {s}\n", .{ var_name, if (default_value.len > 0) default_value else "parameter not set" });
                            return error.ParameterNotSet;
                        } else if (var_value) |v| {
                            try result.appendSlice(self.allocator, v);
                        }
                    },
                    else => {
                        // No modifier, just ${VAR}
                        if (var_value) |v| {
                            try result.appendSlice(self.allocator, v);
                        }
                    },
                }
            } else {
                // Simple $VAR without braces
                const name_start = i;
                // Find end of variable name (alphanumeric + underscore)
                while (i < input.len and (std.ascii.isAlphanumeric(input[i]) or input[i] == '_')) {
                    i += 1;
                }

                if (i > name_start) {
                    const var_name = input[name_start..i];

                    // Look up variable
                    if (self.variables.get(var_name)) |value| {
                        try result.appendSlice(self.allocator, value);
                    } else {
                        // Try environment variable
                        const env_value = std.process.getEnvVarOwned(self.allocator, var_name) catch null;
                        if (env_value) |val| {
                            defer self.allocator.free(val);
                            try result.appendSlice(self.allocator, val);
                        }
                        // If no variable found, don't expand (leave empty)
                    }
                } else {
                    // Just a lone $, keep it
                    try result.append(self.allocator, '$');
                }
            }
        } else if (input[i] == '`') {
            // Handle backtick command substitution
            i += 1; // skip `
            const cmd_start = i;

            // Find matching closing backtick
            while (i < input.len and input[i] != '`') {
                i += 1;
            }

            if (i < input.len) {
                const command = input[cmd_start..i];
                i += 1; // consume closing `

                // Execute command and capture output
                const cmd_output = self.executeCommandAndCapture(command) catch "";
                try result.appendSlice(self.allocator, std.mem.trimRight(u8, cmd_output, "\n\r"));
            } else {
                // Unmatched backtick, treat as regular text
                try result.append(self.allocator, '`');
                i = cmd_start;
            }
        } else {
            try result.append(self.allocator, input[i]);
            i += 1;
        }
    }

    return try result.toOwnedSlice(self.allocator);
}

pub fn evaluateArithmetic(self: *Shell, expr: []const u8) !i64 {
    const trimmed = std.mem.trim(u8, expr, " \t\n\r");
    if (trimmed.len == 0) return 0;

    // SectorLambda-inspired: fast path for common simple expressions
    // Pattern: "var + num", "num + var", "var + var", "num OP num"
    if (tryFastArithmetic(trimmed, self)) |result| {
        return result;
    }

    // Slow path: recursive evaluation for complex expressions
    for ([_]u8{ '+', '-', '*', '/' }) |op| {
        if (std.mem.lastIndexOfScalar(u8, trimmed, op)) |op_pos| {
            if (op_pos > 0 and op_pos < trimmed.len - 1) {
                const left = try self.evaluateArithmetic(trimmed[0..op_pos]);
                const right = try self.evaluateArithmetic(trimmed[op_pos + 1 ..]);
                return switch (op) {
                    '+' => left + right,
                    '-' => left - right,
                    '*' => left * right,
                    '/' => if (right != 0) @divTrunc(left, right) else 0,
                    else => 0,
                };
            }
        }
    }

    // try to parse as number
    if (std.fmt.parseInt(i64, trimmed, 10)) |num| {
        return num;
    } else |_| {
        // try as variable
        if (self.variables.get(trimmed)) |val| {
            return std.fmt.parseInt(i64, val, 10) catch 0;
        }
        // unknown variable defaults to 0
        return 0;
    }
}

// Fast path for simple binary expressions - avoids recursion overhead
// Handles: "a + b", "1 + 2", "i + 1", etc.
fn tryFastArithmetic(expr: []const u8, shell: *Shell) ?i64 {
    // Find operator (only handle single operator case)
    var op_pos: ?usize = null;
    var op_char: u8 = 0;
    var op_count: usize = 0;

    for (expr, 0..) |c, i| {
        if (c == '+' or c == '-' or c == '*' or c == '/') {
            if (i > 0 and i < expr.len - 1) {
                op_count += 1;
                if (op_count > 1) return null; // Multiple operators - use slow path
                op_pos = i;
                op_char = c;
            }
        }
    }

    const pos = op_pos orelse return null;

    // Parse left operand
    const left_str = std.mem.trim(u8, expr[0..pos], " \t");
    const left = if (std.fmt.parseInt(i64, left_str, 10)) |n|
        n
    else |_| blk: {
        const val = shell.variables.get(left_str) orelse return null;
        break :blk std.fmt.parseInt(i64, val, 10) catch return null;
    };

    // Parse right operand
    const right_str = std.mem.trim(u8, expr[pos + 1 ..], " \t");
    const right = if (std.fmt.parseInt(i64, right_str, 10)) |n|
        n
    else |_| blk: {
        const val = shell.variables.get(right_str) orelse return null;
        break :blk std.fmt.parseInt(i64, val, 10) catch return null;
    };

    return switch (op_char) {
        '+' => left + right,
        '-' => left - right,
        '*' => left * right,
        '/' => if (right != 0) @divTrunc(left, right) else 0,
        else => null,
    };
}

fn executeCommandAndCapture(self: *Shell, command: []const u8) ![]const u8 {
    // Execute a command and capture its output
    const trimmed_cmd = std.mem.trim(u8, command, " \t\n\r");

    // Fast path for simple built-ins (no pipes/redirects)
    if (std.mem.indexOfAny(u8, trimmed_cmd, "|<>&;") == null) {
        // pwd builtin
        if (std.mem.eql(u8, trimmed_cmd, "pwd")) {
            var buf: [4096]u8 = undefined;
            const cwd = std.posix.getcwd(&buf) catch return self.allocator.dupe(u8, "");
            return self.allocator.dupe(u8, cwd);
        }

        // echo builtin - very common in command substitution
        if (std.mem.startsWith(u8, trimmed_cmd, "echo ") or std.mem.eql(u8, trimmed_cmd, "echo")) {
            const args = if (trimmed_cmd.len > 5) trimmed_cmd[5..] else "";
            // Handle -n flag
            if (std.mem.startsWith(u8, args, "-n ")) {
                return self.allocator.dupe(u8, args[3..]);
            } else if (std.mem.eql(u8, args, "-n")) {
                return self.allocator.dupe(u8, "");
            }
            // Normal echo - just return args with newline (no expansion needed for simple case)
            var result = try std.ArrayList(u8).initCapacity(self.allocator, args.len + 1);
            try result.appendSlice(self.allocator, args);
            try result.append(self.allocator, '\n');
            return result.toOwnedSlice(self.allocator);
        }

        // printf builtin - simple version
        if (std.mem.startsWith(u8, trimmed_cmd, "printf ")) {
            const args = trimmed_cmd[7..];
            return self.allocator.dupe(u8, args);
        }

        // true/false
        if (std.mem.eql(u8, trimmed_cmd, "true") or std.mem.eql(u8, trimmed_cmd, ":")) {
            return self.allocator.dupe(u8, "");
        }
        if (std.mem.eql(u8, trimmed_cmd, "false")) {
            return self.allocator.dupe(u8, "");
        }
    }

    // For all other commands (including pipelines), execute via shell
    return self.executeExternalAndCapture(trimmed_cmd) catch self.allocator.dupe(u8, "");
}

fn executeExternalAndCapture(self: *Shell, command: []const u8) ![]const u8 {
    // Execute external command and capture output
    const result = try std.process.Child.run(.{
        .allocator = self.allocator,
        .argv = &[_][]const u8{ "/bin/sh", "-c", command },
        .max_output_bytes = 4096,
    });
    defer self.allocator.free(result.stderr);

    return result.stdout; // caller owns this memory
}

fn executeCommandInternal(self: *Shell, command: []const u8) !u8 {
    var cmd_parser = parser.Parser.init(command, self.allocator) catch |err| {
        try self.stdout().print("zish: parse error: {}\n", .{err});
        return 1;
    };
    defer cmd_parser.deinit();

    const ast_root = cmd_parser.parse() catch |err| {
        try self.stdout().print("zish: parse error: {}\n", .{err});
        return 1;
    };

    return eval.evaluateAst(self, ast_root);
}

fn executeExternal(self: *Shell, command: []const u8) !u8 {
    // tokenize command
    var lex = try lexer.Lexer.init(command);
    var tokens = try std.ArrayList([]const u8).initCapacity(self.allocator, 16);
    defer {
        // free all allocated token strings
        for (tokens.items) |token_str| {
            self.allocator.free(token_str);
        }
        tokens.deinit(self.allocator);
    }

    while (true) {
        const token = try lex.nextToken();
        if (token.ty == .Eof) break;
        if (token.ty == .Word or token.ty == .String) {
            // allocate separate storage for each token to avoid buffer reuse issues
            const owned_token = try self.allocator.dupe(u8, token.value);
            try tokens.append(self.allocator, owned_token);
        }
    }

    if (tokens.items.len == 0) return 1;

    // prepare args for exec with glob expansion
    var args = try std.ArrayList([]const u8).initCapacity(self.allocator, tokens.items.len);
    defer {
        for (args.items) |arg| {
            // Only free if it was allocated by glob expansion (not in tokens)
            var is_original = false;
            for (tokens.items) |tok| {
                if (arg.ptr == tok.ptr) {
                    is_original = true;
                    break;
                }
            }
            if (!is_original) self.allocator.free(arg);
        }
        args.deinit(self.allocator);
    }

    for (tokens.items) |token_val| {
        // Check if this looks like a glob pattern
        const has_glob = for (token_val) |c| {
            if (c == '*' or c == '?' or c == '[') break true;
        } else false;

        if (has_glob) {
            // Expand glob pattern
            const glob_results = glob.expandGlob(self.allocator, token_val) catch {
                // If glob fails, use literal
                try args.append(self.allocator, token_val);
                continue;
            };
            defer self.allocator.free(glob_results);

            if (glob_results.len == 0) {
                // No matches, use literal pattern
                try args.append(self.allocator, token_val);
            } else {
                // Add all glob matches
                for (glob_results) |match| {
                    try args.append(self.allocator, match);
                }
            }
        } else {
            try args.append(self.allocator, token_val);
        }
    }

    // execute with PATH resolution
    // restore terminal to normal mode so child can handle signals properly
    const is_tty = std.posix.isatty(std.posix.STDIN_FILENO);
    if (is_tty) {
        self.disableRawMode();
    }
    defer if (is_tty) {
        self.enableRawMode() catch {};
    };

    var child = std.process.Child.init(args.items, self.allocator);
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.stdin_behavior = .Inherit;

    // inherit full environment from parent
    child.env_map = null; // null means inherit all from parent

    // spawn child first, THEN ignore SIGINT in parent
    // (child must not inherit SIG_IGN or it can't be interrupted)
    child.spawn() catch |err| switch (err) {
        error.FileNotFound => {
            try self.stdout().print("zish: {s}: command not found\n", .{args.items[0]});
            return 127;
        },
        else => return err,
    };

    // now ignore SIGINT in shell while child runs
    var old_sigint: std.posix.Sigaction = undefined;
    const ignore_action = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &ignore_action, &old_sigint);
    defer std.posix.sigaction(std.posix.SIG.INT, &old_sigint, null);

    const term = child.wait();
    return switch (term) {
        .Exited => |code| code,
        .Signal => |sig| @as(u8, @intCast(sig + 128)),
        .Stopped => |sig| @as(u8, @intCast(sig + 128)),
        .Unknown => |code| @as(u8, @intCast(code)),
    };
}
