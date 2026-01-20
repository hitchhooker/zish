// lexer.zig - flat state machine lexer for zish
// Design: one loop, one switch, explicit state transitions

const std = @import("std");
const types = @import("types.zig");

pub const TokenType = enum {
    Word,
    String,              // quoted string content (for highlighting)
    DoubleQuotedString,  // double-quoted content

    // operators
    Pipe,           // |
    And,            // &&
    Or,             // ||
    Background,     // &
    Semicolon,      // ;
    DoubleSemi,     // ;;
    NewLine,        // \n

    // redirects
    RedirectInput,       // <
    RedirectOutput,      // >
    RedirectAppend,      // >>
    RedirectHereDoc,     // <<<
    RedirectHereDocLiteral, // <<
    RedirectStderr,      // 2>
    RedirectStderrAppend, // 2>>
    RedirectBoth,        // 2>&1
    RedirectToStderr,    // >&2
    RedirectAll,         // &>
    RedirectAllAppend,   // &>>

    // grouping
    LeftParen,      // (
    RightParen,     // )
    LeftBrace,      // {
    RightBrace,     // }
    TestOpen,       // [[
    TestClose,      // ]]

    // keywords
    If, Then, Else, Elif, Fi,
    For, While, Until, Do, Done, In,
    Case, Esac, Function,

    // special
    Dollar,
    ParameterExpansion,
    CommandSubstitution,
    ArithmeticExpansion,
    Eof,
};

pub const Token = struct {
    ty: TokenType,
    value: []const u8,
    line: u32,
    column: u32,

    pub const EMPTY = Token{ .ty = .Eof, .value = "", .line = 0, .column = 0 };
};

// All lexer states - explicit and visible
const State = enum {
    normal,
    word,
    // single quote
    sq,
    // double quote
    dq,
    dq_esc,
    dq_dollar,
    dq_dollar_brace,
    dq_dollar_paren,
    // unquoted dollar
    dollar,
    dollar_brace,
    dollar_paren,
    dollar_dparen,  // $((
    // backtick
    tick,
    tick_esc,
    // comment
    comment,
    // operators
    pipe,
    amp,
    gt,
    lt,
    lt_lt,
    // escape
    esc,
    // bracket
    lbracket,
    rbracket,
    // fd redirect (e.g., 2>)
    fd_num,
    // URL (e.g., https://example.com?a=1&b=2)
    url,
};

pub const Lexer = struct {
    input: []const u8,
    pos: usize,
    line: u32,
    column: u32,
    state: State,

    // token building
    token_start: usize,
    token_line: u32,
    token_col: u32,

    // double-buffering for token values (prevents overwrite when peeking)
    buf: [2][types.MAX_TOKEN_LENGTH]u8,
    buf_len: usize,
    buf_idx: u1,  // alternates between 0 and 1
    use_buf: bool,  // true if we're building into buffer

    // nesting counters
    paren_depth: u32,
    brace_depth: u32,

    const Self = @This();

    pub fn init(input: []const u8) !Self {
        try types.validateShellSafe(input);
        return Self{
            .input = input,
            .pos = 0,
            .line = 1,
            .column = 1,
            .state = .normal,
            .token_start = 0,
            .token_line = 1,
            .token_col = 1,
            .buf = undefined,
            .buf_len = 0,
            .buf_idx = 0,
            .use_buf = false,
            .paren_depth = 0,
            .brace_depth = 0,
        };
    }

    fn peek(self: *Self) ?u8 {
        return if (self.pos < self.input.len) self.input[self.pos] else null;
    }

    fn peekN(self: *Self, n: usize) ?u8 {
        const idx = self.pos + n;
        return if (idx < self.input.len) self.input[idx] else null;
    }

    fn advance(self: *Self) ?u8 {
        if (self.pos >= self.input.len) return null;
        const c = self.input[self.pos];
        self.pos += 1;
        if (c == '\n') {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        return c;
    }

    fn bufAppend(self: *Self, c: u8) void {
        if (self.buf_len < types.MAX_TOKEN_LENGTH) {
            self.buf[self.buf_idx][self.buf_len] = c;
            self.buf_len += 1;
        }
    }

    fn bufAppendSlice(self: *Self, s: []const u8) void {
        for (s) |c| self.bufAppend(c);
    }

    fn startToken(self: *Self) void {
        self.token_start = self.pos;
        self.token_line = self.line;
        self.token_col = self.column;
        self.buf_len = 0;
        self.use_buf = false;
        // alternate buffer for next token (double-buffering)
        self.buf_idx = 1 - self.buf_idx;
    }

    fn makeToken(self: *Self, ty: TokenType) Token {
        const value = if (self.use_buf)
            self.buf[self.buf_idx][0..self.buf_len]
        else
            self.input[self.token_start..self.pos];

        return Token{
            .ty = if (ty == .Word) classifyWord(value) else ty,
            .value = value,
            .line = self.token_line,
            .column = self.token_col,
        };
    }

    fn makeTokenValue(self: *Self, ty: TokenType, value: []const u8) Token {
        return Token{
            .ty = ty,
            .value = value,
            .line = self.token_line,
            .column = self.token_col,
        };
    }

    pub fn nextToken(self: *Self) !Token {
        while (true) {
            const c = self.peek();

            switch (self.state) {
                .normal => {
                    // skip whitespace (but not newlines)
                    if (c) |ch| {
                        if (ch == ' ' or ch == '\t') {
                            _ = self.advance();
                            continue;
                        }
                    }

                    if (c == null) {
                        return Token.EMPTY;
                    }

                    self.startToken();
                    const ch = c.?;

                    switch (ch) {
                        '#' => {
                            self.state = .comment;
                            _ = self.advance();
                        },
                        '\'' => {
                            _ = self.advance(); // skip opening quote
                            self.token_start = self.pos; // start AFTER quote
                            self.buf_len = 0;
                            self.use_buf = true;
                            self.state = .sq;
                        },
                        '"' => {
                            _ = self.advance(); // skip opening quote
                            self.token_start = self.pos; // start AFTER quote
                            self.buf_len = 0;
                            self.use_buf = true;
                            self.state = .dq;
                        },
                        '`' => {
                            self.state = .tick;
                            _ = self.advance();
                        },
                        '$' => {
                            self.state = .dollar;
                            _ = self.advance();
                        },
                        '\\' => {
                            self.state = .esc;
                            _ = self.advance();
                        },
                        '|' => {
                            _ = self.advance();
                            if (self.peek() == @as(u8, '|')) {
                                _ = self.advance();
                                return self.makeTokenValue(.Or, "||");
                            }
                            return self.makeTokenValue(.Pipe, "|");
                        },
                        '&' => {
                            _ = self.advance();
                            if (self.peek() == @as(u8, '&')) {
                                _ = self.advance();
                                return self.makeTokenValue(.And, "&&");
                            }
                            if (self.peek() == @as(u8, '>')) {
                                _ = self.advance(); // >
                                if (self.peek() == @as(u8, '>')) {
                                    _ = self.advance(); // second >
                                    return self.makeTokenValue(.RedirectAllAppend, "&>>");
                                }
                                return self.makeTokenValue(.RedirectAll, "&>");
                            }
                            return self.makeTokenValue(.Background, "&");
                        },
                        ';' => {
                            _ = self.advance();
                            if (self.peek() == @as(u8, ';')) {
                                _ = self.advance();
                                return self.makeTokenValue(.DoubleSemi, ";;");
                            }
                            return self.makeTokenValue(.Semicolon, ";");
                        },
                        '\n' => {
                            _ = self.advance();
                            return self.makeTokenValue(.NewLine, "\n");
                        },
                        '(' => {
                            _ = self.advance();
                            return self.makeTokenValue(.LeftParen, "(");
                        },
                        ')' => {
                            _ = self.advance();
                            return self.makeTokenValue(.RightParen, ")");
                        },
                        '{' => {
                            _ = self.advance();
                            return self.makeTokenValue(.LeftBrace, "{");
                        },
                        '}' => {
                            _ = self.advance();
                            return self.makeTokenValue(.RightBrace, "}");
                        },
                        '[' => {
                            _ = self.advance();
                            if (self.peek() == @as(u8, '[')) {
                                _ = self.advance();
                                return self.makeTokenValue(.TestOpen, "[[");
                            }
                            return self.makeTokenValue(.Word, "[");
                        },
                        ']' => {
                            _ = self.advance();
                            if (self.peek() == @as(u8, ']')) {
                                _ = self.advance();
                                return self.makeTokenValue(.TestClose, "]]");
                            }
                            return self.makeTokenValue(.Word, "]");
                        },
                        '>' => {
                            _ = self.advance();
                            if (self.peek() == @as(u8, '>')) {
                                _ = self.advance();
                                return self.makeTokenValue(.RedirectAppend, ">>");
                            }
                            if (self.peek() == @as(u8, '&')) {
                                if (self.peekN(1) == @as(u8, '2')) {
                                    _ = self.advance(); // &
                                    _ = self.advance(); // 2
                                    return self.makeTokenValue(.RedirectToStderr, ">&2");
                                }
                            }
                            return self.makeTokenValue(.RedirectOutput, ">");
                        },
                        '<' => {
                            _ = self.advance();
                            if (self.peek() == @as(u8, '<')) {
                                _ = self.advance();
                                if (self.peek() == @as(u8, '<')) {
                                    _ = self.advance();
                                    return self.makeTokenValue(.RedirectHereDoc, "<<<");
                                }
                                return self.makeTokenValue(.RedirectHereDocLiteral, "<<");
                            }
                            return self.makeTokenValue(.RedirectInput, "<");
                        },
                        '0'...'9' => {
                            // check for fd redirect like 2> or 2>>
                            if (self.peekN(1) == @as(u8, '>')) {
                                const fd = ch;
                                _ = self.advance(); // digit
                                _ = self.advance(); // first >
                                if (fd == '2') {
                                    // check for 2>&1
                                    if (self.peek() == @as(u8, '&') and self.peekN(1) == @as(u8, '1')) {
                                        _ = self.advance();
                                        _ = self.advance();
                                        return self.makeTokenValue(.RedirectBoth, "2>&1");
                                    }
                                    // check for 2>>
                                    if (self.peek() == @as(u8, '>')) {
                                        _ = self.advance();
                                        return self.makeTokenValue(.RedirectStderrAppend, "2>>");
                                    }
                                }
                                return self.makeTokenValue(.RedirectStderr, &[_]u8{fd});
                            }
                            self.state = .word;
                            _ = self.advance();
                        },
                        else => {
                            self.state = .word;
                            _ = self.advance();
                        },
                    }
                },

                .word => {
                    if (c == null or isOperator(c.?)) {
                        self.state = .normal;
                        return self.makeToken(.Word);
                    }

                    const ch = c.?;

                    // Check for URL pattern: if we see :// transition to URL mode
                    if (ch == ':' and self.peekN(1) == @as(u8, '/') and self.peekN(2) == @as(u8, '/')) {
                        self.switchToBuf();
                        self.bufAppend(':');
                        _ = self.advance();
                        self.bufAppend('/');
                        _ = self.advance();
                        self.bufAppend('/');
                        _ = self.advance();
                        self.state = .url;
                        continue;
                    }

                    switch (ch) {
                        // quotes continue the word
                        '\'' => {
                            self.switchToBuf();
                            self.state = .sq;
                            _ = self.advance();
                        },
                        '"' => {
                            self.switchToBuf();
                            self.state = .dq;
                            _ = self.advance();
                        },
                        '$' => {
                            self.switchToBuf();
                            self.bufAppend('$');
                            self.state = .dollar;
                            _ = self.advance();
                        },
                        '`' => {
                            self.switchToBuf();
                            self.bufAppend('`');
                            self.state = .tick;
                            _ = self.advance();
                        },
                        '\\' => {
                            self.switchToBuf();
                            self.state = .esc;
                            _ = self.advance();
                        },
                        else => {
                            if (self.use_buf) self.bufAppend(ch);
                            _ = self.advance();
                        },
                    }
                },

                .sq => {
                    // single quote: literal until closing '
                    if (c == null) return error.UnterminatedString;
                    const ch = c.?;
                    if (ch == '\'') {
                        _ = self.advance();
                        // check if word continues
                        if (self.peek()) |next| {
                            if (!isOperator(next)) {
                                self.state = .word;
                                continue;
                            }
                        }
                        self.state = .normal;
                        return self.makeToken(.String);
                    }
                    if (self.use_buf) self.bufAppend(ch);
                    _ = self.advance();
                },

                .dq => {
                    // double quote: process escapes and $
                    if (c == null) return error.UnterminatedString;
                    const ch = c.?;
                    switch (ch) {
                        '"' => {
                            _ = self.advance();
                            // check if word continues
                            if (self.peek()) |next| {
                                if (!isOperator(next)) {
                                    self.state = .word;
                                    continue;
                                }
                            }
                            self.state = .normal;
                            return self.makeToken(.DoubleQuotedString);
                        },
                        '\\' => {
                            self.state = .dq_esc;
                            _ = self.advance();
                        },
                        '$' => {
                            self.state = .dq_dollar;
                            self.bufAppend('$');
                            _ = self.advance();
                        },
                        else => {
                            if (self.use_buf) self.bufAppend(ch);
                            _ = self.advance();
                        },
                    }
                },

                .dq_esc => {
                    if (c == null) return error.UnterminatedString;
                    const ch = c.?;
                    // in double quotes: \$, \`, \", \\, \newline are special
                    const escaped = switch (ch) {
                        '$', '`', '"', '\\' => ch,
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        else => ch,
                    };
                    if (self.use_buf) self.bufAppend(escaped);
                    self.state = .dq;
                    _ = self.advance();
                },

                .dq_dollar => {
                    // inside double quote, saw $
                    if (c == null) {
                        self.state = .dq;
                        continue;
                    }
                    const ch = c.?;
                    switch (ch) {
                        '{' => {
                            self.bufAppend('{');
                            self.brace_depth = 1;
                            self.state = .dq_dollar_brace;
                            _ = self.advance();
                        },
                        '(' => {
                            self.bufAppend('(');
                            self.paren_depth = 1;
                            self.state = .dq_dollar_paren;
                            _ = self.advance();
                        },
                        'a'...'z', 'A'...'Z', '_', '?', '!', '#', '*', '@', '-', '0'...'9' => {
                            self.bufAppend(ch);
                            _ = self.advance();
                            // continue reading var name
                            while (self.peek()) |nc| {
                                if (std.ascii.isAlphanumeric(nc) or nc == '_') {
                                    self.bufAppend(nc);
                                    _ = self.advance();
                                } else break;
                            }
                            self.state = .dq;
                        },
                        else => self.state = .dq,
                    }
                },

                .dq_dollar_brace => {
                    if (c == null) return error.UnterminatedExpansion;
                    const ch = c.?;
                    self.bufAppend(ch);
                    if (ch == '{') self.brace_depth += 1;
                    if (ch == '}') {
                        self.brace_depth -= 1;
                        if (self.brace_depth == 0) self.state = .dq;
                    }
                    _ = self.advance();
                },

                .dq_dollar_paren => {
                    if (c == null) return error.UnterminatedExpansion;
                    const ch = c.?;
                    self.bufAppend(ch);
                    if (ch == '(') self.paren_depth += 1;
                    if (ch == ')') {
                        self.paren_depth -= 1;
                        if (self.paren_depth == 0) self.state = .dq;
                    }
                    _ = self.advance();
                },

                .dollar => {
                    // unquoted $
                    if (c == null) {
                        self.state = .normal;
                        return self.makeToken(.Word);
                    }
                    const ch = c.?;
                    switch (ch) {
                        '{' => {
                            self.bufAppend('{');
                            self.brace_depth = 1;
                            self.state = .dollar_brace;
                            _ = self.advance();
                        },
                        '(' => {
                            self.bufAppend('(');
                            if (self.peekN(1) == @as(u8, '(')) {
                                _ = self.advance();
                                self.bufAppend('(');
                                self.paren_depth = 2;
                                self.state = .dollar_dparen;
                            } else {
                                self.paren_depth = 1;
                                self.state = .dollar_paren;
                            }
                            _ = self.advance();
                        },
                        'a'...'z', 'A'...'Z', '_' => {
                            self.bufAppend(ch);
                            _ = self.advance();
                            while (self.peek()) |nc| {
                                if (std.ascii.isAlphanumeric(nc) or nc == '_') {
                                    self.bufAppend(nc);
                                    _ = self.advance();
                                } else break;
                            }
                            // check if word continues
                            if (self.peek()) |next| {
                                if (!isOperator(next)) {
                                    self.state = .word;
                                    continue;
                                }
                            }
                            self.state = .normal;
                            return self.makeToken(.Word);
                        },
                        '?', '!', '#', '$', '*', '@', '-', '0'...'9' => {
                            self.bufAppend(ch);
                            _ = self.advance();
                            if (self.peek()) |next| {
                                if (!isOperator(next)) {
                                    self.state = .word;
                                    continue;
                                }
                            }
                            self.state = .normal;
                            return self.makeToken(.Word);
                        },
                        else => {
                            // lone $
                            if (!isOperator(ch)) {
                                self.state = .word;
                            } else {
                                self.state = .normal;
                                return self.makeToken(.Word);
                            }
                        },
                    }
                },

                .dollar_brace => {
                    if (c == null) return error.UnterminatedExpansion;
                    const ch = c.?;
                    self.bufAppend(ch);
                    if (ch == '{') self.brace_depth += 1;
                    if (ch == '}') {
                        self.brace_depth -= 1;
                        if (self.brace_depth == 0) {
                            _ = self.advance();
                            if (self.peek()) |next| {
                                if (!isOperator(next)) {
                                    self.state = .word;
                                    continue;
                                }
                            }
                            self.state = .normal;
                            return self.makeToken(.Word);
                        }
                    }
                    _ = self.advance();
                },

                .dollar_paren => {
                    if (c == null) return error.UnterminatedExpansion;
                    const ch = c.?;
                    self.bufAppend(ch);
                    if (ch == '(') self.paren_depth += 1;
                    if (ch == ')') {
                        self.paren_depth -= 1;
                        if (self.paren_depth == 0) {
                            _ = self.advance();
                            if (self.peek()) |next| {
                                if (!isOperator(next)) {
                                    self.state = .word;
                                    continue;
                                }
                            }
                            self.state = .normal;
                            return self.makeToken(.Word);
                        }
                    }
                    _ = self.advance();
                },

                .dollar_dparen => {
                    // $(( arithmetic ))
                    if (c == null) return error.UnterminatedExpansion;
                    const ch = c.?;
                    self.bufAppend(ch);
                    if (ch == '(') self.paren_depth += 1;
                    if (ch == ')') {
                        self.paren_depth -= 1;
                        if (self.paren_depth == 0) {
                            _ = self.advance();
                            if (self.peek()) |next| {
                                if (!isOperator(next)) {
                                    self.state = .word;
                                    continue;
                                }
                            }
                            self.state = .normal;
                            return self.makeToken(.Word);
                        }
                    }
                    _ = self.advance();
                },

                .tick => {
                    if (c == null) return error.UnterminatedString;
                    const ch = c.?;
                    if (self.use_buf) self.bufAppend(ch);
                    if (ch == '`') {
                        _ = self.advance();
                        if (self.peek()) |next| {
                            if (!isOperator(next)) {
                                self.state = .word;
                                continue;
                            }
                        }
                        self.state = .normal;
                        return self.makeToken(.Word);
                    }
                    if (ch == '\\') {
                        self.state = .tick_esc;
                    }
                    _ = self.advance();
                },

                .tick_esc => {
                    if (c == null) return error.UnterminatedString;
                    if (self.use_buf) self.bufAppend(c.?);
                    self.state = .tick;
                    _ = self.advance();
                },

                .esc => {
                    // backslash escape
                    if (c == null) {
                        self.state = .normal;
                        return self.makeToken(.Word);
                    }
                    const ch = c.?;
                    if (ch == '\n') {
                        // line continuation - skip backslash-newline
                        _ = self.advance();
                        if (self.use_buf) {
                            // already building a token in buffer, continue in word mode
                            self.state = .word;
                        } else if (self.pos > self.token_start + 2) {
                            // had content before backslash, need to use buffer
                            // copy content without the backslash
                            const content = self.input[self.token_start .. self.pos - 2];
                            @memcpy(self.buf[self.buf_idx][0..content.len], content);
                            self.buf_len = content.len;
                            self.use_buf = true;
                            self.state = .word;
                        } else {
                            // backslash-newline at start, just skip and restart
                            self.state = .normal;
                        }
                    } else {
                        if (self.use_buf) self.bufAppend(ch);
                        self.state = .word;
                        _ = self.advance();
                    }
                },

                .comment => {
                    if (c == null or c.? == '\n') {
                        self.state = .normal;
                        // don't emit comment as token, just skip
                        continue;
                    }
                    _ = self.advance();
                },

                .url => {
                    // URL mode: allow &, ?, =, etc. until whitespace or shell-specific operators
                    if (c == null) {
                        self.state = .normal;
                        return self.makeToken(.Word);
                    }
                    const ch = c.?;
                    // End URL on whitespace or shell operators that wouldn't appear in URLs
                    if (ch == ' ' or ch == '\t' or ch == '\n' or ch == '|' or
                        ch == ';' or ch == '(' or ch == ')' or ch == '<' or
                        ch == '>' or ch == '`' or ch == '"' or ch == '\'')
                    {
                        self.state = .normal;
                        return self.makeToken(.Word);
                    }
                    // Allow all other chars including & ? = # etc.
                    self.bufAppend(ch);
                    _ = self.advance();
                },

                else => {
                    _ = self.advance();
                    self.state = .normal;
                },
            }
        }
    }

    fn switchToBuf(self: *Self) void {
        if (!self.use_buf) {
            // copy current token content to buffer
            const current = self.input[self.token_start..self.pos];
            @memcpy(self.buf[self.buf_idx][0..current.len], current);
            self.buf_len = current.len;
            self.use_buf = true;
        }
    }
};

// Operator check using lookup table - faster than switch for hot path
// Inspired by SectorLambda's minimal instruction approach
const operator_table: [256]bool = blk: {
    var table = [_]bool{false} ** 256;
    for ([_]u8{ ' ', '\t', '\n', '|', '&', ';', '(', ')', '<', '>', '{', '}' }) |c| {
        table[c] = true;
    }
    break :blk table;
};

inline fn isOperator(c: u8) bool {
    return operator_table[c];
}

// Fast keyword classification using length-based dispatch
// SectorLambda-inspired: minimize comparisons by filtering on length first
fn classifyWord(word: []const u8) TokenType {
    return switch (word.len) {
        2 => {
            if (word[0] == 'i') {
                if (word[1] == 'f') return .If;
                if (word[1] == 'n') return .In;
            }
            if (word[0] == 'd' and word[1] == 'o') return .Do;
            if (word[0] == 'f' and word[1] == 'i') return .Fi;
            return .Word;
        },
        3 => {
            if (word[0] == 'f' and word[1] == 'o' and word[2] == 'r') return .For;
            return .Word;
        },
        4 => {
            // Copy to aligned buffer for fast comparison
            var buf: [4]u8 align(4) = undefined;
            @memcpy(&buf, word[0..4]);
            const w = @as(*const u32, @ptrCast(&buf)).*;
            if (w == @as(u32, @bitCast([4]u8{ 't', 'h', 'e', 'n' }))) return .Then;
            if (w == @as(u32, @bitCast([4]u8{ 'e', 'l', 's', 'e' }))) return .Else;
            if (w == @as(u32, @bitCast([4]u8{ 'e', 'l', 'i', 'f' }))) return .Elif;
            if (w == @as(u32, @bitCast([4]u8{ 'c', 'a', 's', 'e' }))) return .Case;
            if (w == @as(u32, @bitCast([4]u8{ 'e', 's', 'a', 'c' }))) return .Esac;
            if (w == @as(u32, @bitCast([4]u8{ 'd', 'o', 'n', 'e' }))) return .Done;
            return .Word;
        },
        5 => {
            // First 4 chars comparison + check 5th
            var buf: [4]u8 align(4) = undefined;
            @memcpy(&buf, word[0..4]);
            const w4 = @as(*const u32, @ptrCast(&buf)).*;
            if (w4 == @as(u32, @bitCast([4]u8{ 'w', 'h', 'i', 'l' })) and word[4] == 'e') return .While;
            if (w4 == @as(u32, @bitCast([4]u8{ 'u', 'n', 't', 'i' })) and word[4] == 'l') return .Until;
            return .Word;
        },
        8 => {
            // Check first char quickly, then do full comparison
            if (word[0] == 'f') {
                var buf: [8]u8 align(4) = undefined;
                @memcpy(&buf, word[0..8]);
                const w1 = @as(*const u32, @ptrCast(&buf)).*;
                const w2 = @as(*const u32, @ptrCast(buf[4..8])).*;
                if (w1 == @as(u32, @bitCast([4]u8{ 'f', 'u', 'n', 'c' })) and
                    w2 == @as(u32, @bitCast([4]u8{ 't', 'i', 'o', 'n' }))) return .Function;
            }
            return .Word;
        },
        else => .Word,
    };
}
