// history.zig - Secure, high-performance history implementation
// Security-focused design with DoS protection and memory safety

const std = @import("std");
const types = @import("types.zig");
const crypto_mod = @import("crypto.zig");
const log_mod = @import("history_log.zig");

const CryptoContext = crypto_mod.CryptoContext;
const LogWriter = log_mod.LogWriter;
const LogReader = log_mod.LogReader;

// Security constants - prevent DoS attacks
const MAX_COMMAND_LENGTH = types.MAX_COMMAND_LENGTH; // Use consistent limit from types
const MAX_HISTORY_ENTRIES = 10000; // Hard limit to prevent memory exhaustion
const DEFAULT_CAPACITY = 1000; // Default size
const STRING_POOL_SIZE = 256 * 1024; // 256KB string pool for cache efficiency

const HistoryEntry = struct {
    command_hash: u64, // For fast deduplication
    command_offset: u32, // Offset into string pool (cache-friendly)
    command_len: u16, // Command length
    frequency: u16, // Usage count for ranking
    timestamp: u32, // When command was last used
    exit_code: u8,
    flags: u8, // Success flag, etc.

    const SUCCESSFUL_FLAG: u8 = 1;

    pub fn isSuccessful(self: HistoryEntry) bool {
        return (self.flags & SUCCESSFUL_FLAG) != 0;
    }
};

pub const History = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(HistoryEntry),
    string_pool: []u8, // Contiguous string storage for cache efficiency
    string_pool_used: usize,
    hash_map: std.HashMap(u64, u32, std.hash_map.AutoContext(u64), 80), // For O(1) deduplication
    // encrypted persistence
    crypto: *CryptoContext,
    log_writer: LogWriter,
    dirty: bool, // needs save

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, _: ?[]const u8) !*Self {
        const history = try allocator.create(Self);
        errdefer allocator.destroy(history);

        // Pre-allocate for performance and predictable memory usage
        var entries = try std.ArrayList(HistoryEntry).initCapacity(allocator, DEFAULT_CAPACITY);
        errdefer entries.deinit(allocator);

        const string_pool = try allocator.alloc(u8, STRING_POOL_SIZE);
        errdefer allocator.free(string_pool);

        var hash_map = std.HashMap(u64, u32, std.hash_map.AutoContext(u64), 80).init(allocator);
        errdefer hash_map.deinit();
        try hash_map.ensureTotalCapacity(DEFAULT_CAPACITY);

        // init crypto (allocate on heap so pointer stays valid)
        const crypto = try allocator.create(CryptoContext);
        errdefer allocator.destroy(crypto);
        crypto.* = try CryptoContext.init(allocator);
        errdefer crypto.deinit();

        // init log writer
        var log_writer = try LogWriter.init(allocator, crypto);
        errdefer log_writer.deinit();

        history.* = .{
            .allocator = allocator,
            .entries = entries,
            .string_pool = string_pool,
            .string_pool_used = 0,
            .hash_map = hash_map,
            .crypto = crypto,
            .log_writer = log_writer,
            .dirty = false,
        };

        // load encrypted history from disk
        history.load() catch |err| {
            std.log.warn("failed to load encrypted history: {}", .{err});
        };

        return history;
    }

    pub fn deinit(self: *Self) void {
        // save any pending changes
        self.save() catch |err| {
            std.log.warn("failed to save history on exit: {}", .{err});
        };

        self.log_writer.deinit();
        self.crypto.deinit();
        self.allocator.destroy(self.crypto);
        self.hash_map.deinit();
        self.entries.deinit(self.allocator);
        self.allocator.free(self.string_pool);
        self.allocator.destroy(self);
    }

    pub fn addCommand(self: *Self, command: []const u8, exit_code: u8) !void {
        // Security: Input validation
        if (command.len == 0) return;
        if (command.len > MAX_COMMAND_LENGTH) return error.CommandTooLong;

        // Security: Sanitize command - remove control characters except tab/newline
        if (!isCommandSafe(command)) return error.UnsafeCommand;

        // Calculate hash for deduplication
        const command_hash = std.hash.Wyhash.hash(0, command);

        // Check if command already exists - move to end for recency
        if (self.hash_map.get(command_hash)) |existing_index| {
            var entry = self.entries.items[existing_index];
            entry.frequency = @min(65535, entry.frequency + 1);
            entry.timestamp = @intCast(std.time.timestamp());
            entry.exit_code = exit_code;
            entry.flags = if (exit_code == 0) HistoryEntry.SUCCESSFUL_FLAG else 0;

            // move to end: swap with last entry, then update in place
            const last_index: u32 = @intCast(self.entries.items.len - 1);
            if (existing_index != last_index) {
                // swap entries
                const last_entry = self.entries.items[last_index];
                self.entries.items[existing_index] = last_entry;
                self.entries.items[last_index] = entry;

                // update hash_map for swapped entry
                try self.hash_map.put(last_entry.command_hash, existing_index);
                try self.hash_map.put(command_hash, last_index);
            } else {
                // already at end, just update in place
                self.entries.items[last_index] = entry;
            }

            self.dirty = true;
            try self.saveEntry(entry);
            return;
        }

        // Security: Check limits to prevent DoS
        if (self.entries.items.len >= MAX_HISTORY_ENTRIES) {
            try self.evictOldestEntry();
        }

        // Check if we have space in string pool
        if (self.string_pool_used + command.len > self.string_pool.len) {
            // String pool full - compact or error
            return error.StringPoolFull;
        }

        // Store command in string pool for cache efficiency
        const command_offset: u32 = @intCast(self.string_pool_used);
        @memcpy(self.string_pool[self.string_pool_used..self.string_pool_used + command.len], command);
        self.string_pool_used += command.len;

        const entry = HistoryEntry{
            .command_hash = command_hash,
            .command_offset = command_offset,
            .command_len = @intCast(command.len),
            .frequency = 1,
            .timestamp = @intCast(std.time.timestamp()),
            .exit_code = exit_code,
            .flags = if (exit_code == 0) HistoryEntry.SUCCESSFUL_FLAG else 0,
        };

        const entry_index: u32 = @intCast(self.entries.items.len);
        try self.entries.append(self.allocator, entry);
        try self.hash_map.put(command_hash, entry_index);

        // mark dirty for save
        self.dirty = true;

        // save immediately (append-only, fast)
        try self.saveEntry(entry);
    }

    /// save single entry immediately (append-only)
    fn saveEntry(self: *Self, entry: HistoryEntry) !void {
        const command = self.getCommand(entry);

        const log_entry = log_mod.EntryData{
            .command_hash = entry.command_hash,
            .command = command,
            .exit_code = entry.exit_code,
            .flags = entry.flags,
            .frequency = entry.frequency,
        };

        try self.log_writer.append(log_entry);
        self.dirty = false; // just saved
    }

    // Security: Validate that command contains only safe characters
    fn isCommandSafe(command: []const u8) bool {
        for (command) |c| {
            switch (c) {
                // Allow printable ASCII, tab, and newline
                32...126, '\t', '\n' => {},
                else => return false, // Reject control characters
            }
        }
        return true;
    }

    fn evictOldestEntry(self: *Self) !void {
        if (self.entries.items.len == 0) return;

        // Find oldest entry (could be optimized with a min-heap)
        var oldest_index: usize = 0;
        var oldest_timestamp = self.entries.items[0].timestamp;

        for (self.entries.items, 0..) |entry, i| {
            if (entry.timestamp < oldest_timestamp) {
                oldest_timestamp = entry.timestamp;
                oldest_index = i;
            }
        }

        // Remove from hash map and entries
        const removed_entry = self.entries.orderedRemove(oldest_index);
        _ = self.hash_map.remove(removed_entry.command_hash);

        // Update indices in hash map (they shifted after removal)
        var iterator = self.hash_map.iterator();
        while (iterator.next()) |kv| {
            if (kv.value_ptr.* > oldest_index) {
                kv.value_ptr.* -= 1;
            }
        }
    }

    pub fn getStats(self: *Self) struct { total: usize, unique: usize } {
        return .{
            .total = self.entries.items.len,
            .unique = self.entries.items.len, // All entries are unique due to deduplication
        };
    }

    pub fn getCommand(self: *Self, entry: HistoryEntry) []const u8 {
        const start = entry.command_offset;
        const end = start + entry.command_len;
        return self.string_pool[start..end];
    }

    pub fn fuzzySearch(self: *Self, query: []const u8, allocator: std.mem.Allocator) ![]FuzzyMatch {
        // Security: Validate query
        if (query.len == 0 or query.len > MAX_COMMAND_LENGTH) {
            return try allocator.alloc(FuzzyMatch, 0);
        }
        if (!isCommandSafe(query)) {
            return try allocator.alloc(FuzzyMatch, 0);
        }

        var matches = try std.ArrayList(FuzzyMatch).initCapacity(allocator, 20);

        // Score-based matching with frequency and recency weighting
        for (self.entries.items, 0..) |entry, i| {
            const command = self.getCommand(entry);

            // Simple substring match (could be improved with fuzzy matching)
            if (std.mem.indexOf(u8, command, query)) |_| {
                // Calculate score based on multiple factors
                var score: f32 = 1.0;

                // Frequency bonus (commands used more often rank higher)
                score += @as(f32, @floatFromInt(entry.frequency)) * 0.1;

                // Recency bonus (recent commands rank higher)
                const now = @as(u32, @intCast(std.time.timestamp()));
                const age = now - entry.timestamp;
                if (age < 3600) {
                    score += 2.0; // Bonus for commands used in last hour
                } else if (age < 86400) {
                    score += 1.0; // Bonus for commands used today
                }

                // Success bonus (successful commands rank higher)
                if (entry.isSuccessful()) score += 0.5;

                // Exact match bonus
                if (std.mem.eql(u8, command, query)) score += 5.0;

                // Prefix match bonus
                if (std.mem.startsWith(u8, command, query)) score += 2.0;

                try matches.append(allocator, .{
                    .entry_index = @intCast(i),
                    .score = score,
                });
            }
        }

        // Sort by score (highest first)
        std.sort.insertion(FuzzyMatch, matches.items, {}, FuzzyMatch.compareByScore);

        // Limit results to top 10 for performance
        const result_count = @min(matches.items.len, 10);
        matches.shrinkRetainingCapacity(result_count);
        return try matches.toOwnedSlice(allocator);
    }

    /// save all entries to encrypted log
    pub fn save(self: *Self) !void {
        if (!self.dirty) return; // nothing to save

        // write all current entries
        for (self.entries.items) |entry| {
            const command = self.getCommand(entry);

            const log_entry = log_mod.EntryData{
                .command_hash = entry.command_hash,
                .command = command,
                .exit_code = entry.exit_code,
                .flags = entry.flags,
                .frequency = entry.frequency,
            };

            try self.log_writer.append(log_entry);
        }

        self.dirty = false;
    }

    /// load entries from encrypted log and merge with in-memory
    fn load(self: *Self) !void {
        var reader = try LogReader.init(self.allocator, self.crypto);
        defer reader.deinit();

        const entries = try reader.readAll();
        defer {
            for (entries) |entry| {
                self.allocator.free(entry.command);
            }
            self.allocator.free(entries);
        }

        // merge with in-memory entries (silently skip failures)
        for (entries) |entry| {
            self.mergeEntry(entry) catch {};
        }
    }

    /// re-encrypt all history with a new key
    pub fn reEncryptWithKey(self: *Self, new_key: [32]u8) !void {
        const fs = std.fs;

        // update crypto context with new key
        self.crypto.key = new_key;

        // get log file path
        const log_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/current.log.enc",
            .{self.log_writer.log_dir},
        );
        defer self.allocator.free(log_path);

        // delete old encrypted log
        fs.deleteFileAbsolute(log_path) catch |err| {
            if (err != error.FileNotFound) return err;
        };

        // reset sequence counter
        self.log_writer.sequence = 0;

        // re-save all entries with new key
        for (self.entries.items) |entry| {
            try self.saveEntry(entry);
        }
    }

    /// merge single entry from disk into memory
    pub fn mergeEntry(self: *Self, disk_entry: log_mod.EntryData) !void {
        // check if exists in memory
        if (self.hash_map.get(disk_entry.command_hash)) |existing_index| {
            // merge: higher frequency + newer timestamp wins, move to end for recency
            var memory_entry = self.entries.items[existing_index];

            memory_entry.frequency = @max(memory_entry.frequency, disk_entry.frequency);
            memory_entry.timestamp = @intCast(std.time.timestamp()); // use current time for recency
            memory_entry.flags |= disk_entry.flags;
            memory_entry.exit_code = disk_entry.exit_code;

            // move to end for recency (same logic as addCommand)
            const last_index: u32 = @intCast(self.entries.items.len - 1);
            if (existing_index != last_index) {
                const last_entry = self.entries.items[last_index];
                self.entries.items[existing_index] = last_entry;
                self.entries.items[last_index] = memory_entry;

                try self.hash_map.put(last_entry.command_hash, existing_index);
                try self.hash_map.put(disk_entry.command_hash, last_index);
            } else {
                self.entries.items[last_index] = memory_entry;
            }
        } else {
            // add new entry from disk
            if (self.string_pool_used + disk_entry.command.len > self.string_pool.len) {
                return error.StringPoolFull;
            }

            const command_offset: u32 = @intCast(self.string_pool_used);
            @memcpy(
                self.string_pool[self.string_pool_used .. self.string_pool_used + disk_entry.command.len],
                disk_entry.command,
            );
            self.string_pool_used += disk_entry.command.len;

            const entry = HistoryEntry{
                .command_hash = disk_entry.command_hash,
                .command_offset = command_offset,
                .command_len = @intCast(disk_entry.command.len),
                .frequency = disk_entry.frequency,
                .timestamp = @intCast(std.time.timestamp()),
                .exit_code = disk_entry.exit_code,
                .flags = disk_entry.flags,
            };

            const entry_index: u32 = @intCast(self.entries.items.len);
            try self.entries.append(self.allocator, entry);
            try self.hash_map.put(disk_entry.command_hash, entry_index);
        }
    }
};

pub const FuzzyMatch = struct {
    entry_index: u32,
    score: f32,

    pub fn compareByScore(_: void, a: FuzzyMatch, b: FuzzyMatch) bool {
        return a.score > b.score;
    }
};