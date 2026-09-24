//! bpfdump: a live process's seccomp filters, and what a stack of them does
//! (the Zig port's phase 6). tests/parity/bpfdump.c, line by line; every
//! subcommand, output format and exit status is the C's. The C was deleted
//! in phase 6 (b), and its line numbers here are those of b82b18c.
//!
//!   bpfdump dump PID PREFIX
//!       Writes every filter attached to PID as PREFIX.N.bpf, N = 0 the most
//!       recently attached, and prints the count. Needs CAP_SYS_ADMIN in the
//!       initial namespace, and a caller that is not itself filtered.
//!
//!   bpfdump eval [-k F.bpf]... F.bpf...
//!       Runs the stack of filters, with the kernel's precedence, over every
//!       syscall number 0..1023 of x86_64, x32 and i386 with all arguments 0,
//!       and prints one line each. Where that run read an argument, it sweeps
//!       them: every (slot, K) with and without bit 32 set, and every pair of
//!       slots with constants, for every constant K any program compares an
//!       argument with. A sweep prints a line only where the result differs
//!       from the all-zero one. A run that read no argument took a path no
//!       argument can change, so its line is the call's whole answer.
//!       -k adds a file's constants to the sweep without running it, so that
//!       two stacks evaluated apart are swept with the same values and their
//!       output can be compared line for line.
//!
//! The output is sorted and diffable. The interpreter covers the classic BPF
//! libseccomp and systemd emit, and stops on anything else (bpfdump.c:1-23).
//! It is this file's own: std's BPF module names the classic opcodes with
//! eBPF's.
//!
//! It links libc, for libseccomp's syscall names (scmp.zig), and malloc
//! through std.heap.c_allocator; the calls are the kernel's through
//! std.os.linux, and strerror and strerrorname_np errno.zig's. stdout is
//! buffered and flushed at every exit, as stdio's is; stderr is not.
//!
//! Where the C's behaviour is undefined, on programs the kernel's checker
//! refuses (seccomp_check_filter: a load past seccomp_data or unaligned, a
//! scratch slot past 15), this one kills (a load, as the in-range check
//! does) or panics (a slot) instead of reading out of bounds.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys");
const errno = @import("errno");
const msg = @import("msg");
const scmp = @import("scmp");

pub const std_options: std.Options = .{
    .enable_segfault_handler = false,
    .keep_sigpipe = true,
};

pub const panic = std.debug.FullPanic(msg.onPanic(125));

const max_progs = 16;
const max_consts = 4096;

/// struct seccomp_data (linux/seccomp.h): what a filter loads from.
const Data = extern struct {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [6]u64,
};

comptime {
    std.debug.assert(@sizeOf(Data) == 64);
}

/// The first byte of seccomp_data's args: a load at or past it reads one
/// (bpfdump.c:44-45).
const args_offset = @offsetOf(Data, "args");

/// struct sock_filter (linux/filter.h), 8 bytes as the kernel hands it out.
const Insn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

comptime {
    std.debug.assert(@sizeOf(Insn) == 8);
}

/// The classic BPF opcodes (linux/bpf_common.h, linux/filter.h), whole,
/// as bpfdump.c:102-141 spells them.
const op = struct {
    // classes
    const ld = 0x00;
    const ldx = 0x01;
    const st = 0x02;
    const stx = 0x03;
    const alu = 0x04;
    const jmp = 0x05;
    const ret = 0x06;
    const misc = 0x07;
    // sizes and modes
    const w = 0x00;
    const imm = 0x00;
    const abs = 0x20;
    const mem = 0x60;
    const len = 0x80;
    // alu and jmp operations
    const add = 0x00;
    const sub = 0x10;
    const lsh = 0x60;
    const rsh = 0x70;
    const neg = 0x80;
    const and_ = 0x50;
    const or_ = 0x40;
    const ja = 0x00;
    const jeq = 0x10;
    const jgt = 0x20;
    const jge = 0x30;
    const jset = 0x40;
    // sources
    const k = 0x00;
    const x = 0x08;
    // ret's
    const a = 0x10;
    // misc's
    const tax = 0x00;
    const txa = 0x80;

    fn class(code: u16) u16 {
        return code & 0x07;
    }
    fn operation(code: u16) u16 {
        return code & 0xf0;
    }
    fn src(code: u16) u16 {
        return code & 0x08;
    }
};

/// The seccomp return actions (linux/seccomp.h).
const ret = struct {
    const kill_process: u32 = 0x80000000;
    const kill_thread: u32 = 0x00000000;
    const trap: u32 = 0x00030000;
    const errno_: u32 = 0x00050000;
    const user_notif: u32 = 0x7fc00000;
    const trace: u32 = 0x7ff00000;
    const log: u32 = 0x7ffc0000;
    const allow: u32 = 0x7fff0000;
    const action_full: u32 = 0xffff0000;
    const data: u32 = 0x0000ffff;
};

/// BPF_MEMWORDS (linux/filter.h).
const memwords = 16;

/// AUDIT_ARCH_X86_64 and AUDIT_ARCH_I386 (linux/audit.h).
const audit_arch_x86_64: u32 = 0xc000003e;
const audit_arch_i386: u32 = 0x40000003;

/// PTRACE_SEIZE, PTRACE_INTERRUPT, PTRACE_DETACH (linux/ptrace.h) and
/// PTRACE_SECCOMP_GET_FILTER (bpfdump.c:38-40).
const ptrace_seize = 0x4206;
const ptrace_interrupt = 0x4207;
const ptrace_detach = 17;
const ptrace_seccomp_get_filter = 0x420c;

/// __WALL (linux/wait.h).
const wall = 0x40000000;

// ---- stdout: buffered, flushed at exit, as stdio's is ----

var out_buf: [1 << 16]u8 = undefined;
var out: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &out_buf };

/// Writes what is buffered, then `data` (the last piece `splat` times). A
/// failed write is dropped, as stdio drops it; SIGPIPE, left at its
/// default, ends the process first.
fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    writeOut(w.buffer[0..w.end]);
    w.end = 0;
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |d| {
        writeOut(d);
        n += d.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| writeOut(last);
    return n + last.len * splat;
}

fn writeOut(bytes: []const u8) void {
    var rest = bytes;
    while (rest.len > 0) {
        switch (sys.write(1, rest)) {
            .ok => |n| rest = rest[n..],
            .err => return,
        }
    }
}

fn print(comptime fmt: []const u8, args: anytype) void {
    out.print(fmt, args) catch |err| switch (err) {
        error.WriteFailed => {}, // drain never fails
    };
}

/// exit(3): stdout flushed, then every thread ended.
fn exit(status: u8) noreturn {
    out.flush() catch |err| switch (err) {
        error.WriteFailed => {}, // drain never fails
    };
    sys.exitGroup(status);
}

/// perror(3): "WHAT: <strerror(e)>", or the text alone when WHAT is "".
fn perror(what: []const u8, e: sys.E) void {
    var buf: [errno.max_len]u8 = undefined;
    if (what.len == 0) return msg.bare("{s}", .{errno.describe(e, &buf)});
    msg.bare("{s}: {s}", .{ what, errno.describe(e, &buf) });
}

fn errOf(rc: usize) ?sys.E {
    return switch (linux.E.init(rc)) {
        .SUCCESS => null,
        else => |e| e,
    };
}

pub fn main() noreturn {
    msg.prog = "bpfdump";
    msg.mode = .whole;
    const argv = sys.argv();
    // bpfdump.c:322-330.
    if (argv.len == 4 and std.mem.eql(u8, std.mem.span(argv[1]), "dump"))
        exit(dump(atoi(std.mem.span(argv[2])), std.mem.span(argv[3])));
    if (argv.len >= 3 and std.mem.eql(u8, std.mem.span(argv[1]), "eval"))
        exit(eval(argv[2..]));
    msg.bare("usage: bpfdump dump PID PREFIX | eval [-k F.bpf]... F.bpf...", .{});
    exit(2);
}

/// atoi(3), which glibc makes (int) strtol(s, NULL, 10): blanks, a sign,
/// decimal digits; past a long's range the long's bound, then cut to an
/// int.
pub fn atoi(s: []const u8) i32 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or (s[i] >= '\t' and s[i] <= '\r'))) i += 1;
    var negative = false;
    if (i < s.len and (s[i] == '+' or s[i] == '-')) {
        negative = s[i] == '-';
        i += 1;
    }
    // The magnitude, saturating at 2^63, the most a negative long takes.
    var v: u64 = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
        const shifted = @mulWithOverflow(v, 10);
        const added = @addWithOverflow(shifted[0], s[i] - '0');
        v = if (shifted[1] != 0 or added[1] != 0) std.math.maxInt(u64) else added[0];
    }
    const long: i64 = if (negative)
        (if (v >= 1 << 63) std.math.minInt(i64) else -@as(i64, @intCast(v)))
    else
        (if (v > std.math.maxInt(i64)) std.math.maxInt(i64) else @intCast(v));
    return @truncate(long);
}

fn ptrace(req: usize, pid: i32, addr: usize, data: usize) usize {
    return linux.syscall4(.ptrace, req, @bitCast(@as(isize, pid)), addr, data);
}

/// bpfdump.c:47-93.
fn dump(pid: i32, prefix: []const u8) u8 {
    if (errOf(ptrace(ptrace_seize, pid, 0, 0))) |e| {
        perror("PTRACE_SEIZE", e);
        return 1;
    }
    if (errOf(ptrace(ptrace_interrupt, pid, 0, 0))) |e| {
        perror("PTRACE_INTERRUPT", e);
        return 1;
    }
    var status: u32 = 0;
    const waited = linux.wait4(pid, &status, wall, null);
    if (errOf(waited)) |e| {
        perror("waitpid", e);
        return 1;
    }
    if (waited != @as(usize, @bitCast(@as(isize, pid)))) {
        // waitpid returned another pid, and errno is what it was.
        perror("waitpid", .SUCCESS);
        return 1;
    }
    var n: i32 = 0;
    while (true) : (n += 1) {
        const rc = ptrace(ptrace_seccomp_get_filter, pid, @intCast(n), 0);
        if (errOf(rc)) |e| {
            if (e != .NOENT) {
                perror("PTRACE_SECCOMP_GET_FILTER", e);
                return 1;
            }
            break;
        }
        const len = rc;
        const f = std.heap.c_allocator.alloc(Insn, len) catch {
            perror("PTRACE_SECCOMP_GET_FILTER", .NOMEM);
            return 1;
        };
        @memset(f, std.mem.zeroes(Insn));
        const again = ptrace(ptrace_seccomp_get_filter, pid, @intCast(n), @intFromPtr(f.ptr));
        if (again != len) {
            perror("PTRACE_SECCOMP_GET_FILTER", errOf(again) orelse .SUCCESS);
            return 1;
        }
        // snprintf into 4096 bytes: cut at 4095.
        var path_buf: [4096]u8 = undefined;
        const path = cut(&path_buf, "{s}.{d}.bpf", .{ prefix, n });
        if (writeFile(path, std.mem.sliceAsBytes(f))) |e| {
            perror(path, e);
            return 1;
        }
        print("filter {d}: {d} instructions -> {s}\n", .{ n, len, path });
        std.heap.c_allocator.free(f);
    }
    _ = ptrace(ptrace_detach, pid, 0, 0);
    print("filters: {d}\n", .{n});
    return 0;
}

/// snprintf(buf, sizeof buf, fmt, ...): the text, cut to leave room for the
/// NUL, which is written after it.
fn cut(buf: *[4096]u8, comptime fmt: []const u8, args: anytype) [:0]const u8 {
    var w: std.Io.Writer = .fixed(buf[0 .. buf.len - 1]);
    w.print(fmt, args) catch |err| switch (err) {
        error.WriteFailed => {}, // a full buffer is the cut
    };
    buf[w.end] = 0;
    return buf[0..w.end :0];
}

/// fopen(path, "w"), fwrite, fclose: the errno of the first that failed.
fn writeFile(path: [*:0]const u8, bytes: []const u8) ?sys.E {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o666);
    if (errOf(rc)) |e| return e;
    const f: i32 = @intCast(rc);
    var rest = bytes;
    while (rest.len > 0) {
        switch (sys.write(f, rest)) {
            .ok => |n| rest = rest[n..],
            .err => |e| {
                _ = linux.close(f);
                return e;
            },
        }
    }
    return errOf(linux.close(f));
}

const Prog = struct {
    f: []const Insn,
};

/// One program over `d`, as the kernel runs it. `read` is set when it
/// loads an argument (bpfdump.c:95-145).
fn run(p: Prog, d: *const Data, read: *bool) u32 {
    var a: u32 = 0;
    var x: u32 = 0;
    var mem = [_]u32{0} ** memwords;
    const data = std.mem.asBytes(d);
    var pc: usize = 0;
    while (pc < p.f.len) : (pc += 1) {
        const i = p.f[pc];
        const k = i.k;
        switch (i.code) {
            op.ld | op.w | op.abs => {
                if (@as(u64, k) + 4 > @sizeOf(Data)) return ret.kill_process;
                if (k >= args_offset) read.* = true;
                a = std.mem.readInt(u32, data[k..][0..4], .little);
            },
            op.ld | op.w | op.len => a = @sizeOf(Data),
            op.ldx | op.w | op.len => x = @sizeOf(Data),
            op.ld | op.imm => a = k,
            op.ldx | op.imm => x = k,
            op.ld | op.mem => a = mem[k],
            op.ldx | op.mem => x = mem[k],
            op.st => mem[k] = a,
            op.stx => mem[k] = x,
            op.misc | op.tax => x = a,
            op.misc | op.txa => a = x,
            op.ret | op.k => return k,
            op.ret | op.a => return a,
            op.jmp | op.ja => pc +%= k,
            op.jmp | op.jeq | op.k => pc += if (a == k) i.jt else i.jf,
            op.jmp | op.jgt | op.k => pc += if (a > k) i.jt else i.jf,
            op.jmp | op.jge | op.k => pc += if (a >= k) i.jt else i.jf,
            op.jmp | op.jset | op.k => pc += if (a & k != 0) i.jt else i.jf,
            op.jmp | op.jeq | op.x => pc += if (a == x) i.jt else i.jf,
            op.jmp | op.jgt | op.x => pc += if (a > x) i.jt else i.jf,
            op.jmp | op.jge | op.x => pc += if (a >= x) i.jt else i.jf,
            op.jmp | op.jset | op.x => pc += if (a & x != 0) i.jt else i.jf,
            op.alu | op.add | op.k => a +%= k,
            op.alu | op.sub | op.k => a -%= k,
            op.alu | op.and_ | op.k => a &= k,
            op.alu | op.or_ | op.k => a |= k,
            // C's shift of a 32-bit value by 32 or more is undefined; x86's
            // shift takes the count modulo 32, as this does.
            op.alu | op.lsh | op.k => a <<= @truncate(k),
            op.alu | op.rsh | op.k => a >>= @truncate(k),
            op.alu | op.and_ | op.x => a &= x,
            op.alu | op.or_ | op.x => a |= x,
            op.alu | op.neg => a = 0 -% a,
            else => {
                msg.say("unsupported opcode 0x{x} at {d}", .{ i.code, pc });
                exit(3);
            },
        }
    }
    return ret.kill_process;
}

/// The stack's answer: every program runs, and the kernel keeps the lowest
/// action, compared as a signed value (bpfdump.c:147-160).
fn stack(ps: []const Prog, d: *const Data, read: *bool) u32 {
    var r: u32 = ret.allow;
    for (ps) |p| {
        const this = run(p, d, read);
        const a: i32 = @bitCast(this & ret.action_full);
        const b: i32 = @bitCast(r & ret.action_full);
        if (a < b) r = this;
    }
    return r;
}

/// An action's name (bpfdump.c:162-187): the action alone, ERRNO(NAME) with
/// strerrorname_np's name or the number, or the value in hex.
fn action(r: u32, buf: *[32]u8) []const u8 {
    const a = r & ret.action_full;
    const v = r & ret.data;
    return switch (a) {
        ret.allow => "ALLOW",
        ret.log => "LOG",
        ret.kill_process => "KILL_PROCESS",
        ret.kill_thread => "KILL_THREAD",
        ret.trap => "TRAP",
        ret.trace => "TRACE",
        ret.user_notif => "USER_NOTIF",
        ret.errno_ => if (errno.name(@enumFromInt(v))) |name|
            std.fmt.bufPrint(buf, "ERRNO({s})", .{name}) catch unreachable // proven: the longest name is 15 bytes
        else
            std.fmt.bufPrint(buf, "ERRNO({d})", .{v}) catch unreachable, // proven: 5 digits
        else => std.fmt.bufPrint(buf, "0x{x:0>8}", .{r}) catch unreachable, // proven: 10 bytes
    };
}

/// bpfdump.c:189-213: the file's instructions, or null having said why.
fn load(path: [*:0]const u8) ?Prog {
    const name = std.mem.span(path);
    // fopen(path, "r"), then fseek to the end and ftell.
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    if (errOf(rc)) |e| {
        perror(name, e);
        return null;
    }
    const f: i32 = @intCast(rc);
    // glibc's fseek(SEEK_END) takes a regular file's end from fstat's
    // st_size, and lseeks to the end only for anything else: a procfs file,
    // whose st_size is 0, is empty to it, where lseek would fail.
    var st: linux.Stat = undefined;
    const size: usize = if (errOf(linux.fstat(f, &st)) == null and linux.S.ISREG(st.mode))
        @intCast(st.size)
    else end: {
        const end = linux.lseek(f, 0, linux.SEEK.END);
        if (errOf(end)) |e| {
            perror(name, e);
            return null;
        }
        break :end end;
    };
    if (size == 0 or size % @sizeOf(Insn) != 0) {
        msg.say("{s} is not a BPF program", .{name});
        return null;
    }
    // rewind, then fread the whole of it.
    _ = linux.lseek(f, 0, linux.SEEK.SET);
    const insns = std.heap.c_allocator.alloc(Insn, size / @sizeOf(Insn)) catch {
        perror(name, .NOMEM);
        return null;
    };
    const bytes = std.mem.sliceAsBytes(insns);
    var got: usize = 0;
    while (got < bytes.len) {
        switch (sys.read(f, bytes[got..])) {
            .ok => |n| {
                if (n == 0) {
                    // Short: errno is whatever it was.
                    perror(name, .SUCCESS);
                    return null;
                }
                got += n;
            },
            .err => |e| {
                perror(name, e);
                return null;
            },
        }
    }
    _ = linux.close(f);
    return .{ .f = insns };
}

/// The constants `p` compares an argument with: those of a conditional
/// jump whose accumulator was last loaded from the arguments
/// (bpfdump.c:215-243).
fn constants(p: Prog, k: *[max_consts]u32, nk: *usize) void {
    var last: u32 = 0;
    for (p.f) |i| {
        const c = i.code;
        if (c == op.ld | op.w | op.abs) last = i.k;
        if (op.class(c) == op.jmp and op.src(c) == op.k and op.operation(c) != op.ja and last >= args_offset) {
            if (std.mem.indexOfScalar(u32, k[0..nk.*], i.k) == null) {
                if (nk.* == max_consts) {
                    msg.say("too many constants", .{});
                    exit(3);
                }
                k[nk.*] = i.k;
                nk.* += 1;
            }
        }
    }
}

const Arch = struct { name: []const u8, arch: u32, sarch: u32, bias: u32 };

const arches = [_]Arch{
    .{ .name = "x86_64", .arch = audit_arch_x86_64, .sarch = scmp.arch_x86_64, .bias = 0 },
    .{ .name = "x32", .arch = audit_arch_x86_64, .sarch = scmp.arch_x32, .bias = 0x40000000 },
    .{ .name = "i386", .arch = audit_arch_i386, .sarch = scmp.arch_x86, .bias = 0 },
};

var consts: [max_consts]u32 = undefined;

/// bpfdump.c:245-320.
fn eval(args: []const [*:0]const u8) u8 {
    var ps: [max_progs]Prog = undefined;
    var np: usize = 0;
    var nk: usize = 0;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, std.mem.span(args[i]), "-k")) {
            i += 1;
            if (i == args.len) return 2;
            const extra = load(args[i]) orelse return 2;
            constants(extra, &consts, &nk);
            std.heap.c_allocator.free(extra.f);
            continue;
        }
        if (np == max_progs) {
            msg.say("too many programs", .{});
            return 2;
        }
        ps[np] = load(args[i]) orelse return 2;
        constants(ps[np], &consts, &nk);
        np += 1;
    }
    if (np == 0) {
        msg.say("no program to evaluate", .{});
        return 2;
    }
    const progs = ps[0..np];
    const k = consts[0..nk];

    var b1: [32]u8 = undefined;
    var b2: [32]u8 = undefined;
    for (arches) |arch| {
        for (0..1024) |nr_| {
            const nr: u32 = @intCast(nr_);
            const d: Data = .{
                .nr = @bitCast(nr + arch.bias),
                .arch = arch.arch,
                .instruction_pointer = 0,
                .args = .{0} ** 6,
            };
            var read = false;
            var ignored = false;
            const base = stack(progs, &d, &read);
            const resolved = scmp.resolveNumArch(arch.sarch, @bitCast(nr + arch.bias));
            const name: []const u8 = if (resolved) |r| std.mem.span(r) else "-";

            print("{s} {d:>4} {s:<24} {s}\n", .{ arch.name, nr, name, action(base, &b1) });
            if (read) {
                for (0..6) |s| for (k) |kq| for (0..2) |hi| for (s..6) |t| {
                    const ws: usize = if (t == s) 1 else k.len;
                    for (0..ws) |w| {
                        var e = d;
                        e.args[s] = @as(u64, kq) | (if (hi != 0) @as(u64, 1) << 32 else 0);
                        if (t != s) e.args[t] = k[w];
                        const r = stack(progs, &e, &ignored);
                        if (r == base) continue;
                        print("{s} {d:>4} {s:<24} a{d}=0x{x}", .{ arch.name, nr, name, s, e.args[s] });
                        if (t != s) print(" a{d}=0x{x}", .{ t, e.args[t] });
                        print(" {s} (base {s})\n", .{ action(r, &b2), action(base, &b1) });
                    }
                };
            }
            scmp.freeName(resolved);
        }
    }
    return 0;
}
