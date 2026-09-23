// Must not compile: a Held descriptor closed. What the C never closes is
// held until the process exits (ZIG.md, "The descriptor layer").
const fd = @import("fd");

export fn bug() void {
    const r = fd.openDir(fd.cwd, "/") catch return;
    const d = switch (r) {
        .ok => |d| d,
        .err => return,
    };
    const held = d.holdUntilExit();
    held.close();
}
