// Must not compile: a network namespace's descriptor entered as a mount
// namespace (ZIG.md, "Lint and analysis": netns to an mntns setns).
const fd = @import("fd");

export fn bug() void {
    const net: fd.Fd(.netns) = undefined;
    _ = net.setns(.mnt);
}
