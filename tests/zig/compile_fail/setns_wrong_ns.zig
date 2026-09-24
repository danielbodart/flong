// Must not compile: a network namespace's descriptor entered as a mount
// namespace (DESIGN.md, "Conventions": handles, not numbers).
const fd = @import("fd");

export fn bug() void {
    const net: fd.Fd(.netns) = undefined;
    _ = net.setns(.mnt);
}
