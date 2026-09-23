// Must not compile: stdin, stdout or stderr closed. Descriptors 0-2 are
// not in the table and have no close.
const fd = @import("fd");

export fn bug() void {
    fd.Stdio.out.close();
}
