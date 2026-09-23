// Must not compile: a syscall's result dropped. A Result is a value, so
// ignoring it is a compile error, and the errno cannot be lost silently.
const sys = @import("sys");

export fn bug() void {
    sys.write(2, "x");
}
