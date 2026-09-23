// Must not compile: a Result used as its value, errno unread.
const sys = @import("sys");

export fn bug() usize {
    var b: [1]u8 = undefined;
    const n: usize = sys.read(0, &b);
    return n;
}
