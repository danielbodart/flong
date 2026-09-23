// Must not compile: a message whose format names more values than it is
// given, which would otherwise print garbage or a wrong message.
const msg = @import("msg");

export fn bug() void {
    msg.say("line {d}: {s}", .{@as(u32, 1)});
}
