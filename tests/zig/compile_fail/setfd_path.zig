// Must not compile: an O_PATH descriptor handed to FSCONFIG_SET_FD, whose
// fget refuses it; an overlay's layers are directories (flong-mount.c:221,
// 226-228).
const fd = @import("fd");

export fn bug() void {
    const ctx: fd.Fd(.fsctx) = undefined;
    const lower: fd.Fd(.path) = undefined;
    _ = ctx.setFd("lowerdir+", lower);
}
