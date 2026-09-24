"""ptydrive: runs a launch on a terminal of its own and plays the caller.

    ptydrive SCENARIO [--stderr FILE] -- COMMAND...

The driver opens a pty pair, the "outer" terminal, and sets its window to
30x100. A stand-in for the caller's shell leads a new session with the outer
slave as its controlling terminal, and starts COMMAND as a job in the
terminal's foreground with the slave as stdin and stdout (and stderr, unless
--stderr names a file). The driver keeps the master, the caller's side, and a
descriptor on the slave, through which it reads and sets the terminal's modes
as the caller's shell would. COMMAND is expected to be a launcher and payload
that print "ready" once the payload runs; each scenario starts after it, and
first prints pid=, COMMAND's pid.

Each scenario prints KEY=VALUE lines, one per observation, for the test to
compare whole. Nothing here judges: a wait that does not end in time prints
what it saw and carries on, so a failing launcher shows as a wrong line and
never as a hang. The timeouts bound only a failure; nothing passes by one.

What the launcher writes to the terminal is read with the OSC 666 marks
(flong-tty.c:119-121, 156-165) and carriage returns taken out.

The scenarios:
  escape     ^]^]^] in one write, then waits for COMMAND's exit: status=
  keys       ^]^]x^] and a newline, the escape's control: status=
  resize     prints the payload's two "stty size" lines around a resize of
             the outer window to 40x120: size=
  watchdog   the descriptors of COMMAND's child named flong-ttyguard
             (guard=, see guard()), whether the outer terminal is raw
             (raw=), SIGKILLs COMMAND and waits for the modes to be the
             ones it started with: restored=
  sigcont    SIGSTOPs COMMAND, puts the starting modes back, SIGCONTs it and
             waits for raw modes (raw=), then a newline ends the payload
             (status=) and the modes are compared again (restored=)
  hangup     closes the master and waits for COMMAND's exit: status=
  output     a newline, then every line the payload printed until it
             exits (line=) and status=
  eio        a newline; the payload prints "bye", closes its terminal and
             says so in $PTYDRIVE_DIR/closed: closed=, then whether COMMAND
             sleeps (idle=, see asleep()), then SIGTERMs COMMAND: status=
  drain      stops the caller's terminal's output (TCOOFF), a newline; the
             payload prints numbered lines, writes its pid to
             $PTYDRIVE_DIR/done and exits; once it is a zombie (exited,
             not reaped) the output starts again (TCOON). The number lines
             seen while stopped (before=), all of them (lines=, last=),
             status=
  winch      puts the terminal in canonical mode and sends ^D, so
             COMMAND's stdin reads EOF; waits for $PTYDRIVE_DIR/hup, which
             the payload's SIGHUP trap makes (hup=), SIGWINCHes COMMAND,
             makes $PTYDRIVE_DIR/go: status=

Statuses are a shell's: the exit code, or 128 plus the signal. The driver's
own failure (no "ready") exits 2. COMMAND gets PTYDRIVE_DIR in its
environment: a directory of the driver's, for the files the scenarios and
payloads say things through, removed at the end.
"""

import fcntl
import os
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

# Bounds on a failure only (see above).
READY_WAIT = 120.0
WAIT = 30.0

MARK = re.compile(rb"\x1b\]666;[^\x1b]*\x1b\\")


class Outer:
    """The caller's terminal, with COMMAND started on it."""

    def __init__(self, argv, stderr=None, rows=30, cols=100):
        self.master, self.slave = os.openpty()
        self.set_size(rows, cols)
        # The caller's modes before the launch, as `stty -g` prints them.
        self.start_modes = self.stty()
        self.buf = b""
        self.status = None
        err = os.open(stderr, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600) if stderr else None
        report_r, report_w = os.pipe()
        # The shell lives until the driver does: this pipe's EOF.
        hold_r, self.hold = os.pipe()
        if os.fork() == 0:
            try:
                os.close(report_r)
                os.close(self.hold)
                self._shell(argv, err, report_w, hold_r)
            finally:
                os._exit(127)
        os.close(report_w)
        os.close(hold_r)
        if err is not None:
            os.close(err)
        self.report = report_r
        # COMMAND's pid, once it has the terminal's foreground.
        self.pid = int(self._report_line())

    def _shell(self, argv, err, report_w, hold_r):
        """The stand-in for the caller's shell: the session's leader, with
        the terminal as its controlling one. It starts COMMAND as a job in a
        process group of its own, gives that group the foreground, reports
        COMMAND's pid and then its status, and exits only when the driver
        does, as an interactive shell outlives its jobs: a leader's exit
        would send SIGHUP to the foreground group (disassociate_ctty), the
        watchdog's among others. It ignores SIGHUP and forwards nothing, so
        a hang-up of the terminal reaches COMMAND only as its input ending:
        the kernel signals the session's leader alone
        (tty_signal_session_leader)."""
        os.setsid()
        fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        go_r, go_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(go_w)
                os.setpgid(0, 0)
                # Started only once its group has the foreground, as a
                # shell's job is.
                os.read(go_r, 1)
                signal.signal(signal.SIGHUP, signal.SIG_DFL)
                os.dup2(self.slave, 0)
                os.dup2(self.slave, 1)
                os.dup2(err if err is not None else self.slave, 2)
                os.closerange(3, 1 << 16)
                os.execvp(argv[0], argv)
            finally:
                os._exit(127)
        os.close(go_r)
        try:
            os.setpgid(pid, pid)
        except PermissionError:
            # The job has made its group already.
            pass
        os.tcsetpgrp(self.slave, pid)
        os.write(go_w, b"g")
        os.close(go_w)
        for fd in (self.master, self.slave, err):
            if fd is not None:
                os.close(fd)
        os.write(report_w, f"{pid}\n".encode())
        _, st = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(st)
        os.write(report_w, f"{128 - code if code < 0 else code}\n".encode())
        os.read(hold_r, 1)
        os._exit(0)

    def _report_line(self):
        """A line from the shell, read a byte at a time so that nothing
        after it is taken; "" once the shell is gone."""
        line = b""
        while not line.endswith(b"\n"):
            c = os.read(self.report, 1)
            if not c:
                break
            line += c
        return line.decode().strip()

    def set_size(self, rows, cols):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def stty(self):
        """The terminal's modes, by stty -g on the slave."""
        return subprocess.run(["stty", "-g"], stdin=self.slave, capture_output=True,
                              check=True, text=True).stdout.strip()

    def raw(self):
        """Whether the modes are cfmakeraw's in the part a shell restores:
        no canonical input, no echo, no signal keys."""
        lflag = termios.tcgetattr(self.slave)[3]
        return lflag & (termios.ICANON | termios.ECHO | termios.ISIG) == 0

    def send(self, data):
        os.write(self.master, data)

    def read_some(self, timeout):
        """Reads what the terminal has within TIMEOUT. False at EOF or EIO,
        which is how a pty master says every slave is closed."""
        r, _, _ = select.select([self.master], [], [], timeout)
        if not r:
            return True
        try:
            data = os.read(self.master, 65536)
        except OSError:
            return False
        if not data:
            return False
        self.buf += data
        return True

    def text(self):
        return MARK.sub(b"", self.buf).replace(b"\r", b"").decode(errors="replace")

    def expect_line(self, line, timeout=READY_WAIT):
        """Waits for LINE, whole, on the terminal; everything up to it is
        consumed. Exits 2 when it does not come."""
        end = time.monotonic() + timeout
        while True:
            lines = self.text().split("\n")
            # The last element is a line still being written.
            if line in lines[:-1]:
                i = lines.index(line)
                self.buf = "\n".join(lines[i + 1:]).encode()
                return
            left = end - time.monotonic()
            if left <= 0 or not self.read_some(left):
                print(f"error=no {line!r} line; the terminal said {self.text()!r}", flush=True)
                self.kill()
                sys.exit(2)

    def wait(self, timeout=WAIT, drain=True):
        """COMMAND's status, or "none" when it has not exited in TIMEOUT.
        The master is read meanwhile, so output never blocks it."""
        end = time.monotonic() + timeout
        while self.status is None:
            if select.select([self.report], [], [], 0)[0]:
                self.status = self._report_line() or "gone"
                break
            left = end - time.monotonic()
            if left <= 0:
                return "none"
            if drain and self.master >= 0:
                if not self.read_some(min(left, 0.1)):
                    time.sleep(0.1)
            else:
                time.sleep(0.1)
        if drain and self.master >= 0:
            while self.read_some(0.2) and select.select([self.master], [], [], 0)[0]:
                pass
        return self.status

    def until(self, check, timeout=WAIT):
        """Whether CHECK holds within TIMEOUT, polled; the master is read
        meanwhile."""
        end = time.monotonic() + timeout
        while not check():
            if time.monotonic() >= end:
                return False
            if self.master >= 0:
                self.read_some(0.05)
            else:
                time.sleep(0.05)
        return True

    def kill(self):
        if self.status is None:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def close_master(self):
        os.close(self.master)
        self.master = -1


def stopped(pid):
    """Whether PID is in the stopped state, from /proc/PID/stat."""
    with open(f"/proc/{pid}/stat") as f:
        return f.read().rsplit(")", 1)[1].split()[0] == "T"


def state(pid):
    """PID's state letter, from /proc/PID/stat; "" once it is gone."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return ""


def asleep(pid, samples=10):
    """Whether PID is sleeping (S) at SAMPLES reads 50 ms apart, every one:
    a process blocked in poll is, and one spinning on a descriptor that
    stays ready never is."""
    for _ in range(samples):
        if state(pid) != "S":
            return False
        time.sleep(0.05)
    return True


def guard_pid(t):
    """The pid of COMMAND's child named flong-ttyguard, the watchdog
    (flong-tty.c:243-246), or None."""
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/stat") as f:
                comm, rest = f.read().split(" (", 1)[1].rsplit(") ", 1)
        except OSError:
            continue
        if comm == "flong-ttyguard" and int(rest.split()[1]) == t.pid:
            return pid
    return None


def guard(t):
    """The watchdog's descriptors: 0-2 by number, each "tty" when it is the
    outer terminal, then the kinds of the others, sorted, without their
    numbers, which are no part of what it keeps. It names itself after its
    descriptors are closed (flong-util.c:474, then flong-tty.c:246),
    so once it has the name the list is final. "none" when no child of
    COMMAND takes the name in time."""
    if not t.until(lambda: guard_pid(t) is not None):
        return "none"
    pid = guard_pid(t)
    tty = os.ttyname(t.slave)
    low, high = [], []
    for fd in sorted(os.listdir(f"/proc/{pid}/fd"), key=int):
        target = os.readlink(f"/proc/{pid}/fd/{fd}")
        if target == tty:
            kind = "tty"
        elif target.startswith("pipe:"):
            kind = "pipe"
        elif "pidfd" in target:
            kind = "pidfd"
        else:
            kind = target
        if int(fd) <= 2:
            low.append(f"{fd}:{kind}")
        else:
            high.append(kind)
    return " ".join(low + sorted(high))


def main():
    args = sys.argv[1:]
    stderr = None
    scenario = args.pop(0)
    if args[:1] == ["--stderr"]:
        stderr = args[1]
        args = args[2:]
    if args[:1] != ["--"] or len(args) < 2:
        sys.exit(__doc__.split("\n\n")[0])
    d = tempfile.mkdtemp(prefix="ptydrive-")
    os.chmod(d, 0o755)
    os.environ["PTYDRIVE_DIR"] = d
    try:
        run(scenario, args, stderr, d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def run(scenario, args, stderr, d):
    t = Outer(args[1:], stderr)
    t.expect_line("ready")
    print(f"pid={t.pid}", flush=True)

    if scenario == "escape":
        t.send(b"\x1d\x1d\x1d")
        print(f"status={t.wait()}")
    elif scenario == "keys":
        t.send(b"\x1d\x1dx\x1d\n")
        print(f"status={t.wait()}")
    elif scenario == "resize":
        t.expect_line("30 100")
        print("size=30 100")
        # The kernel sends SIGWINCH to the terminal's foreground group,
        # COMMAND's, before this returns; the newline comes after it.
        t.set_size(40, 120)
        t.send(b"\n")
        status = t.wait()
        for line in t.text().split("\n"):
            if re.fullmatch(r"\d+ \d+", line):
                print(f"size={line}")
        print(f"status={status}")
    elif scenario == "watchdog":
        print(f"guard={guard(t)}")
        print(f"raw={'yes' if t.raw() else 'no'}")
        os.kill(t.pid, signal.SIGKILL)
        print(f"status={t.wait()}")
        ok = t.until(lambda: t.stty() == t.start_modes)
        print(f"restored={'yes' if ok else 'no'}")
    elif scenario == "sigcont":
        print(f"raw={'yes' if t.raw() else 'no'}")
        os.kill(t.pid, signal.SIGSTOP)
        stop = t.until(lambda: stopped(t.pid))
        print(f"stopped={'yes' if stop else 'no'}")
        # The caller's shell, while its job is stopped, puts its own modes back.
        subprocess.run(["stty", t.start_modes], stdin=t.slave, check=True)
        print(f"raw={'yes' if t.raw() else 'no'}")
        os.kill(t.pid, signal.SIGCONT)
        print(f"raw={'yes' if t.until(t.raw) else 'no'}")
        t.send(b"\n")
        print(f"status={t.wait()}")
        print(f"restored={'yes' if t.stty() == t.start_modes else 'no'}")
    elif scenario == "hangup":
        t.close_master()
        print(f"status={t.wait()}")
    elif scenario == "output":
        t.send(b"\n")
        status = t.wait()
        for line in t.text().split("\n"):
            if line:
                print(f"line={line}")
        print(f"status={status}")
    elif scenario == "eio":
        t.send(b"\n")
        t.expect_line("bye", WAIT)
        closed = t.until(lambda: os.path.exists(f"{d}/closed"))
        print(f"closed={'yes' if closed else 'no'}")
        # Every slave closed: the master reports POLLHUP from here on, so a
        # relay still polling it would never sleep.
        print(f"idle={'yes' if t.until(lambda: asleep(t.pid)) else 'no'}")
        # And the launcher still forwards a signal to the leader.
        os.kill(t.pid, signal.SIGTERM)
        print(f"status={t.wait()}")
    elif scenario == "drain":
        termios.tcflow(t.slave, termios.TCOOFF)
        t.send(b"\n")
        done = f"{d}/done"
        t.until(lambda: os.path.exists(done) and os.path.getsize(done) > 0)
        with open(done) as f:
            payload = f.read().strip()
        t.until(lambda: state(payload) == "Z")
        before = [ln for ln in t.text().split("\n") if re.fullmatch(r"\d+", ln)]
        print(f"before={len(before)}")
        termios.tcflow(t.slave, termios.TCOON)
        status = t.wait()
        nums = [ln for ln in t.text().split("\n") if re.fullmatch(r"\d+", ln)]
        print(f"lines={len(nums)} last={nums[-1] if nums else 'none'}")
        print(f"status={status}")
    elif scenario == "winch":
        subprocess.run(["stty", "icanon"], stdin=t.slave, check=True)
        t.send(b"\x04")
        hup = t.until(lambda: os.path.exists(f"{d}/hup"))
        print(f"hup={'yes' if hup else 'no'}")
        os.kill(t.pid, signal.SIGWINCH)
        open(f"{d}/go", "w").close()
        print(f"status={t.wait()}")
    else:
        sys.exit(f"ptydrive: no scenario {scenario!r}")
    t.kill()


if __name__ == "__main__":
    main()
