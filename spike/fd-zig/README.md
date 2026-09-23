# fd spike: making descriptor bugs hard in a Zig launcher

A spike for rewriting the launcher in Zig. It asks one question: how much of
the fd bug class can be made impossible, or caught, before anything else is
ported? `src/fd.zig` is the candidate descriptor layer. Everything else here
exists to attack it.

```sh
zig build test          # unit tests + the model-based property (minish)
zig build compile-fail  # kind confusion must not compile
zig build lint          # fdlint: raw descriptor APIs only in the syscall layer
zig build analyze       # zwanzig: src/ clean, planted bugs still caught
zig build test -Drelease=true   # the same in ReleaseSafe, the launcher's mode
```

Zig 0.15.2. minish and zwanzig are lazy dependencies, pinned to tags, so a
plain `zig build` needs no network (the Nix derivation's constraint).

## The design

- A handle is `{slot, gen}` into a fixed process-global table, never a
  number. `close` bumps the slot's generation, so every copy (in a struct, a
  keep list, a forked child's globals) is stale, and `raw()` on a stale copy
  panics instead of reaching whatever file reused the number.
- The kind is in the type: `Fd(.pidfd)` is not `Fd(.dir)`, and `read` on a
  write end is a `@compileError`.
- `fork(keep)` runs `retainOnly(keep)` in the child: every other descriptor
  is closed, and every other handle goes stale. This replaces
  `fl_close_from` and the hand-written `fl_sigfd` fix-up.
- `Spawn.passFd(h)` is the only way to put a descriptor number in argv, and
  it keeps the descriptor. The launcher's argv-vs-keep mismatch
  (`flong-launch.c:281-336`) cannot be written.
- `Child` owns a pidfd: `wait` reaps once, and `deinit` kills and reaps
  first if nothing has.
- Every open is `O_CLOEXEC`, and the spawned child also marks everything
  above 2 close-on-exec with `close_range` before clearing the kept ones, as
  the C does.

## What catches what

| Bug | Types | zwanzig | fdlint | Runtime table | Property test |
|---|---|---|---|---|---|
| Double close | | ✅ | | ✅ panics | |
| Use after close | | ✅ | | ✅ panics | ✅ |
| Alias closed twice | | ✅ | | ✅ panics | |
| Pipe end (struct field) double close | | ✅ | | ✅ panics | |
| Child deinit twice | | ✅ ¹ | | ✅ panics | |
| Stale copy in a struct | | ❌ | | ✅ panics | ✅ |
| Stale handle in a fork child | | ❌ | | ✅ panics | ✅ |
| Leak | | ❌ ² | | `liveCount` | ✅ `/proc/self/fd` |
| Kind confusion | ✅ | | | ✅ panics | |
| argv names an fd the child lacks | ✅ `passFd` | | | | ✅ probe |
| fd reaching a child unkept | | | | | ✅ probe |
| Raw `close`/`open` bypassing the table | | | ✅ | | ✅ |
| Forged handle (`.slot = …`) | | | ✅ | | |

¹ Only with a model that matches on method name alone (`.zwanzig.json`).
² See the zwanzig findings below.

**Mutation check.** Each bug below was planted in `fd.zig` and caught, with
minish shrinking the failing input to 2–3 operations:

- The spawned child ignores the keep list: the probe's held set differs from
  its argv.
- `retainOnly` skips the final `close_range`: the fork child sees extra fds.
- `close` does not bump the generation: `expected 134, found 1`, which means
  the read through a stale handle reached the reused file.

Removing `O_CLOEXEC` from `openDir` is not caught, and correctly so: the
spawned child's `close_range(CLOEXEC)` already covers it, as the C's
"close_range before every spawn" rule does.

## zwanzig findings (v0.15.1)

- **It never reports a leak from the CLI**, not even on its own fixture
  (`test/fixtures/store_violations_engine/leak.zig`, which expects one).
  This happens with both release binaries (0.15.2 and 0.16.0 frontends) and
  with a source build. Its unit test calls the checker directly and
  passes. Separately, leak reports on error-return paths are suppressed by
  design. **Leaks therefore come from the table and the property test, not
  from zwanzig.** The CLI behaviour is worth an upstream issue.
- **It tracks resources stored in a struct as escaped**, per its docs, so it
  misses stale copies (B5). The generation check covers these.
- **`receiver_type` and `fqn` models do not resolve a type imported from
  another file.** Only `method_name` matching caught `Child.deinit` twice.
  That is broad (every `deinit` becomes a close), but on this code it gives
  no false positives.
- **Without any config** it already catches B1–B3, B6 and B8. Its built-in
  `open*`/`close` name patterns fit the API as written. Keeping the fd API's
  verbs as `open…`/`close` is worth doing for that reason.
- On raw `std.posix` fds it catches nothing without a model. On
  `std.fs.File` it catches double close and use after close.
- It builds from source in about a minute (ReleaseFast).

## fdlint

`tools/fdlint.zig` is about 100 lines over `std.zig.Tokenizer`, so comments
and strings never match. Outside the allowed files it reports three things:

- `.posix`, `.os`, `.fs` or `.c` after a period.
- `@cImport`.
- `.slot` or `.gen`.

It bans the namespaces rather than individual functions, so an alias like
`const P = std.posix` is caught where it is made. For the port, the allowed
set is the syscall layer: `fd.zig` and whatever wraps the mount API and
`clone3` alongside it. That layer mints `Fd(.tree)` and `Fd(.fsctx)`
handles, so they also go through the table.

## Layout

- `src/fd.zig`: the layer.
- `src/fd_test.zig`: unit tests and the property.
- `src/procfds.zig`: `/proc/self/fd` read with raw syscalls, safe to run in
  a fork child.
- `src/probe.zig`: the spawned probe. It prints the fds it holds and the
  numbers its argv names.
- `probes/api/bugs.zig`: planted bugs against the API, for zwanzig.
- `probes/raw/`: the zwanzig baseline on `std.posix` and `std.fs.File`.
- `probes/compile_fail/`: kind confusion that must not compile.
- `probes/lint/bad.zig`: planted lint violations.
