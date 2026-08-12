# Ahab

* [Quickstart](#quickstart)
  * [Recording what you find](#recording-what-you-find)
  * [The macros](#the-macros)
* [Checks](#checks)
  * [Environment leaks](#environment-leaks)
  * [`PATH`](#path)
  * [Execution requirements](#execution-requirements)
  * [Absolute paths](#absolute-paths)
  * [Workspace status](#workspace-status)
  * [Reproducibility](#reproducibility)
* [Reproducibility specifications](#reproducibility-specifications)
  * [Naming a program](#naming-a-program)
  * [Writing one](#writing-one)
  * [When a rule only sometimes applies](#when-a-rule-only-sometimes-applies)
  * [Saying it another way](#saying-it-another-way)
* [Exceptions](#exceptions)
  * [How they match](#how-they-match)
  * [What they will not let you do](#what-they-will-not-let-you-do)
* [Development](#development)
* [The fishery](#the-fishery)
* [License](#license)

This is Ahab—a hermeticity analyzer for Bazel. The usual way to find out
whether a build is reproducible is to record and then [compare execution
logs][comparing-execlogs], and it does not scale: a complete log of a real
monorepo build reaches 100 GB and beyond. So in practice people look closely
at a few targets of interest, fix what they find there, and move on to the
next few, until the cache hit rate looks acceptable. That is useful work,
but it never adds up to a statement about the build as a whole.

Ahab goes the other way round. An execution log records what actually ran,
so producing one means building everything—twice, if you mean to compare.
Bazel's aquery instead describes what *would* run, which costs an analysis
phase and no build at all. Ahab reads that description and reports what it
finds there: values that leaked in from the environment, absolute paths,
actions declaring that they need the network or must not be sandboxed,
actions reading build metadata rather than their own inputs, and programs
whose reproducibility nobody has vouched for.

The two answer different questions, and Ahab does not replace execution log
comparison. Comparing logs is empirical—it catches a compiler embedding a
timestamp even though nobody knew it did. Ahab is analytical: it finds the
causes that make a build depend on the machine it runs on, before the build
runs, and it is only ever as good as what it has been told about the tools
involved. That is why a program nobody has described is reported rather than
passed over. What it buys is a check that covers everything and finishes in
seconds.

[comparing-execlogs]: https://bazel.build/versions/8.6.0/remote/cache-remote#comparing-the-execution-logs

## Quickstart

Ahab is a Bazel module. Add it to your `MODULE.bazel`:

```starlark
bazel_dep(name = "ahab", version = "0.1.0")
```

Then declare a target for whatever you want analyzed:

```starlark
load("@ahab//:defs.bzl", "ahab")

ahab(
    name = "hermeticity",
    label = "//...",
)
```

```
bazel run //:hermeticity
```

That prints every violation found and exits non-zero if there were any. One
has to use `bazel run` and not `bazel test` with Ahab, since invoking Bazel
commands inside a Bazel build is not permitted.

### Recording what you find

A real codebase will not reach zero violations on the first day. The way to
make that tractable is to record what you have and fail only on what is
new:

```starlark
load("@ahab//:defs.bzl", "ahab_check", "ahab_update")

ahab_update(
    name = "hermeticity.update",
    baseline = "//:expectation.json",
    label = "//...",
)

ahab_check(
    name = "hermeticity.check",
    baseline = "//:expectation.json",
    label = "//...",
)
```

`bazel run //:hermeticity.update` writes the report to `expectation.json`,
which you commit. `bazel run //:hermeticity.check` prints nothing and exits
0 while the findings match it exactly and prints a diff and exits 1 as soon
as they do not. That is the target to put in CI.

`baseline` is a label in both, deliberately the same string, so the two
cannot drift apart. `ahab_update` writes relative to the workspace root, so
it lands in the same place whatever directory you ran it from.

`ahab_explain` prints a recorded report without analyzing anything:

```starlark
ahab_explain(
    name = "hermeticity.explain",
    report = "//:expectation.json",
)
```

### The macros

`ahab` takes `label`, `configs`, `compilation_mode`, `repro_specs`,
`exceptions`, `shut_up`, `no_fail`, `write_json`, `explain_json` and
`expect_json`. The three wrappers take the subset that makes sense for them,
plus `baseline` or `report`. All of them pass unrecognized arguments
through, so `visibility` and `tags` work as usual.

`configs` forwards `--config=<name>` values to the underlying `aquery`,
which matters when the thing worth analyzing is a particular configuration.

`compilation_mode` sets the compilation mode to `fastbuild`, `dbg` or `opt`
rather than the default.

The binary is also usable directly—`bazel run @ahab//:ahab -- --help` lists
the flags the macros set for you.

## Checks

Ahab reports two kinds of finding. A **hermeticity violation** says the
action's behaviour can depend on the machine it runs on. A **reproducibility
violation** says the action runs a program that will not produce the same
output twice.

### Environment leaks

Ahab runs `aquery` with `USER` and `HOSTNAME` replaced by long,
distinctive sentinels, then looks for those sentinels anywhere in the
resulting graph: command lines, param file contents, and environment
variable values. Anything that comes back is a value the build copied out
of the invoking environment.

The sentinels are fixed rather than random, because a different `USER` on
every run changes every action key and makes Bazel redo its analysis every
time—and because the sentinel is recorded in the violation, so a changing
one could never be compared against a saved report.

### `PATH`

Every action is required to set `PATH` to exactly
`/bin:/usr/bin:/usr/local/bin`, which is what Bazel uses when nothing
interferes. Anything else is a path the build chose, and a build that
chooses its own `PATH` is choosing the machine's tools.

### Execution requirements

An action's `execution_requirements`—`tags` on the target, or the rule's own
declarations—are read straight out of the graph, and these are reported:

| requirement                   | reading                                     |
| ----------------------------- | ------------------------------------------- |
| `requires-network`            | the output can depend on anything out there |
| `no-sandbox`, `local`         | the action sees the whole filesystem, so it can read inputs it never declared |

Everything else—`supports-workers`, `cpu:4`, `resources:…`,
`supports-path-mapping`—is scheduling advice and is ignored.

### Absolute paths

Any `/`-rooted run appearing in an argument, a param file line, or an
environment variable value. A build that names `/opt/toolchain/bin/cc` is a
build that only works where that exists.

Not every absolute path is a path on the build machine, though. A tool that
builds a container image, a package or an installer is routinely told where
a file will sit once the artifact is unpacked *somewhere else*:

```
img manifest --working-dir /app --entrypoint /app/bin/server
```

`/app` is a directory the image will have, not an input path on the system
where we are running the build. Ahab has the necessary knowledge in order
make a distinction. See [`declared_paths`](#writing-one) below.

### Workspace status

An action that reads `bazel-out/stable-status.txt` or
`bazel-out/volatile-status.txt` is reported by default. These are where
Bazel writes the workspace status, and an action reading one produces output
that depends on values gathered about the build rather than on anything it
declared as an input.

Reading these files is often deliberate: it is how a release binary carries
a version. Like a `local` tag, that makes it a fact worth having on the
record rather than a mistake, and [exceptions](#exceptions) are how you say
so.

### Reproducibility

Ahab identifies the program each action runs, follows it through any
wrappers, and asks its library what is known about it. Five findings come
out of that:

| finding                     | meaning                            |
| --------------------------- | ---------------------------------- |
| system program              | reached outside the execution root |
| host-derived program        | inside the execution root, but written by inspecting the machine |
| unknown program             | Ahab has no specification for it, and says so rather than assuming the best |
| never reproducible          | the program cannot be made deterministic by any flags |
| conditional reproducibility | the program is deterministic only under conditions this invocation does not meet |

Unknown programs are reported rather than passed over. A tool nobody has
described is not evidence of anything, and treating silence as approval is
how a total check stops being total.

## Reproducibility specifications

A specification says what Ahab knows about one program. It can be extended
by users and this section explains how to do it.

*Heads up: the JSON format described below is subject to change before
1.0.0.*

### Naming a program

Programs are named in a Bazel-like label form, which is exactly how they
appear in the report, so one can be copied out of the other:

```
@rules_rust+rust//rust_toolchain/bin/rustc
@rules_cc+cc_configure_extension//cc_wrapper.sh
@rules_rust//util/process_wrapper/process_wrapper
//src/tools/generate
/usr/bin/gcc
```

The form is `@<module>+<extension>//<path>`, dropping to `@<module>//...` if
no extension is involved, `//<path>` for a program in the main module, and a
bare path for anything outside the execution root. Everything unstable is
normalized away: the Bazel version's separator, the module version, the
generated repository name. What is left is the module and extension names,
fixed by whoever wrote the tool, and the path within them.

The consequence worth knowing is that every repository generated by one
extension shares an identity. Each `crate_universe` build script is
`@rules_rust+crate//...` whatever crate it belongs to.

### Writing one

Pass specifications with `repro_specs`, either as a label naming a JSON
file or written out in the `BUILD.bazel` file directly:

```starlark
ahab(
    name = "hermeticity",
    label = "//...",
    repro_specs = [
        {
            "@acme+tools//bin/codegen": {
                "spec": {
                    "reproducibility": "sometimes",
                    "required_flags": ["--deterministic"],
                    "breaking_flags": ["--timestamp*"],
                    "recognize": {"-d": "--deterministic"},
                },
            },
        },
        "//tools:more_specs.json",
    ],
)
```

The fields live directly under `spec`, and only the first is required:

| field             |          | meaning                              |
| ----------------- | -------- | ------------------------------------ |
| `reproducibility` | required | the baseline disposition             |
| `required_flags`  | optional | patterns the invocation has to match |
| `breaking_flags`  | optional | patterns that spoil it               |
| `requirements`    | optional | the same, said conditionally         |
| `prohibitions`    | optional | the same, said conditionally         |
| `takes_value`     | optional | flags whose value is the next word   |
| `declared_paths`  | optional | absolute paths here are not inputs   |
| `recognize`       | optional | how to transform options             |

`reproducibility` is one of:

| value          | meaning                                         |
| -------------- | ----------------------------------------------- |
| `always`       | deterministic however it is invoked             |
| `never`        | no set of flags can make it deterministic       |
| `sometimes`    | deterministic under the conditions below        |
| `host_derived` | this program was derived by inspecting the host |

Only `sometimes` looks at the invocation at all; for the other three there
is nothing an invocation could say to change the answer.

`required_flags` and `breaking_flags` are lists of patterns, matched against
the invocation's arguments. `*` matches any run of characters and `?`
exactly one; a pattern with neither is an exact argument. A specification is
met when every required pattern matches some argument and no breaking one
matches any—unconditionally, which is not always what one wants to say; see
[below](#when-a-rule-only-sometimes-applies).

They are patterns rather than names because what makes an invocation
reproducible is usually a flag *and* its value. `--remap-path-prefix` says
only that some remapping happens; `--remap-path-prefix=${pwd}=*` says the
execution root is what gets remapped, which is the thing actually worth
requiring.

`takes_value` names the flags whose value arrives as a separate argument. A
pattern sees one argument at a time, so `--mtime=portable` is within reach
and `--invalidation_mode unchecked_hash` is not—the value is simply a
different word. Naming the flag folds the pair together with an `=` before
anything looks at it:

```json
{
  "reproducibility": "sometimes",
  "takes_value": ["--invalidation_mode"],
  "required_flags": ["--invalidation_mode=*hash*"]
}
```

Folding with `=` is what makes the two spellings converge, so one pattern
covers a tool however it was invoked—`-t 5` and `-t=5` both become `-t=5`.

`declared_paths` names the options in which an absolute path describes the
artifact the program produces rather than the machine producing it, and so
is not an [absolute-path](#absolute-paths) violation:

```json
{
  "reproducibility": "always",
  "takes_value": ["--working-dir", "--entrypoint"],
  "declared_paths": ["--working-dir=*", "--entrypoint=*"]
}
```

`recognize` is applied to each argument before the patterns see it, which is
what lets one specification cover a tool with several spellings for the same
thing. In the example above an invocation passing `-d` satisfies the
required `--deterministic`, as though it had been written out. Anything
unlisted stands for itself, so a table only has to name the exceptions.

### When a rule only sometimes applies

`required_flags` is unconditional and a program that does more than one job
cannot be described that way. Clang compiles, links, and preprocesses; a
rule about compiling, stated over every invocation, is a rule stated about
the wrong ones. `requirements` and `prohibitions` are the same idea with a
condition attached, and a sentence explaining themselves:

```json
{
  "reproducibility": "sometimes",
  "requirements": [
    {
      "because": "a source mentioning __DATE__ records when it was compiled",
      "when": {"family": ["-c"]},
      "any_of": ["-D__DATE__=*"]
    },
    {
      "because": "debugging information records the directory it was compiled in",
      "when": {"family": ["-g", "-gsplit-dwarf"], "off": ["-g0"]},
      "any_of": ["-ffile-prefix-map=*", "-fdebug-compilation-dir=*"]
    }
  ]
}
```

| field     |          | meaning                                        |
| --------- | -------- | ---------------------------------------------- |
| `because` | required | what the rule is about, quoted in the report   |
| `any_of`  | required | patterns, any one of which satisfies it        |
| `when`    | optional | the condition; absent means always             |

The two clauses show the two things a flat list cannot say.

**A condition.** `when` names a `family` of flags that turn something on and
the `off` flags of the same family that turn it back off. It is decided by
the *last* argument that speaks to it, because that is how compilers read
their own flags: `-g -g0` leaves debugging information off, and `-g0 -g`
leaves it on. A rule that only asked whether `-g0` appeared anywhere would
get the second one wrong. With no `off` flags the question is simply whether
the family appears, which is all the first clause needs.

**Alternatives.** `any_of` is satisfied by any one of its patterns, not all
of them. There is more than one way to keep the execution root out of the
DWARF—`-ffile-prefix-map` covers it, and naming the compilation directory
outright addresses the same field from the other end—and a specification
that demanded a particular one would report a build that had done the job
differently. For the conjunction, write more clauses.

`because` is not decoration. It is what the report says when the clause goes
unmet, so it should finish the sentence "this is not reproducible because…":

```
reproducibility violation: CppCompile action for target
//source/common/common:assert_lib runs program
"@llvm_toolchain//bin/cc_wrapper.sh" non-reproducibly: debugging information
records the directory it was compiled in, but none of
-fdebug-compilation-dir=* -ffile-prefix-map=* was passed
```

`required_flags` and `breaking_flags` remain the short way to say the
unconditional case, and mean exactly what a clause with no `when` and a
single pattern means.

### Saying it another way

Two other entry shapes save repeating yourself:

```json
{
  "programs": {
    "@llvm+t//bin/clang++": {
      "same_as": "@llvm+t//bin/clang"
    },
    "@acme//bin/runner": {
      "wraps": {
        "after_separator": "--"
      }
    }
  }
}
```

`same_as` judges one program by another's specification—a claim about
behavior, not identity, and the report still says what actually ran, and
which program answered for it. `wraps` says the real command follows a
separator in this one's arguments, so Ahab unwraps and judges what is
underneath. That is how e.g. `process_wrapper` is handled.

## Exceptions

An exception excuses violations you have decided to live with. They are
applied to the finished report, downstream of every check, so no exception
can change what a check looks at—only whether you hear about it.

*Heads up: the JSON format described below is subject to change before
1.0.0.*

### How they match

An exception is a set of conditions that **all** have to hold. A field left
out is not a condition:

```starlark
exceptions = [
    {
        "reason": "clang finds its own headers through the sysroot",
        "mnemonic": "CppCompile",
        "path": "/usr/include/*",
    },
]
```

A lone `mnemonic` would excuse everything that mnemonic's actions do. With a
`path` beside it, only that path is excused.

Every field except `reason` and `kind` is a pattern, with the same `*` and
`?` as everywhere else.

| field                | applies to              | matches                      |
| -------------------- | ----------------------- | ---------------------------- |
| `reason`             | —                       | nothing; it is documentation |
| `kind`               | all                     | the finding's kind, exactly  |
| `mnemonic`, `target` | all                     | the action                   |
| `program`            | the program findings    | the label form above         |
| `path`               | absolute paths          | the path found               |
| `actual`             | `PATH` findings         | the offending `PATH`         |
| `requirement`        | execution requirements  | the declared tag             |
| `source`             | environment leaks       | `user` or `hostname`         |
| `location`           | leaks, absolute paths   | `argument`, `param_file`, `env_var` |
| `env_var`            | the same, in an env var | the variable's name          |

The kinds are `environment_leak`, `bad_path`, `execution_requirement`,
`absolute_path`, `workspace_status`, `system_program`,
`host_derived_program`, `unknown_program`, `never_reproducible` and
`conditional_reproducibility`.

Fields that only some kinds carry narrow an exception on their own: `path`
can only match an absolute-path or a workspace-status finding, so naming one
already rules out the rest. Naming a field the stated kind cannot carry is
refused when the file loads, rather than quietly matching nothing.

### What they will not let you do

An exception with no conditions is refused, since it would suppress
everything. Unknown fields are refused too—a misspelled condition would
otherwise be dropped, and a dropped condition *widens* the exception, which
is the one direction a mistake here must not go.

Suppression is never silent. The report ends with a note saying how much
was excused and by how many exceptions, and an exception that matched
nothing is reported:

```
warning: 1 exception matched nothing:
  - "clang finds its own headers through the sysroot" (exceptions.json)
```

It is a warning rather than an error, because turning good news into a
failed build teaches people to stop fixing things.

## Development

Some useful commands while developing:

* `bazel build //:clippy` lints every crate in this repository.
* `bazel test //:rustfmt_test` can be used to check if all Rust source code
  is formatted.
* `bazel run //:format` formats the Rust source code.
* `bazel test //tools:buildifier_test` can be used to check if all Starlark
  source code is formatted.
* `bazel run //tools:buildifier` formats the Starlark source code.

## The fishery

`fishery/` runs Ahab against real open-source Bazel projects and records
what it finds, so that a change to a check can be judged by its effect on
somebody else's build. See [fishery/README.md](fishery/README.md).

## License

Copyright 2026–present Mark Karpov

Distributed under the MIT license.
