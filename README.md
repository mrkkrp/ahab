# Ahab

* [Quickstart](#quickstart)
  * [Recording what you find](#recording-what-you-find)
  * [The macros](#the-macros)
* [Checks](#checks)
  * [Environment leaks](#environment-leaks)
  * [`PATH`](#path)
  * [Execution requirements](#execution-requirements)
  * [Absolute paths](#absolute-paths)
  * [Reproducibility](#reproducibility)
* [Reproducibility specifications](#reproducibility-specifications)
  * [Naming a program](#naming-a-program)
  * [Writing one](#writing-one)
  * [When a rule only sometimes applies](#when-a-rule-only-sometimes-applies)
  * [Saying it another way](#saying-it-another-way)
* [Exceptions](#exceptions)
  * [How they match](#how-they-match)
  * [What they will not let you do](#what-they-will-not-let-you-do)
  * [Being specific](#being-specific)
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
actions declaring that they need the network or must not be sandboxed, and
programs whose reproducibility nobody has vouched for.

The two answer different questions, and Ahab does not replace log
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

That prints every violation found and exits non-zero if there were any.
Nothing is built: Ahab asks Bazel for the action graph with `aquery` and
reads it, so the cost is one analysis phase rather than one build.

One has to use `bazel run` and not `bazel test` with Ahab targets. Ahab
shells out to Bazel, and a nested invocation inside a build action would
contend for the output base with the invocation that started it—so it is
deliberately not offered as a test rule.

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

`ahab_explain` prints a recorded report without analyzing anything, which is
how you read one produced on another machine:

```starlark
ahab_explain(
    name = "hermeticity.explain",
    report = "//:expectation.json",
)
```

### The macros

`ahab` takes `label`, `configs`, `repro_specs`, `exceptions`, `shut_up`,
`no_fail`, `write_json`, `explain_json` and `expect_json`. The three
wrappers take the subset that makes sense for them, plus `baseline` or
`report`. All of them pass unrecognized arguments through, so `visibility`
and `tags` work as usual.

`configs` forwards `--config=<name>` values to the underlying `aquery`,
which matters when the thing worth analyzing is a particular configuration.

The binary is also usable directly—`bazel run @ahab//:ahab -- --help` lists
the flags the macros set for you.

## Checks

Ahab reports two kinds of finding. A **hermeticity violation** says the
action's behaviour can depend on the machine it runs on. A
**reproducibility violation** says the action runs a program that will not
produce the same output twice, or that Ahab cannot vouch for.

### Environment leaks

Ahab runs `aquery` with `USER` and `HOSTNAME` replaced by long,
distinctive sentinels, then looks for those sentinels anywhere in the
resulting graph: command lines, param file contents, and environment
variable values. Anything that comes back is a value the build copied out
of the invoking environment.

The sentinels are fixed rather than random, because a different `USER` on
every run changes every action key and makes Bazel redo its analysis every
time—and because the sentinel is recorded in the violation, so a moving one
could never be compared against a saved report.

### `PATH`

Every action is required to set `PATH` to exactly
`/bin:/usr/bin:/usr/local/bin`, which is what Bazel uses when nothing
interferes. Anything else is a path the build chose, and a build that
chooses its own `PATH` is choosing the machine's tools.

### Execution requirements

The only finding Ahab does not have to infer. An action's
`execution_requirements`—`tags` on the target, or the rule's own
declarations—are read straight out of the graph, and these are reported:

| requirement                   | reading                                     |
| ----------------------------- | ------------------------------------------- |
| `requires-network`            | the output can depend on anything out there |
| `no-cache`                    | refusing to cache is saying the output is not a function of the inputs |
| `no-sandbox`, `local`         | the action sees the whole filesystem, so it can read inputs it never declared |
| `no-remote`, `no-remote-exec` | an action that must run *here* is likely to depend on here |

Everything else—`supports-workers`, `cpu:4`, `resources:…`,
`supports-path-mapping`—is scheduling advice and is ignored. The list is a
deny-list rather than an allow-list so that a tag nobody has classified is
silence rather than noise.

### Absolute paths

Any `/`-rooted run appearing in an argument, a param file line, or an
environment variable value. A build that names `/opt/toolchain/bin/cc` is a
build that only works where that exists.

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

Unknown is reported rather than passed over. A tool nobody has described is
not evidence of anything, and treating silence as approval is how a total
check stops being total.

## Reproducibility specifications

A specification says what Ahab knows about one program. The library it ships
with is small and deliberately so—every entry is a claim somebody had to
justify—so describing your own tools is the normal case, not an advanced
one.

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
generated repository name—which braids together names your project chose,
dependency versions and platform triples. What is left is the module and
extension names, fixed by whoever wrote the tool, and the path within them.

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

`recognize` is applied to each argument before the patterns see it, which is
what lets one specification cover a tool with several spellings for the same
thing. In the example above an invocation passing `-d` satisfies the
required `--deterministic`, as though it had been written out. Anything
unlisted stands for itself, so a table only has to name the exceptions.

### When a rule only sometimes applies

`required_flags` says *always*, and a program that does more than one job
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
differently.

For the conjunction, write more clauses: three macros that each need
defining away are three requirements sharing one condition, and every one of
them has to be met.

`because` is not decoration. It is what the report says when the clause goes
unmet, so it should finish the sentence "this is not reproducible because…":

```
CppCompile for //source/common/common:assert_lib runs
"@llvm_toolchain//bin/cc_wrapper.sh" non-reproducibly: debugging information
records the directory it was compiled in (none of ["-fdebug-compilation-dir=*",
"-ffile-prefix-map=*"])
```

`required_flags` and `breaking_flags` remain the short way to say the
unconditional case, and mean exactly what a clause with no `when` and a
single pattern means. Use them where a rule really does hold however the
program was invoked.

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

A file given later overrides one given earlier, and both override Ahab's
built-in knowledge—so a project can correct what Ahab believes about
anyone's tools, not only its own.

## Exceptions

An exception excuses violations you have decided to live with. They are
applied to the finished report, downstream of every check, so no exception
can change what a check looks at—only whether you hear about it.

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
`path` beside it, only that path is excused, and only there.

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
`absolute_path`, `system_program`, `host_derived_program`,
`unknown_program`, `never_reproducible` and `conditional_reproducibility`.

Fields that only some kinds carry are self-restricting: `path` can only ever
match an absolute-path finding, so naming one already implies the kind.
Naming a field the stated kind cannot carry is refused when the file loads,
rather than quietly matching nothing.

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

That is how you find out a problem was fixed years ago. It is a warning
rather than an error, because turning good news into a failed build teaches
people to stop fixing things.

### Being specific

Prefer exact conditions to patterns that happen to cover them. Two
exceptions naming `no-sandbox` and `no-cache` will each tell you when it
stops matching; one naming `no-*` covers both, stays in use while either
matches, and would silently swallow `no-remote` as well.

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
