# The fishery

The fishery keeps a set of real open-source Bazel projects, fetches each at
a pinned commit, runs this working copy of Ahab on it, and records what Ahab
has to say.

The recorded report is the point. A change to a check can then be judged by
what it does to somebody else's build—the diff of `expectation.json` is what
review looks at, and a check that quietly starts flagging four hundred more
things says so in the diff rather than in production.

Ahab is built once and then pointed at each project in turn. The project is
fetched and analyzed, never modified: it gains no dependency on Ahab, so its
own dependency versions, toolchains and build graph are exactly what its
authors pinned. What Ahab reports is therefore about that project rather
than about what depending on Ahab did to it.

## Layout

```
fishery/
  fishery.py            the driver
  <target>/
    spec.json           what to fetch, and what to analyze   (committed)
    expectation.json    what Ahab reported last time         (created)
    exceptions.json     what to excuse, if anything          (optional)
    work/               the fetched project                  (gitignored)
```

## Commands

Each command, except for `ci`, takes a target name, which is a directory
under `fishery/`:

```
$ ./fishery.py <command> <target>
```

* `setup` fetches the project into `work/`.
* `check` fails if Ahab's findings differ from `expectation.json`.
* `update` rewrites `expectation.json` with what Ahab reports now.
* `explain` prints the recorded report without analyzing anything.
* `clean` expunges the project's Bazel state and removes `work/`.
* `ci` runs `setup`, `check` and `clean` on every target, summarizing each
  expectation as it goes. `--shard=I/N` runs only the `I`th of `N` shares of
  them, which is how CI splits the work across parallel jobs.

`setup` does one thing: a depth-1 fetch of exactly the pinned commit. It
refuses to run over an existing `work/`; run `clean` first.

Each target analyzes in an output base of the fishery's choosing, passed to
Ahab as `--output-base`, and `clean` expunges exactly that. The location has
to be dictated rather than discovered: a `startup` line in a home
`.bazelrc`, which is what CI runners tend to write, overrides anything a
workspace says, and would put every target and Ahab's own build in one
shared base—where expunging between targets would delete the binary the
fishery is running. An analysis output base runs to gigabytes, so it has to
be both ours and reclaimable.

`expectation.json` need not exist beforehand. When it does not, an empty one
recording no violations is written. That is what makes a new target's first
`check` a readable diff—everything Ahab finds shows up as added—rather than
a complaint about a missing file.

## Adding a target

Make a directory and write a `spec.json`. Every field it accepts is shown
here; only the first two are required:

```json
{
  "repo": "https://gitlab.arm.com/bazel/rules_tar",
  "commit": "c7da674bdea961c1f8f955a3cad5837251e0cc38",
  "label": "//...",
  "configs": [],
  "flags": [],
  "compilation_mode": "opt",
  "workspace": "e2e",
  "weight": 4
}
```

| field              | required/default    | meaning                        |
| ------------------ | ------------------- | ------------------------------ |
| `repo`             | required            | anything `git fetch` accepts   |
| `commit`           | required            | a full 40-character SHA        |
| `label`            | `//...`             | what to analyze                |
| `configs`          | `[]`                | `--config` values to forward   |
| `flags`            | `[]`                | Bazel flags to forward         |
| `compilation_mode` | the project's own   | `fastbuild`, `dbg` or `opt`    |
| `workspace`        | the root workspace  | a workspace nested inside it   |
| `weight`           | `1`                 | how costly this one is to run  |

`flags` are handed to `bazel aquery` as they stand, through Ahab's
`--bazel-flag`. `configs` covers a project that has already written the
configuration down; this is for the rest, and for a build a Linux runner can
only reach by being told how—see `rules_apple` below. `{target}` in a flag
expands to the target's own directory, which is how a flag can name a file
that lives in the fishery: an absolute path differs on every machine, and a
relative one would be resolved against the project.

`weight` is a scheduling hint and nothing else: it decides which CI shard a
project lands in, never what Ahab reports. Most targets cost about the same
and leave it out; set it only for one that is several times slower than the
rest, so that two of those cannot land in the same shard. Shards are worked
out from it at run time rather than written into the workflow, so adding a
target cannot silently drop it from CI.

Pin a full SHA rather than a branch—a fishery whose input moves cannot tell
you what your own change did. `repo` need not be GitHub; it is handed
straight to `git`.

Then:

```
$ ./fishery.py setup <target>
$ ./fishery.py update <target>
```

`setup` will have written an empty `expectation.json`; the first `update` is
what fills it in. Read it before committing: everything in there is
something Ahab currently believes, and a fishery target is only worth having
if somebody has looked at that list.

Choosing `label` is a judgment call. `//...` is the honest answer but on a
large project it is also a slow one, and the interesting findings usually
repeat. A subtree that exercises the toolchain—`//absl/strings/...` for a
C++ project—costs a fraction of the analysis and says most of the same
things.

## Exceptions

A target may also hold an `exceptions.json`, in exactly the format
`--exceptions-json` takes. It is optional, and passed to Ahab only when it
is there.

Note that `expectation.json` records what survives filtering, so adding an
exception shrinks it. That diff is the reviewable artifact—an exception and
the findings it removes land in the same commit.

## Apple, on Linux

`rules_apple` is analyzed here from a Linux runner with no Xcode anywhere,
which takes explaining, because building an Apple target that way is not
possible at all.

Analyzing one is, and the difference is what the fishery runs: `aquery`
describes the actions rather than running them. Two things stand between a
Linux host and that description, and the target's `flags` answer both. The
cc toolchains `apple_support` registers are `exec_compatible_with =
["@platforms//os:macos"]`, so toolchain resolution finds nowhere to run
them—`--extra_execution_platforms` names a macOS platform, which is a claim
about where the actions would run and costs nothing when none of them do.
And on a non-Darwin host `xcode_configure` writes a `local_config_xcode`
holding no Xcode versions, which `rules_swift` reports as "Could not
determine Xcode version at all"—`--xcode_version_config` points at one
written out by hand instead. `--platforms` puts the whole analysis on an
Apple platform, which the bundling rules would otherwise only transition
part of the graph onto.

Both declared targets live in `rules_apple/xcode/`, a repository the
analysis is handed with `--inject_repository` so that nothing has to be
written into the fetched project. The Xcode version it names is a fiction.
That is the point: it is the same fiction on every machine, where a real
Xcode would be whatever the runner had installed that month. The recorded
report holds no path, no Xcode version and no SDK version, and analyzing two
checkouts at different paths produces it byte for byte.

What this does not do is promise that a Mac would report exactly this. It is
the same rules, the same toolchain configuration and the same action graph,
with everything Xcode-specific still standing in `__BAZEL_XCODE_*`
placeholders—but nobody has compared the two.

## Constraints worth knowing

**The fishery does not test Ahab's packaging.** Running a prebuilt binary is
what keeps a target's dependency graph its own, and the price is that
nothing here exercises Ahab as a Bazel module. That is `packaging/`'s job,
in a sibling workspace where Ahab is somebody else's dependency.

**Setup fetches over the network** and `check`/`update` run a full Bazel
analysis of the target project, so these are not part of `bazel test //...`
and never will be. CI runs them as its own step, `./fishery.py ci`.

**`ci` attempts every target even after one fails.** A run that stopped at
the first bad news would tell you about one project when it could have told
you about all of them, and breadth is the whole point. The exit code is
still 1 if anything failed, and the run ends with a count and the names.
