# The fishery

The fishery keeps a set of real open-source Bazel projects, fetches each at
a pinned commit, wires this working copy of Ahab into it, and records what
Ahab has to say.

The recorded report is the point. A change to a check can then be judged by
what it does to somebody else's build—the diff of `expectation.json` is what
review looks at, and a check that quietly starts flagging four hundred more
things says so in the diff rather than in production.

Ahab runs as a prebuilt binary, built once from this working copy and then
pointed at each project in turn. The project is fetched and analyzed, never
modified: it gains no dependency on Ahab, so its own dependency versions,
toolchains and build graph are exactly what its authors pinned. What Ahab
reports is therefore about that project rather than about what depending on
Ahab did to it.

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
* `ci` runs `setup`, `check` and `clean` on every target, summarizing
  each expectation as it goes. `--shard=I/N` runs only the `I`th of `N`
  shares of them, which is how CI splits the work across parallel jobs.

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
| `compilation_mode` | the project's own   | `fastbuild`, `dbg` or `opt`    |
| `workspace`        | the root workspace  | a workspace nested inside it   |
| `weight`           | `1`                 | how costly this one is to run  |

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
