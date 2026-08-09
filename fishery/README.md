# The fishery

The fishery keeps a set of real open-source Bazel projects, fetches each at
a pinned commit, wires this working copy of Ahab into it, and records what
Ahab has to say.

The recorded report is the point. A change to a check can then be judged by
what it does to somebody else's build—the diff of `expectation.json` is what
review looks at, and a check that quietly starts flagging four hundred more
things says so in the diff rather than in production.

A target here also exercises Ahab as a Bazel module, which its own build
cannot: `//:hermeticity` runs the rules from inside the repository that
defines them, where dev dependencies exist and the root module is Ahab
itself.

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

* `setup` fetches the project into `work/` and injects the Ahab targets.
* `check` fails if Ahab's findings differ from `expectation.json`.
* `update` rewrites `expectation.json` with what Ahab reports now.
* `explain` prints the recorded report without analyzing anything.
* `clean` expunges the project's Bazel state and removes `work/`.
* `ci` runs `setup` and then `check` on every target.

`setup` does four things: a depth-1 fetch of exactly the pinned commit, a
`bazel_dep` plus `local_path_override` appended to the project's
`MODULE.bazel`, a load and three `ahab_*` targets added to its top-level
`BUILD.bazel`, and `expectation.json` copied in under the name those targets
expect. It refuses to run over an existing `work/`; run `clean` first.

`expectation.json` need not exist beforehand. When it does not, `setup`
writes one recording no violations. That is what makes a new target's first
`check` a readable diff—everything Ahab finds shows up as added—rather than
an analysis error about a missing source file.

`update` copies the report back out of `work/` afterwards, so that `clean`
does not throw away the thing the run produced.

## Adding a target

Make a directory and write a `spec.json`:

```json
{
  "repo": "https://github.com/abseil/abseil-cpp",
  "commit": "5650e9cf76d3be4318d5fa3af38ee483ddfd5e4a",
  "label": "//absl/strings/...",
  "configs": []
}
```

`repo` and `commit` are required; `label` defaults to `//...` and `configs`
to none. Pin a full 40-character SHA rather than a branch—a fishery whose
input moves cannot tell you what your own change did.

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
`--exceptions-json` takes. It is optional, and `setup` wires it up only when
it is there—the attribute is omitted rather than passed empty, because a
label naming a file that does not exist is an analysis error rather than an
empty list.

Note that `expectation.json` records what survives filtering, so adding an
exception shrinks it. That diff is the reviewable artifact—an exception and
the findings it removes land in the same commit.

## Constraints worth knowing

**The project has to use bzlmod.** The wiring is `bazel_dep` plus
`local_path_override`, so a `WORKSPACE`-only project cannot be a target.
`setup` says so rather than producing something broken.

**Setup fetches over the network** and `check`/`update` run a full Bazel
analysis of the target project, so these are not part of `bazel test //...`
and never will be. CI runs them as its own step, `./fishery.py ci`.

**`ci` attempts every target even after one fails.** A run that stopped at
the first bad news would tell you about one project when it could have told
you about all of them, and breadth is the whole point. The exit code is
still 1 if anything failed, and the run ends with a count and the names.
