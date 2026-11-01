## Docs and comments

When you write docs in source code most of them must be a single sentence
that conveys the essence of the thing you are documenting. Do not be afraid
to use precise technical terms. Prefer them strongly to multi-word plain
English formulations. Each sentence after the first one needs justification
to be included—it must be important and non-trivial information.

Do not write line comments that explain what is going on inside the code,
unless the point they convey is truly important and non-trivial. Code should
dominate comments, not the other way around.

Instead of writing in Claudisms, try to write in a style that is already
used in the codebase.

Write lines that are no longer than 76 characters, if possible. The same
applies to commit messages and especially commit headers—they always have to
be under 76 characters.

## Config files

Do not write comments in GitHub workflows and other config files, and do
not separate their entries with blank lines. Give the reasoning in the
commit message instead.

## Checking your implementations

Before declaring something done, ask yourself the question: is this the
simplest and irreducible implementation of this logic? Are
simplifications/ablations possible that make the solution more elegant?

## Running Bazel

`bazel` exists only inside the `bazel-env` FHS environment, which direnv
enters only from an interactive terminal. If `bazel` is not on `PATH`,
run commands through it, e.g. `bazel-env -c 'bazel test //rust/...'`.

## The fishery

When adding or changing a fishery target, run `./fishery.py` for that
target only, and leave `./fishery.py ci` to CI. Say what was not checked
locally and why that is safe. If a change can affect several targets, as
a change to Ahab's checks or to the shape of the report can, ask before
running more than one target.
