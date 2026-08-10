#!/usr/bin/env python3
"""Run Ahab against real Bazel projects.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

FISHERY = Path(__file__).resolve().parent
AHAB = FISHERY.parent

# The files placed inside the fetched project. Named distinctively because
# they are written into somebody else's source tree.
REPORT = "ahab-expectation.json"
EXCEPTIONS = "ahab-exceptions.json"

# What a target expects before anyone has looked: nothing at all.
NO_VIOLATIONS = '{\n  "violations": []\n}\n'

# What `setup` writes into the project. Kept together so that `setup` can
# recognize its own work and refuse to do it twice.
MARKER = "# --- added by fishery, do not edit ---"

LOAD = 'load("@ahab//:defs.bzl", "ahab_check", "ahab_explain", "ahab_update")'

class TargetError(Exception):
    """A target cannot proceed.

    Raised rather than exiting, because whether that is fatal depends on who
    asked: it ends a single-target command, but a `ci` run has other
    projects to get to.
    """

def fail(message):
    raise TargetError(message)

def report_error(error):
    print(f"fishery: {error}", file=sys.stderr)

def run(args, cwd, check=True):
    """Run a command, letting its output through to the terminal."""
    print(f"fishery: $ {' '.join(str(a) for a in args)}", file=sys.stderr)
    return subprocess.run(args, cwd=cwd, check=check)

def targets():
    """Every directory under `fishery/` that is a target.

    A `spec.json` is what makes one, so a stray directory is not mistaken
    for a project with nothing in it.
    """
    return sorted(
        p.name for p in FISHERY.iterdir() if (p / "spec.json").is_file()
    )

def target_dir(name):
    path = FISHERY / name
    if not path.is_dir():
        known = ", ".join(targets()) or "none"
        fail(f"no such target {name!r}; known targets: {known}")
    return path

def read_spec(name):
    path = target_dir(name) / "spec.json"
    if not path.is_file():
        fail(f"{path} does not exist")
    spec = json.loads(path.read_text())
    for required in ("repo", "commit"):
        if required not in spec:
            fail(f"{path}: missing {required!r}")
    return spec

def work_dir(name):
    return target_dir(name) / "work"

def require_work(name):
    work = work_dir(name)
    if not work.is_dir():
        fail(f"{name} is not set up; run `fishery.py setup {name}` first")
    return work

def starlark_list(values):
    return "[" + ", ".join(json.dumps(v) for v in values) + "]"

def fetch(spec, work):
    """Shallow-fetch exactly the pinned commit.

    A depth-1 fetch of one SHA rather than a clone: the projects worth
    testing against have long histories, and none of that history is
    interesting here.
    """
    work.mkdir(parents=True)
    run(["git", "init", "--quiet"], cwd=work)
    run(["git", "remote", "add", "origin", spec["repo"]], cwd=work)
    fetched = run(
        ["git", "fetch", "--quiet", "--depth", "1", "origin", spec["commit"]],
        cwd=work,
        check=False,
    )
    if fetched.returncode != 0:
        fail(
            f"could not fetch {spec['commit']} from {spec['repo']}.\n"
            "        A server that refuses to serve a bare commit needs the "
            "commit to be\n        reachable from a branch or tag."
        )
    run(["git", "checkout", "--quiet", "FETCH_HEAD"], cwd=work)

def inject_module(work):
    """Point the project at this working copy of Ahab."""
    module = work / "MODULE.bazel"
    if not module.is_file():
        fail(
            f"{module} does not exist: the fishery can only wire itself into "
            "a bzlmod project"
        )
    # An absolute path because the override is resolved against the project
    # root, and work/ is disposable anyway—nothing here is committed.
    module.write_text(
        module.read_text()
        + f"\n{MARKER}\n"
        + 'bazel_dep(name = "ahab", version = "0.1.0")\n'
        + "local_path_override(\n"
        + '    module_name = "ahab",\n'
        + f"    path = {json.dumps(str(AHAB))},\n"
        + ")\n"
    )

def inject_build(work, spec, exceptions):
    """Add the Ahab targets to the project's top-level package.

    `exceptions` says whether the target supplied an exception file.
    """
    build = work / "BUILD.bazel"
    if not build.is_file():
        alternative = work / "BUILD"
        build = alternative if alternative.is_file() else build

    existing = build.read_text() if build.is_file() else ""
    label = spec.get("label", "//...")
    configs = spec.get("configs", [])
    common = (
        f'    label = {json.dumps(label)},\n'
        f'    configs = {starlark_list(configs)},\n'
        f'    baseline = "//:{REPORT}",\n'
    )
    if exceptions:
        common += f'    exceptions = ["//:{EXCEPTIONS}"],\n'
    build.write_text(
        f"{LOAD}\n\n"
        + existing
        + f"\n{MARKER}\n\n"
        + f'ahab_update(\n    name = "ahab.update",\n{common})\n\n'
        + f'ahab_check(\n    name = "ahab.check",\n{common})\n\n'
        + 'ahab_explain(\n    name = "ahab.explain",\n'
        + f'    report = "//:{REPORT}",\n)\n'
    )

def place_exceptions(name, work):
    """Copy the target's exception file in, if it has one.

    Optional on purpose: a project Ahab has nothing to excuse should not
    need an empty file to say so. Returns whether there was one, since the
    injected targets can only name it when it exists.
    """
    authored = target_dir(name) / "exceptions.json"
    if not authored.is_file():
        return False
    shutil.copyfile(authored, work / EXCEPTIONS)
    return True

def place_expectation(name, work):
    """Seed the project with the recorded report, recording one if absent.

    A target need not ship an expectation. A new one starts out expecting
    nothing, and `setup` writes that out rather than only handing it to the
    project, so the file is on disk from the first run and the first
    `update` shows up as a diff against it rather than as a new file.
    """
    recorded = target_dir(name) / "expectation.json"
    if not recorded.is_file():
        recorded.write_text(NO_VIOLATIONS)
        print(
            f"fishery: no expectation on record, wrote an empty "
            f"{recorded.relative_to(AHAB)}"
        )
    shutil.copyfile(recorded, work / REPORT)

def output_base(name):
    """Where a target's Bazel state lives.

    Its own, rather than whatever the environment would otherwise pick. CI
    pins one `--output_base` for the whole runner, which in absence of an
    override would make `clean --expunge` invocations quite
    counter-productive.
    """
    return Path.home() / ".cache" / "ahab-fishery" / name

def bazel_run(name, target):
    """`bazel run` one of the injected targets, propagating its exit code."""
    completed = run(
        ["bazel", f"--output_base={output_base(name)}", "run", target],
        cwd=require_work(name),
        check=False,
    )
    return completed.returncode

def cmd_setup(name):
    spec = read_spec(name)
    work = work_dir(name)
    if work.exists():
        fail(f"{work} already exists; run `fishery.py clean {name}` first")

    fetch(spec, work)
    inject_module(work)
    exceptions = place_exceptions(name, work)
    inject_build(work, spec, exceptions)
    place_expectation(name, work)
    print(f"fishery: {name} is ready in {work}")
    return 0

def cmd_check(name):
    return bazel_run(name, "//:ahab.check")

def cmd_update(name):
    work = require_work(name)
    code = bazel_run(name, "//:ahab.update")
    if code != 0:
        return code
    recorded = target_dir(name) / "expectation.json"
    shutil.copyfile(work / REPORT, recorded)
    print(f"fishery: recorded {recorded.relative_to(AHAB)}")
    return 0

def cmd_explain(name):
    return bazel_run(name, "//:ahab.explain")

def cmd_clean(name):
    work = work_dir(name)
    if not work.exists():
        print(f"fishery: {name} has nothing to clean")
        return 0
    run(
        ["bazel", f"--output_base={output_base(name)}", "clean", "--expunge"],
        cwd=work,
        check=False,
    )
    shutil.rmtree(work, ignore_errors=True)
    if work.exists():
        shutil.rmtree(work)
    shutil.rmtree(output_base(name), ignore_errors=True)
    print(f"fishery: removed {work.relative_to(AHAB)}")
    return 0

def summarize(name):
    """A target's recorded expectation, counted by kind.

    Read from `expectation.json` rather than measured afresh: that file is
    what review looks at, and after an `update` sweep it is exactly what
    Ahab found. Counting it costs nothing, where finding out again would
    cost another analysis of every project.
    """
    recorded = target_dir(name) / "expectation.json"
    if not recorded.is_file():
        return 0, 0, {}
    try:
        violations = json.loads(recorded.read_text())["violations"]
    except (ValueError, KeyError):
        return 0, 0, {}

    kinds = {}
    for counted in violations:
        kind = counted["violation"].get("kind", "?")
        distinct, occurrences = kinds.get(kind, (0, 0))
        kinds[kind] = (distinct + 1, occurrences + counted["count"])
    return (
        len(violations),
        sum(counted["count"] for counted in violations),
        kinds,
    )


def print_summary(label, distinct, occurrences, kinds):
    """One block: the totals, then a line per kind, widest first."""
    print(
        f"    {label}: {distinct} distinct, {occurrences} occurrences",
        flush=True,
    )
    ordered = sorted(kinds.items(), key=lambda kv: (-kv[1][0], kv[0]))
    for kind, (kind_distinct, kind_occurrences) in ordered:
        print(
            f"      {kind_distinct:>6} distinct"
            f"  {kind_occurrences:>6} occurrences  {kind}",
            flush=True,
        )


def cmd_ci():
    """Set up and check every target, reporting all of them.
    """
    names = targets()
    if not names:
        fail("no targets found under fishery/")

    failed = []
    totals = {}
    for name in names:
        print(f"\n=== fishery: {name} ===", flush=True)
        if work_dir(name).exists():
            try:
                cmd_clean(name)
            except (TargetError, subprocess.CalledProcessError) as error:
                report_error(error)
        for step, command in (("setup", cmd_setup), ("check", cmd_check)):
            try:
                code = command(name)
            except (TargetError, subprocess.CalledProcessError) as error:
                report_error(error)
                code = 1
            if code != 0:
                print(f"=== fishery: {name} FAILED at {step}", flush=True)
                failed.append(name)
                break
        else:
            print(f"=== fishery: {name} ok", flush=True)

        distinct, occurrences, kinds = summarize(name)
        print_summary("expectation", distinct, occurrences, kinds)

        try:
            cmd_clean(name)
        except (TargetError, subprocess.CalledProcessError) as error:
            report_error(error)
        for kind, (kind_distinct, kind_occurrences) in kinds.items():
            total_distinct, total_occurrences = totals.get(kind, (0, 0))
            totals[kind] = (
                total_distinct + kind_distinct,
                total_occurrences + kind_occurrences,
            )

    print(f"\n=== fishery: {len(names) - len(failed)}/{len(names)} passed",
          flush=True)
    # Worth printing only when it says something a single project did not.
    if len(names) > 1:
        print_summary(
            f"across {len(names)} projects",
            sum(distinct for distinct, _ in totals.values()),
            sum(occurrences for _, occurrences in totals.values()),
            totals,
        )
    if failed:
        print(f"=== fishery: failed: {', '.join(failed)}", flush=True)
        return 1
    return 0

COMMANDS = {
    "setup": cmd_setup,
    "check": cmd_check,
    "update": cmd_update,
    "explain": cmd_explain,
    "clean": cmd_clean,
    "ci": cmd_ci,
}

def main():
    parser = argparse.ArgumentParser(
        prog="fishery.py",
        description="Run Ahab against real Bazel projects.",
    )
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument(
        "target",
        nargs="?",
        help="a directory under fishery/; every one of them for `ci`",
    )
    args = parser.parse_args()

    try:
        if args.command == "ci":
            if args.target:
                fail("`ci` runs every target and takes no target argument")
            return cmd_ci()
        if not args.target:
            fail(
                f"`{args.command}` needs a target; "
                f"one of: {', '.join(targets())}"
            )
        return COMMANDS[args.command](args.target)
    except TargetError as error:
        report_error(error)
        return 1

if __name__ == "__main__":
    sys.exit(main())
