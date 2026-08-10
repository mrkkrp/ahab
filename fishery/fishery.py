#!/usr/bin/env python3
"""Run Ahab against real Bazel projects.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

FISHERY = Path(__file__).resolve().parent
AHAB = FISHERY.parent

# What a target expects before anyone has looked: nothing at all.
NO_VIOLATIONS = '{\n  "violations": []\n}\n'

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

def ensure_expectation(name):
    """The target's recorded report, created empty when there is none.

    A target need not ship one. A new one starts out expecting nothing,
    written to disk rather than merely assumed, so that the first `update`
    reads as a diff against it rather than as a new file.
    """
    recorded = target_dir(name) / "expectation.json"
    if not recorded.is_file():
        recorded.write_text(NO_VIOLATIONS)
        print(
            f"fishery: no expectation on record, wrote an empty "
            f"{recorded.relative_to(AHAB)}"
        )
    return recorded

def output_base(name):
    """Where a target's Bazel state goes, chosen rather than discovered.

    Told to Ahab with `--output-base`, which is the only way to be sure of
    it: a `startup` line in a home `.bazelrc`—which is what CI runners tend
    to write—overrides anything a workspace says, and would otherwise put
    every project, and Ahab's own build, in one shared base. Expunging that
    would delete the very binary the fishery is running. An analysis output
    base runs to gigabytes, so it has to be both ours and reclaimable.
    """
    return Path.home() / ".cache" / "ahab-fishery" / name

def bazel_stdout(args):
    """Ask Bazel something in the Ahab repository and return what it said."""
    return subprocess.run(
        ["bazel"] + args,
        cwd=AHAB,
        check=True,
        capture_output=True,
        text=True,
    ).stdout

_ahab_binary = None

def ahab_binary():
    """Build Ahab once and return the path to the binary.

    Once per fishery invocation rather than once per target: the whole point
    of running a prebuilt binary is that a project under test neither builds
    Ahab nor perturbs its own dependency graph by depending on it.
    """
    global _ahab_binary
    if _ahab_binary is None:
        run(["bazel", "build", "//:ahab"], cwd=AHAB)
        paths = bazel_stdout(["cquery", "//:ahab", "--output=files"]).split()
        if len(paths) != 1:
            fail(f"expected one file for //:ahab, got {paths}")
        # Against the execution root rather than the workspace: Ahab builds
        # with convenience symlinks turned off, so there is no `bazel-out`
        # next to the sources for that relative path to hang from.
        execroot = bazel_stdout(["info", "execution_root"]).strip()
        _ahab_binary = Path(execroot) / paths[0]
        if not _ahab_binary.is_file():
            fail(f"built //:ahab but {_ahab_binary} is not there")
    return _ahab_binary

def ahab_run(name, args):
    """Run Ahab in the project, propagating its exit code.

    The recorded files are named where they are authored, under
    `fishery/<target>/`. Nothing is copied into the project and nothing has
    to be copied back out.
    """
    spec = read_spec(name)
    command = [str(ahab_binary()), f"--output-base={output_base(name)}"]
    for config in spec.get("configs", []):
        command.append(f"--config={config}")
    mode = spec.get("compilation_mode")
    if mode:
        command.append(f"--compilation-mode={mode}")
    exceptions = target_dir(name) / "exceptions.json"
    if exceptions.is_file():
        command.append(f"--exceptions-json={exceptions}")
    command += args + [spec.get("label", "//...")]
    completed = run(command, cwd=require_work(name), check=False)
    return completed.returncode

def cmd_setup(name):
    spec = read_spec(name)
    work = work_dir(name)
    if work.exists():
        fail(f"{work} already exists; run `fishery.py clean {name}` first")

    fetch(spec, work)
    ensure_expectation(name)
    print(f"fishery: {name} is ready in {work}")
    return 0

def cmd_check(name):
    return ahab_run(name, [f"--expect-json={ensure_expectation(name)}"])

def cmd_update(name):
    recorded = ensure_expectation(name)
    code = ahab_run(name, ["--no-fail", f"--write-json={recorded}"])
    if code != 0:
        return code
    print(f"fishery: recorded {recorded.relative_to(AHAB)}")
    return 0

def cmd_explain(name):
    """Print the recorded report.

    Ahab reads it without consulting Bazel, so unlike every other command
    this one has nothing to say about `work/` and does not need it.
    """
    recorded = target_dir(name) / "expectation.json"
    if not recorded.is_file():
        fail(f"{name} has no recorded expectation to explain")
    completed = run(
        [str(ahab_binary()), f"--explain-json={recorded}"],
        cwd=AHAB,
        check=False,
    )
    return completed.returncode

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
