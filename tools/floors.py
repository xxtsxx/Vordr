#!/usr/bin/env python3
"""floors - refuse to let a static gate go quiet.

Every checker in tools/ prints how much it inspected, and until now nothing
cared if that number collapsed.  A checker that stops finding things and a
checker that stops LOOKING print the same word: clean.  The second is worse than
having no checker at all, because the green line is counted as evidence.

This has happened here twice.  dlgtarget's verified count fell from 24 to 2 and
nothing said so.  verify_msi.ps1's first draft read one row of a 21-row table -
a PowerShell array-unrolling slip - and passed a package with a missing sequence
action.  Both were found by accident, and one of them only after a live install
went wrong.

So each tool declares what it inspected, and this refuses the build if the
number drops below a floor recorded here.  The floors sit in ONE file on purpose:
lowering one is then a visible, reviewable line in a diff, rather than a constant
edited inside a tool nobody re-reads.

Floors are set around 90% of the count at the time of writing - low enough that
ordinary refactoring does not trip them, high enough that a checker losing half
its reach cannot pass.  Raise them when a count grows a lot; lower them only with
a reason in the commit message.
"""

FLOORS = {
    "framecheck": {
        # FRAME_PROLOG procs whose frame was actually sized and checked.
        "procs": 450,                    # 496 at time of writing
    },
    "idcheck": {
        # control IDs defined in BOTH vordr.rc and gui.asm, i.e. comparable.
        "shared_ids": 120,               # 136
    },
    "constcheck": {
        # constants deliberately mirrored across modules and compared.
        "mirrored": 15,                  # 20
        "files": 25,                     # 30
    },
    "dlgtarget": {
        # every dialog-item call the parser recognised at all.  This is the
        # number that proves the PARSER still works; "verified" below is the
        # number that proves the CHECK still reaches something.
        "calls": 120,                    # 135
        "verified": 40,                  # see the note in dlgtarget.py
        "settings_rows": 10,             # 12
    },
    "rccheck": {
        # dialog templates and controls whose geometry was parsed and checked.
        "dialogs": 13,                   # 15 at time of writing
        "controls": 140,                 # 160
    },
    "wstrcheck": {
        # call sites whose bound-carrying register was checked.
        "calls": 25,                     # 29 at time of writing
    },
    "deadcode": {
        "symbols": 2000,                 # 2305
    },
    "aligncheck": {
        "scalars": 80,                   # 98
    },
}


def check(tool, metrics):
    """Report any metric that has fallen through its floor.

    metrics: {name: count} measured by the caller this run.
    Returns the number of floors breached (0 = fine), so a caller can fold it
    into its exit code and fail a strict build through the path it already has.
    """
    floors = FLOORS.get(tool)
    if floors is None:
        return 0
    breached = 0
    for name, minimum in sorted(floors.items()):
        got = metrics.get(name)
        if got is None:
            print(f"[FLOOR] {tool}: no longer reports '{name}' - either the metric was "
                  f"renamed or the check was removed; update tools/floors.py deliberately")
            breached += 1
            continue
        if got < minimum:
            print(f"[FLOOR] {tool}: only {name}={got}, floor is {minimum} - this checker "
                  f"has gone quiet.  Either it lost its reach (a bug in the tool, or an "
                  f"idiom it no longer recognises) or the codebase really shrank; if the "
                  f"latter, lower the floor in tools/floors.py and say why.")
            breached += 1
    return breached
