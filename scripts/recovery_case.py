from __future__ import annotations

import json
import os
import select
import sys

from claimjumper.bounded_fixtures import FIXED_VULNERABLE_COURIER_TOKEN
from claimjumper.recovery import recover_fixed_vulnerable_fixture

FORBIDDEN_ENVIRONMENT_INPUTS = {
    "CLAIMJUMPER_RECOVERY_TOKEN",
    "CLAIMJUMPER_RECOVERY_CANDIDATES",
    "CLAIMJUMPER_RECOVERY_KEY",
    "CLAIMJUMPER_RECOVERY_PATH",
    "CLAIMJUMPER_RECOVERY_URL",
    "CLAIMJUMPER_RECOVERY_OUTPUT",
}


def reject_external_inputs() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("recovery accepts no command-line arguments")
    if FORBIDDEN_ENVIRONMENT_INPUTS.intersection(os.environ):
        raise SystemExit("recovery accepts no environment overrides")
    readable, _, _ = select.select([sys.stdin], [], [], 0)
    if readable and sys.stdin.read(1):
        raise SystemExit("recovery accepts no stdin")


def main() -> None:
    reject_external_inputs()
    result = recover_fixed_vulnerable_fixture(FIXED_VULNERABLE_COURIER_TOKEN)
    print(
        json.dumps(
            {
                "candidate_count": result.candidate_count,
                "match": result.fictional_match,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
