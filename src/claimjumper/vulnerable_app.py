from __future__ import annotations

import os

from claimjumper.app import create_app

app = create_app(
    mode="vulnerable",
    allow_vulnerable=os.getenv("ALLOW_VULNERABLE_DEMO") == "true",
)
