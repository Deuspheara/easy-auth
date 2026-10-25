#!/usr/bin/env python3
"""Update only the fixed CSP constant after preparing the three style inputs."""
from pathlib import Path
import base64
import hashlib
import re
root = Path(__file__).resolve().parents[2]
styles = root / 'crates/auth-axum/src/pages'
css = b''.join((styles / name).read_bytes() for name in ['vendor/basecoat.css', 'tokens.css', 'reference.css'])
digest = base64.b64encode(hashlib.sha256(css).digest()).decode()
path = root / 'crates/auth-axum/src/browser/boundary.rs'
source = path.read_text()
source, count = re.subn(r"style-src 'sha256-[A-Za-z0-9+/=]+'", f"style-src 'sha256-{digest}'", source, count=1)
assert count == 1
path.write_text(source)
