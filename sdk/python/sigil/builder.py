"""Builder client: local (subprocess) or remote (HTTP) binary builder."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Literal
from urllib.error import HTTPError
from urllib.request import Request, urlopen


@dataclass
class BuildResult:
    binary: bytes
    sha256: str


class Builder:
    """Abstract builder interface."""

    type: Literal["local", "remote"]

    async def build(self, private_key_seed_b64: str, platform: str) -> BuildResult:
        raise NotImplementedError


class LocalBuilder(Builder):
    """Builds identity binaries by invoking the sigil-builder CLI."""

    type: Literal["local"] = "local"

    async def build(self, private_key_seed_b64: str, platform: str) -> BuildResult:
        with tempfile.TemporaryDirectory(prefix="sigil-") as tmp_dir:
            out_path = os.path.join(tmp_dir, "identity")

            proc = await asyncio.create_subprocess_exec(
                "sigil-builder",
                "build",
                "--private-key",
                private_key_seed_b64,
                "--platform",
                platform,
                "--output",
                out_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            if proc.returncode != 0:
                raise RuntimeError(
                    f"sigil-builder exited with code {proc.returncode}: "
                    f"{stderr.decode().strip()}"
                )

            with open(out_path, "rb") as f:
                binary = f.read()

            sha256 = hashlib.sha256(binary).hexdigest()
            return BuildResult(binary=binary, sha256=sha256)


class RemoteBuilder(Builder):
    """Builds identity binaries by calling a remote builder HTTP service."""

    type: Literal["remote"] = "remote"

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    async def build(self, private_key_seed_b64: str, platform: str) -> BuildResult:
        body = json.dumps({
            "private_key": private_key_seed_b64,
            "platform": platform,
        }).encode()

        req = Request(
            f"{self.base_url}/build",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        # Run the blocking HTTP call in a thread to stay async-friendly
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, lambda: urlopen(req, timeout=120))
        except HTTPError as e:
            error_body = e.read().decode()
            try:
                error_msg = json.loads(error_body).get("error", "unknown")
            except (json.JSONDecodeError, AttributeError):
                error_msg = "unknown"
            raise RuntimeError(
                f"Builder error: {error_msg} ({e.code})"
            ) from e

        binary = response.read()
        sha256 = response.headers.get("X-Binary-SHA256", "")
        if not sha256:
            sha256 = hashlib.sha256(binary).hexdigest()

        return BuildResult(binary=binary, sha256=sha256)


def create_builder(mode: str) -> Builder:
    """Create a builder instance.

    Args:
        mode: Either "local" for subprocess-based building, or a URL
              for a remote builder service.
    """
    if mode == "local":
        return LocalBuilder()
    return RemoteBuilder(mode)
