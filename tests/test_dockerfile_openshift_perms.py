"""Shield images run under OpenShift's restricted-v2 SCC without `anyuid`.

OpenShift starts a container as a random UID whose group is 0. Anything the
process writes must therefore be writable by group 0. The images used to leave
their app and cache dirs root-owned 755, so customers were told to grant
`anyuid` (docs/specs/onprem-release-bundle.md, task 1a).

The fix is `chgrp -R 0 <dirs> && chmod -R g=u <dirs>` after everything that
creates files. There is deliberately NO `USER` line: RunPod and Railway run
these images as root, and the data plane binds port 80 by default, which a
non-root user cannot.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# image -> directories the running process writes (beyond /tmp)
WRITABLE = {
    "Dockerfile": ["/runpod", "$CACHE"],        # app + vLLM/HF caches (ENV CACHE=/tmp/cache)
    "Dockerfile.cloud": ["/runpod"],            # app (logs/ at runtime)
    "Dockerfile.admin": ["/app"],               # app (logs/, reports/ at runtime)
}


def _instructions(name: str) -> list[tuple[str, str]]:
    """(INSTRUCTION, argument) per instruction, continuations joined."""
    lines, cur = [], ""
    for raw in (ROOT / name).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cur = f"{cur} {line[:-1].strip()}" if line.endswith("\\") else f"{cur} {line}"
        if not line.endswith("\\"):
            lines.append(cur.strip())
            cur = ""
    out = []
    for line in lines:
        head, _, rest = line.partition(" ")
        out.append((head.upper(), rest))
    return out


@pytest.mark.parametrize("name", sorted(WRITABLE))
def test_no_user_instruction(name):
    assert not [a for i, a in _instructions(name) if i == "USER"], (
        f"{name}: a USER line breaks hosts that run the image as root on port 80")


@pytest.mark.parametrize("name", sorted(WRITABLE))
def test_writable_dirs_are_group_zero_and_group_writable(name):
    ins = _instructions(name)
    perm_idx = [n for n, (i, a) in enumerate(ins)
                if i == "RUN" and "chgrp -R 0" in a and "chmod -R g=u" in a]
    assert perm_idx, f"{name}: no `chgrp -R 0 ... && chmod -R g=u ...` step"
    last = perm_idx[-1]
    arg = ins[last][1]
    chgrp_part = arg.split("chgrp -R 0", 1)[1].split("&&", 1)[0].split()
    chmod_part = arg.split("chmod -R g=u", 1)[1].split("&&", 1)[0].split()
    for d in WRITABLE[name]:
        assert d in chgrp_part and d in chmod_part, f"{name}: {d} not covered by {arg!r}"

    # Nothing after it may create root-only files again.
    for i, a in ins[last + 1:]:
        assert i != "COPY", f"{name}: COPY after the permission step: {a!r}"
        assert not (i == "RUN" and re.search(r"\b(mkdir|pip install|cp|touch)\b", a)), (
            f"{name}: RUN creates files after the permission step: {a!r}")


def test_cache_env_dirs_live_under_the_covered_cache_root():
    """Every cache dir the vLLM image points tools at must sit under $CACHE,
    the root the permission step covers."""
    ins = _instructions("Dockerfile")
    envs = dict(re.match(r"(\S+?)[= ](.*)", a).groups() for i, a in ins if i == "ENV" and a)
    cache = envs["CACHE"].strip()
    for var in ("PIP_CACHE_DIR", "HF_HOME", "HUGGINGFACE_HUB_CACHE", "VLLM_CACHE_ROOT",
                "TORCHINDUCTOR_CACHE_DIR", "FLASHINFER_CACHE_DIR", "TRITON_CACHE_DIR"):
        assert envs[var].strip().startswith("$CACHE/") or envs[var].strip().startswith(cache), var
