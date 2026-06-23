from __future__ import annotations

from dataclasses import dataclass
import re


EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


@dataclass(frozen=True)
class HashCredentials:
    username: str
    domain: str
    lmhash: str
    nthash: str


def parse_hash_credentials(
    *,
    username: str,
    domain: str = "",
    hashes: str | None = None,
    lmhash: str | None = None,
    nthash: str | None = None,
) -> HashCredentials:
    """Build Impacket-compatible LM/NT hash credentials.

    Accepts either an Impacket-style LMHASH:NTHASH value or separate hash
    options. If only an NT hash is provided, the standard empty LM hash is used.
    """
    if not username:
        raise ValueError("username is required")

    parsed_lmhash = lmhash or ""
    parsed_nthash = nthash or ""

    if hashes:
        if lmhash or nthash:
            raise ValueError("use either --hashes or --lmhash/--nthash, not both")
        if ":" in hashes:
            parsed_lmhash, parsed_nthash = hashes.split(":", 1)
        else:
            parsed_nthash = hashes

    parsed_lmhash = parsed_lmhash.strip() or EMPTY_LM_HASH
    parsed_nthash = parsed_nthash.strip()

    if not _HEX32.fullmatch(parsed_lmhash):
        raise ValueError("LM hash must be 32 hexadecimal characters")
    if not _HEX32.fullmatch(parsed_nthash):
        raise ValueError("NT hash must be 32 hexadecimal characters")

    return HashCredentials(
        username=username,
        domain=domain or "",
        lmhash=parsed_lmhash.lower(),
        nthash=parsed_nthash.lower(),
    )
