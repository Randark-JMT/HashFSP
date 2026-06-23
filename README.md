# HashFSP

HashFSP mounts one explicitly configured SMB share as a local WinFsp drive while authenticating with NTLM hashes through Impacket. It is intended for authorized lab and CTF environments.

## Prerequisites

- Windows with WinFsp installed.
- Python 3.10 or 3.11 recommended. `winfspy` currently targets older Python releases than the system Python 3.14 installed here.
- Build tools capable of compiling the `winfspy` CFFI extension if a wheel is not available.

## Install

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .
```

If `winfspy` cannot locate WinFsp during install, set `WINFSP_LIBRARY_PATH` to the WinFsp installation directory, for example `C:\Program Files (x86)\WinFsp`.

If PyPI access is restricted in the lab network, configure your internal package mirror first. Editable installs also require `wheel`; with a pre-provisioned environment you can use `python -m pip install --no-build-isolation -e .` after `wheel` is available.

## Usage

Check credentials and list the root of a single share:

```powershell
hashfsp check 10.10.10.10 SHARE --username alice --domain LAB --hashes aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef
```

Mount the share as `X:`:

```powershell
hashfsp mount 10.10.10.10 SHARE X: --username alice --domain LAB --nthash 0123456789abcdef0123456789abcdef
```

Press `Ctrl+C` in the HashFSP console to unmount cleanly.

## Scope

The first version implements a conservative proxy filesystem: directory listing, stat, open, read, write, create, delete, rename, truncation, and basic timestamp/attribute updates. Advanced Windows filesystem behavior such as remote ACL editing, alternate data streams, reparse point handling, leases/oplocks, and a full Windows Redirector equivalent are intentionally out of scope.
