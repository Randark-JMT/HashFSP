from __future__ import annotations

import logging
import time
from typing import Optional

from rich.console import Console
from rich.table import Table
import typer

from .auth import parse_hash_credentials
from .smb_client import RemoteSmbClient, SmbTarget


app = typer.Typer(
    add_completion=False,
    help="Mount an authorized SMB lab share through WinFsp using NTLM hash authentication.",
)
console = Console()


def _build_client(
    *,
    host: str,
    share: str,
    username: str,
    domain: str,
    hashes: Optional[str],
    lmhash: Optional[str],
    nthash: Optional[str],
    remote_name: Optional[str],
    port: int,
    timeout: int,
) -> RemoteSmbClient:
    credentials = parse_hash_credentials(
        username=username,
        domain=domain,
        hashes=hashes,
        lmhash=lmhash,
        nthash=nthash,
    )
    target = SmbTarget(
        host=host,
        share=share,
        port=port,
        remote_name=remote_name,
        timeout=timeout,
    )
    return RemoteSmbClient(target, credentials)


@app.command()
def check(
    host: str = typer.Argument(..., help="SMB server hostname or IP."),
    share: str = typer.Argument(..., help="Share name to validate."),
    username: str = typer.Option(..., "--username", "-u", help="Authorized account name."),
    domain: str = typer.Option("", "--domain", "-d", help="Domain or workgroup."),
    hashes: Optional[str] = typer.Option(None, "--hashes", help="LMHASH:NTHASH, or just NTHASH."),
    lmhash: Optional[str] = typer.Option(None, "--lmhash", help="LM hash. Defaults to the empty LM hash."),
    nthash: Optional[str] = typer.Option(None, "--nthash", help="NT hash."),
    remote_name: Optional[str] = typer.Option(None, "--remote-name", help="NetBIOS name if different from host."),
    port: int = typer.Option(445, "--port", help="SMB TCP port."),
    timeout: int = typer.Option(30, "--timeout", help="Network timeout in seconds."),
    limit: int = typer.Option(20, "--limit", help="Maximum root entries to display."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
):
    """Validate auth and list the root of the selected share."""
    _configure_logging(verbose)
    try:
        client = _build_client(
            host=host,
            share=share,
            username=username,
            domain=domain,
            hashes=hashes,
            lmhash=lmhash,
            nthash=nthash,
            remote_name=remote_name,
            port=port,
            timeout=timeout,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        client.connect()
        entries = client.list_dir("\\")[:limit]
    finally:
        client.disconnect()

    table = Table(title=f"\\\\{host}\\{share}")
    table.add_column("Type")
    table.add_column("Name")
    table.add_column("Size", justify="right")
    for entry in entries:
        table.add_row("DIR" if entry.is_directory else "FILE", entry.file_name, str(entry.file_size))
    console.print(table)


@app.command()
def mount(
    host: str = typer.Argument(..., help="SMB server hostname or IP."),
    share: str = typer.Argument(..., help="Share name to mount."),
    mountpoint: str = typer.Argument(..., help="Drive letter or mount point, for example X:."),
    username: str = typer.Option(..., "--username", "-u", help="Authorized account name."),
    domain: str = typer.Option("", "--domain", "-d", help="Domain or workgroup."),
    hashes: Optional[str] = typer.Option(None, "--hashes", help="LMHASH:NTHASH, or just NTHASH."),
    lmhash: Optional[str] = typer.Option(None, "--lmhash", help="LM hash. Defaults to the empty LM hash."),
    nthash: Optional[str] = typer.Option(None, "--nthash", help="NT hash."),
    remote_name: Optional[str] = typer.Option(None, "--remote-name", help="NetBIOS name if different from host."),
    port: int = typer.Option(445, "--port", help="SMB TCP port."),
    timeout: int = typer.Option(30, "--timeout", help="Network timeout in seconds."),
    label: str = typer.Option("HashFSP", "--label", help="Local volume label."),
    read_only: bool = typer.Option(False, "--read-only", help="Expose the mounted share as read-only."),
    debug: bool = typer.Option(False, "--debug", help="Enable WinFsp debug logging."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
):
    """Mount one explicit SMB share until Ctrl+C is pressed."""
    _configure_logging(verbose or debug)

    try:
        client = _build_client(
            host=host,
            share=share,
            username=username,
            domain=domain,
            hashes=hashes,
            lmhash=lmhash,
            nthash=nthash,
            remote_name=remote_name,
            port=port,
            timeout=timeout,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    from .fs import create_hash_file_system

    file_system = None
    try:
        display_user = f"{domain}\\{username}" if domain else username
        console.print(f"Connecting to \\\\{host}\\{share} as {display_user}...")
        client.connect()
        file_system = create_hash_file_system(
            mountpoint,
            client,
            label=label,
            read_only=read_only,
            debug=debug,
        )
        file_system.start()
        console.print(f"Mounted \\\\{host}\\{share} at {mountpoint}. Press Ctrl+C to unmount.")
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        console.print("Unmount requested.")
    finally:
        if file_system is not None and file_system.started:
            file_system.stop()
        client.disconnect()
        console.print("Stopped.")


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
