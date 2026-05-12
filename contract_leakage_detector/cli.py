"""
Command-line interface for the Contract Leakage Detector.

Usage examples:

  # Single contract
  cld scan --rpc https://eth-mainnet.example.com \
            --chain-id 1 \
            --address 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

  # Multiple contracts inline
  cld scan --rpc https://... --chain-id 1 \
            --address 0xABCD...,0xDEAD...

  # File with one address per line
  cld scan --rpc https://... --chain-id 1 \
            --address-file contracts.txt \
            --workers 20 --cache-dir .cld_cache \
            --output-json report.json \
            --output-md  report.md \
            --output-csv summary.csv

  # Specific block
  cld scan --rpc https://... --chain-id 1 \
            --address 0x... --block 19000000

  # Disable proxy resolution (faster, less thorough)
  cld scan --rpc https://... --chain-id 1 --address 0x... --no-proxy
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone
from typing import List, Optional

import click

from .cache import LocalCache, NullCache
from .dedup import count_by_risk
from .models import RiskLevel, ScanReport
from .report import (
    console_summary,
    to_csv_file,
    to_json,
    to_json_file,
    to_markdown,
    to_markdown_file,
)
from .rpc import RPCClient
from .worker import batch_scan


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Address loading helpers
# ---------------------------------------------------------------------------

def _load_addresses(address: Optional[str], address_file: Optional[str]) -> List[str]:
    addresses: List[str] = []

    if address:
        for part in address.split(","):
            part = part.strip()
            if part:
                addresses.append(part)

    if address_file:
        try:
            with open(address_file, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Support comma-separated values in the file too
                        for part in line.split(","):
                            part = part.strip()
                            if part:
                                addresses.append(part)
        except OSError as exc:
            raise click.UsageError(f"Cannot read address file: {exc}")

    if not addresses:
        raise click.UsageError(
            "Provide at least one address via --address or --address-file."
        )

    # Basic format validation
    validated: List[str] = []
    for addr in addresses:
        if not addr.startswith("0x") or len(addr) != 42:
            click.echo(f"[warn] Skipping invalid address: {addr}", err=True)
            continue
        validated.append(addr.lower())

    # Deduplicate while preserving order
    seen = set()
    deduped: List[str] = []
    for addr in validated:
        if addr not in seen:
            seen.add(addr)
            deduped.append(addr)

    return deduped


# ---------------------------------------------------------------------------
# Main async scan logic
# ---------------------------------------------------------------------------

async def _run_scan(
    addresses: List[str],
    rpc_url: str,
    chain_id: int,
    block: str,
    cache_dir: Optional[str],
    resolve_proxy: bool,
    workers: int,
    output_json_path: Optional[str],
    output_md_path: Optional[str],
    output_csv_path: Optional[str],
    print_json: bool,
    print_md: bool,
    verbose: bool,
) -> ScanReport:
    cache = LocalCache(cache_dir) if cache_dir else NullCache()
    started_at = datetime.now(timezone.utc).isoformat()

    results = []
    eoas = 0
    errors = 0

    async with RPCClient(
        url=rpc_url,
        timeout=30,
        max_retries=4,
        max_connections=max(workers, 10),
    ) as rpc:
        # Validate RPC connection and resolve chain/block
        try:
            actual_chain_id = await rpc.get_chain_id()
            if actual_chain_id != chain_id:
                click.echo(
                    f"[warn] RPC reports chain_id={actual_chain_id}, "
                    f"but --chain-id={chain_id} was specified.",
                    err=True,
                )
        except Exception as exc:
            raise click.ClickException(f"Failed to connect to RPC endpoint: {exc}")

        block_number_int: Optional[int] = None
        if block == "latest":
            try:
                block_number_int = await rpc.get_block_number()
            except Exception:
                pass
        else:
            try:
                block_number_int = int(block, 16) if block.startswith("0x") else int(block)
                block = hex(block_number_int)
            except ValueError:
                raise click.UsageError(f"Invalid block value: {block!r}")

        if not verbose:
            click.echo(
                f"Scanning {len(addresses)} address(es) on chain {chain_id} "
                f"(block {'latest' if block == 'latest' else block_number_int}) …",
                err=True,
            )

        async for analysis in batch_scan(
            addresses=addresses,
            rpc=rpc,
            cache=cache,
            chain_id=chain_id,
            block=block,
            block_number_int=block_number_int,
            resolve_proxy_flag=resolve_proxy,
            max_workers=workers,
        ):
            results.append(analysis)

            if analysis.is_eoa:
                eoas += 1
            elif analysis.error:
                errors += 1

            # Incremental progress to stderr
            if not verbose:
                counts = count_by_risk(analysis.findings)
                status = "EOA" if analysis.is_eoa else (
                    f"⚠ error" if analysis.error else
                    f"{counts[RiskLevel.HIGH]}H/{counts[RiskLevel.MEDIUM]}M/{counts[RiskLevel.LOW]}L"
                )
                click.echo(f"  {analysis.address}  [{status}]", err=True)

    # Tally totals
    all_findings = [f for r in results for f in r.findings]
    total_counts = count_by_risk(all_findings)

    report = ScanReport(
        chain_id=chain_id,
        rpc_url=rpc_url,
        block_number=block_number_int,
        total_contracts=len(addresses),
        analyzed=len(addresses) - eoas,
        eoas_skipped=eoas,
        errors=errors,
        total_findings=len(all_findings),
        high_findings=total_counts[RiskLevel.HIGH],
        medium_findings=total_counts[RiskLevel.MEDIUM],
        low_findings=total_counts[RiskLevel.LOW],
        results=results,
        started_at=started_at,
    )

    return report


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """Contract Leakage Detector — defensive view/getter leakage scanner."""


@cli.command("scan")
@click.option("--rpc", "rpc_url", required=True, help="JSON-RPC endpoint URL.")
@click.option("--chain-id", required=True, type=int, help="EVM chain ID.")
@click.option(
    "--address", "address",
    default=None,
    help="Single address or comma-separated list.",
)
@click.option(
    "--address-file", "address_file",
    default=None,
    type=click.Path(exists=True),
    help="Path to a file with one address per line.",
)
@click.option(
    "--block", "block",
    default="latest",
    show_default=True,
    help="Block number (decimal or 0x hex) or 'latest'.",
)
@click.option(
    "--cache-dir", "cache_dir",
    default=None,
    help="Local cache directory. Omit to disable caching.",
)
@click.option(
    "--resolve-proxy/--no-proxy",
    "resolve_proxy",
    default=True,
    show_default=True,
    help="Detect and resolve proxy contracts.",
)
@click.option(
    "--workers", "workers",
    default=10,
    show_default=True,
    type=int,
    help="Number of concurrent analysis workers.",
)
@click.option(
    "--output-json", "output_json_path",
    default=None,
    help="Write JSON report to this file.",
)
@click.option(
    "--output-md", "output_md_path",
    default=None,
    help="Write Markdown report to this file.",
)
@click.option(
    "--output-csv", "output_csv_path",
    default=None,
    help="Write CSV summary to this file.",
)
@click.option(
    "--print-json", is_flag=True, default=False,
    help="Print JSON report to stdout.",
)
@click.option(
    "--print-md", is_flag=True, default=False,
    help="Print Markdown report to stdout.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Enable debug logging.",
)
def scan_cmd(
    rpc_url: str,
    chain_id: int,
    address: Optional[str],
    address_file: Optional[str],
    block: str,
    cache_dir: Optional[str],
    resolve_proxy: bool,
    workers: int,
    output_json_path: Optional[str],
    output_md_path: Optional[str],
    output_csv_path: Optional[str],
    print_json: bool,
    print_md: bool,
    verbose: bool,
) -> None:
    """Scan one or more contracts for view/getter information leakage."""
    _setup_logging(verbose)

    addresses = _load_addresses(address, address_file)
    click.echo(f"Loaded {len(addresses)} unique address(es).", err=True)

    report = asyncio.run(
        _run_scan(
            addresses=addresses,
            rpc_url=rpc_url,
            chain_id=chain_id,
            block=block,
            cache_dir=cache_dir,
            resolve_proxy=resolve_proxy,
            workers=workers,
            output_json_path=output_json_path,
            output_md_path=output_md_path,
            output_csv_path=output_csv_path,
            print_json=print_json,
            print_md=print_md,
            verbose=verbose,
        )
    )

    # Write file outputs
    if output_json_path:
        to_json_file(report, output_json_path)
        click.echo(f"JSON report → {output_json_path}", err=True)

    if output_md_path:
        to_markdown_file(report, output_md_path)
        click.echo(f"Markdown report → {output_md_path}", err=True)

    if output_csv_path:
        to_csv_file(report, output_csv_path)
        click.echo(f"CSV summary → {output_csv_path}", err=True)

    # Print to stdout
    if print_json:
        click.echo(to_json(report))
    elif print_md:
        click.echo(to_markdown(report))
    else:
        # Default: console summary
        click.echo("")
        click.echo(console_summary(report))

    # Exit non-zero when high-risk findings exist (useful for CI)
    if report.high_findings > 0:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
