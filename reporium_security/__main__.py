"""CLI entry point: python -m reporium_security scan <repo>"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from reporium_security.scanner import scan_repo
from reporium_security.reporter import generate_report, write_report


def _clone_repo(repo_path: str, dest: Path) -> Path:
    """Clone a GitHub repo to a temporary directory."""
    # Normalize: accept org/repo or full URL
    if not repo_path.startswith("http"):
        url = f"https://github.com/{repo_path}.git"
    else:
        url = repo_path

    subprocess.run(
        ["git", "clone", "--depth=20", url, str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="reporium-security",
        description="Security scanning for Reporium repos",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a repository")
    scan_parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Repository to scan: local path or GitHub org/repo (default: current directory)",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        help="Write SECURITY_REPORT.md to this path",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON (not yet implemented)",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "scan":
        return _handle_scan(args)

    return 0


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle the scan subcommand."""
    repo = args.repo
    temp_dir = None

    try:
        # Determine if this is a remote repo or local path
        if "/" in repo and not Path(repo).exists():
            # Looks like a GitHub org/repo path
            temp_dir = tempfile.mkdtemp(prefix="reporium-scan-")
            print(f"Cloning {repo}...")
            repo_path = _clone_repo(repo, Path(temp_dir) / "repo")
            repo_name = repo
        else:
            repo_path = Path(repo).resolve()
            repo_name = repo_path.name

        print(f"Scanning {repo_name}...")
        report = scan_repo(repo_path, repo_name)

        # Print summary
        print()
        print(report.summary)
        print()

        # Write report if requested
        if args.output:
            output_path = write_report(report, Path(args.output))
            print(f"Report written to {output_path}")

        # Return exit code based on grade
        if report.grade.value in ("A", "B"):
            return 0
        elif report.grade.value == "C":
            return 0
        else:
            return 1

    except subprocess.CalledProcessError as exc:
        print(f"Error: Failed to clone repository: {exc.stderr}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
