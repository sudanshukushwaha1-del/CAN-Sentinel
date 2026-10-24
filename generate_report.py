"""Write the maintained project summary to Markdown and optionally convert it to PDF."""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="CAN-Sentinel-Project-Report.md",
                        help="destination Markdown path (default: project summary in current directory)")
    parser.add_argument("--pdf", action="store_true", help="also convert the output Markdown to PDF")
    args = parser.parse_args()
    output = Path(args.output)
    source = Path(__file__).resolve().with_name("CAN-Sentinel-Project-Report.md")
    if output.resolve() != source.resolve():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Wrote {output.resolve()}")
    if args.pdf:
        converter = shutil.which("manus-md-to-pdf")
        if converter is None:
            raise SystemExit("PDF converter 'manus-md-to-pdf' is unavailable; install the Manus document conversion utility or omit --pdf.")
        pdf = output.with_suffix(".pdf")
        subprocess.run([converter, str(output), str(pdf)], check=True)
        print(f"Wrote {pdf.resolve()}")


if __name__ == "__main__":
    main()
