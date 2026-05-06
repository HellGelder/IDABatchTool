#!/usr/bin/env python3
"""CLI для пакетного анализа файлов в IDA Pro."""
import argparse
import logging
from pathlib import Path

from ida_batch_tool.config.loader import get_ida_executable, get_max_ida
from ida_batch_tool.discovery.finder import find_executables
from ida_batch_tool.ida.runner import IDAAnalyzer
from ida_batch_tool.reporting.generator import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description="Batch IDA analysis tool")
    parser.add_argument("--inputdir", required=True, help="Directory with files to analyze")
    parser.add_argument("--analyse", action="store_true", help="Run autoanalysis and create .i64")
    parser.add_argument("--filter", default=".exe,.dll,.elf,.so", help="Comma-separated extensions")
    parser.add_argument("--max-ida", type=int, help="Max parallel IDA instances")
    parser.add_argument("--idat", help="Path to idat executable")
    parser.add_argument("--script", help="IDAPython script to run")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--report", action="store_true", help="Create HTML reports from .i64 files")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s: %(message)s")

    idat = args.idat or get_ida_executable()
    max_ida = args.max_ida or get_max_ida()
    extensions = [f".{e.strip().lstrip('.')}" for e in args.filter.split(",")]

    input_dir = Path(args.inputdir)
    if not input_dir.is_dir():
        print(f"Error: {args.inputdir} is not a directory")
        return

    if args.report and not args.analyse:
        # Только генерация отчётов по существующим .i64/.idb
        generator = ReportGenerator()
        for ext in ('*.i64', '*.idb'):
            for file in input_dir.glob(ext):
                json_path = file.with_suffix(file.suffix + ".export.json")
                if json_path.exists():
                    report_path = generator.generate_from_json(json_path)
                    print(f"Report saved: {report_path}")
        return

    files = find_executables(str(input_dir), extensions=extensions)
    print(f"Found {len(files)} files to analyze.")

    if not args.analyse:
        print("Use --analyse to start analysis. Exiting.")
        return

    script_path = Path(args.script) if args.script else None
    analyzer = IDAAnalyzer(idat_path=idat, max_workers=max_ida)
    results = analyzer.analyze_batch(files, script_path=script_path)

    succeeded = sum(1 for v in results.values() if v)
    print(f"Analysis completed: {succeeded}/{len(files)} succeeded.")

    if args.report:
        generator = ReportGenerator()
        for f in files:
            for ext in ('.i64', '.idb'):
                idb_path = f.with_suffix(ext)
                if idb_path.exists():
                    json_path = idb_path.with_suffix(idb_path.suffix + ".export.json")
                    if json_path.exists():
                        report_path = generator.generate_from_json(json_path)
                        print(f"Report saved: {report_path}")
                    break


if __name__ == "__main__":
    main()