#!/usr/bin/env python3
"""
Static Analysis CLI for MalWhere Pipeline
TFM 2025-2026 - Universidad Complutense de Madrid
"""

import sys
import json
import argparse
from pathlib import Path

# Add the parent directory so we can import from src
sys.path.insert(0, str(Path(__file__).parent))
from src.analyzer import StaticAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description='Static Analysis for MalWhere Pipeline'
    )
    parser.add_argument(
        '--sample', '-s',
        required=True,
        help='Path to the sample file'
    )
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output directory for JSON results'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--no-floss',
        action='store_true',
        help='Skip FLOSS extraction (faster)'
    )
    parser.add_argument(
        '--export-stix',
        action='store_true',
        help='Export results to STIX 2.1 format'
    )

    args = parser.parse_args()

    sample_path = Path(args.sample)
    if not sample_path.exists():
        print(f"Error: Sample file not found: {args.sample}")
        sys.exit(1)

    analyzer = StaticAnalyzer(sample_path, verbose=args.verbose, no_floss=args.no_floss)
    report = analyzer.analyze()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{sample_path.stem}_static.json"

    with open(output_file, 'w') as f:
        json.dump(report.to_dict(), f, indent=2, default=str)

    # Export to STIX if requested
    if args.export_stix:
        try:
            from src.exporters.stix_exporter import export_report_to_stix
            stix_file = output_dir / f"{sample_path.stem}_stix.json"
            export_report_to_stix(output_file, stix_file)
        except ImportError:
            print("Warning: STIX exporter not available")

    print("\n" + "="*60)
    print(f"ANALYSIS COMPLETE: {sample_path.name}")
    print("="*60)
    print(f"File: {report.filename}")
    print(f"Size: {report.size_mb:.2f} MB")
    print(f"SHA-256: {report.sha256}")
    print(f".NET: {'Yes' if report.is_dotnet else 'No'}")
    print(f"Imphash: {report.imphash or 'N/A'}")
    print(f"Packer: {'Yes' if report.packer.detected else 'No'}")
    if report.packer.detected:
        for p in report.packer.packers:
            print(f"   - {p.get('name', 'Unknown')} (confidence: {p.get('confidence', 'low')})")
    print(f"Sections: {len(report.sections)}")
    print(f"Imports: {len(report.imports)}")
    print(f"Exports: {len(report.exports)}")
    print(f"Strings: {len(report.strings.standard)}")
    print(f"FLOSS Strings: {len(report.strings.floss)}")
    print(f"Suspicious Indicators: {len(report.indicators.suspicious_strings)}")
    print(f"Anti-VM Indicators: {len(report.indicators.anti_vm_strings)}")
    print(f"Anti-Sandbox Indicators: {len(report.indicators.anti_sandbox_strings)}")
    print(f"YARA Matches: {len(report.yara.matched_rules)}")
    print(f"Config Items: {len(report.config.get('ips', [])) + len(report.config.get('domains', []))}")
    if report.errors:
        print(f"Errors: {len(report.errors)}")
        for error in report.errors[:5]:
            print(f"   - {error}")
    print("="*60)
    print(f"Results saved to: {output_file}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
