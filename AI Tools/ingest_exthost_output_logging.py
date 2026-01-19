import argparse
import csv
import os
import re


LINE_TS_PATTERNS = [
    re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<rest>.*)$'),
    re.compile(r'^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<rest>.*)$'),
    re.compile(r'^(?P<ts>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$'),
]
SKIP_PREFIXES = ('ingest_errors', 'ingest_error_paths')
TARGET_PATH_FRAGMENT = f"{os.sep}exthost{os.sep}output_logging_"


def collect_log_files(root):
    log_files = []
    for dirpath, _, filenames in os.walk(root):
        if TARGET_PATH_FRAGMENT not in dirpath.lower():
            continue
        for name in filenames:
            lower_name = name.lower()
            if not lower_name.endswith('.log'):
                continue
            if lower_name.startswith(SKIP_PREFIXES):
                continue
            log_files.append(os.path.join(dirpath, name))
    return log_files


def is_timestamped(line):
    line_to_match = line.lstrip()
    candidates = [line_to_match]
    digit_match = re.search(r'\d', line_to_match)
    if digit_match and digit_match.start() > 0:
        candidates.append(line_to_match[digit_match.start():])
    for pattern in LINE_TS_PATTERNS:
        for candidate in candidates:
            if pattern.match(candidate):
                return True
    return False


def scan_for_multiline_messages(paths):
    results = []
    for full_path in paths:
        lines_read = 0
        multiline_messages = 0
        in_message = False
        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    lines_read += 1
                    line = line.rstrip('\n')
                    if is_timestamped(line):
                        in_message = True
                        continue
                    if in_message:
                        multiline_messages += 1
        except OSError as exc:
            results.append({
                'path': full_path,
                'lines_read': lines_read,
                'multiline_messages': None,
                'error': str(exc),
            })
            continue
        results.append({
            'path': full_path,
            'lines_read': lines_read,
            'multiline_messages': multiline_messages,
            'error': None,
        })
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Scan exthost/output_logging_ log files and report multiline messages.'
    )
    parser.add_argument(
        '--root',
        default=r'C:\\Users\\flynn\\AppData\\Roaming\\Code\\logs',
        help='Root logs directory to scan.',
    )
    parser.add_argument(
        '--csv',
        default='exthost_output_logging_multiline_report.csv',
        help='CSV path to write results.',
    )
    args = parser.parse_args()

    log_files = collect_log_files(args.root)
    print(f"LOG_FILES_FOUND: {len(log_files)}")
    results = scan_for_multiline_messages(log_files)
    with open(args.csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['path', 'lines_read', 'multiline_messages', 'error'],
        )
        writer.writeheader()
        writer.writerows(results)
    print(f"CSV_WRITTEN: {os.path.abspath(args.csv)}")

    total_multiline = 0
    files_with_multiline = 0
    for result in results:
        if result['error'] is not None:
            print(f"READ_ERROR: {result['path']} -> {result['error']}")
            continue
        if result['multiline_messages'] > 0:
            files_with_multiline += 1
            total_multiline += result['multiline_messages']
            print(
                f"MULTILINE: {result['path']} -> {result['multiline_messages']} continued lines"
            )

    if files_with_multiline == 0:
        print("MULTILINE_MESSAGES: not detected")
    else:
        print(
            f"MULTILINE_MESSAGES: detected in {files_with_multiline} files, "
            f"{total_multiline} continued lines"
        )


if __name__ == '__main__':
    main()
