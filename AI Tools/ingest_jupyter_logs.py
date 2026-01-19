import argparse
import csv
import os
import re

import pandas as pd


TIME_PATTERN = re.compile(r'^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<rest>.*)$')
TARGET_PATH_FRAGMENT = f"{os.sep}exthost{os.sep}output_logging_"
OUTPUT_LOGGING_PREFIX = 'output_logging_'


def get_default_root():
    appdata = os.environ.get('APPDATA')
    if not appdata:
        raise ValueError('APPDATA is not set; use --root or define APPDATA.')
    if not os.path.isdir(appdata):
        raise ValueError(f"APPDATA does not resolve to a path: {appdata}")
    return os.path.join(appdata, 'Code', 'logs')


def collect_jupyter_logs(root):
    log_files = []
    for dirpath, _, filenames in os.walk(root):
        if TARGET_PATH_FRAGMENT not in dirpath.lower():
            continue
        for name in filenames:
            lower_name = name.lower()
            if 'jupyter' not in lower_name or not lower_name.endswith('.log'):
                continue
            log_files.append(os.path.join(dirpath, name))
    return log_files


def extract_output_logging_timestamp(path):
    for part in path.split(os.sep):
        lower_part = part.lower()
        if lower_part.startswith(OUTPUT_LOGGING_PREFIX):
            return part[len(OUTPUT_LOGGING_PREFIX):]
    return ''


def combine_date_time(folder_timestamp, time_only):
    if not folder_timestamp or len(folder_timestamp) < 8:
        return time_only
    date_part = folder_timestamp[:8]
    return f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:]} {time_only}"


def ingest_jupyter_log(path, message_joiner):
    rows = []
    folder_timestamp = extract_output_logging_timestamp(path)
    current = None
    current_multiline_lines = 0
    orphan_lines = 0
    multiline_messages = 0
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                match = TIME_PATTERN.match(line)
                if match:
                    if current is not None:
                        if current_multiline_lines > 0:
                            current['multiline_lines'] = current_multiline_lines
                            current['is_multiline'] = True
                            multiline_messages += 1
                        else:
                            current['multiline_lines'] = 0
                            current['is_multiline'] = False
                        current['message'] = message_joiner.join(current['message_parts'])
                        del current['message_parts']
                        rows.append(current)
                    current_multiline_lines = 0
                    time_only = match.group('ts')
                    timestamp = combine_date_time(folder_timestamp, time_only)
                    current = {
                        'timestamp': timestamp,
                        'time_only': time_only,
                        'message_parts': [line],
                        'path': path,
                        'folder_timestamp': folder_timestamp,
                    }
                    continue
                if current is None:
                    orphan_lines += 1
                    continue
                current_multiline_lines += 1
                current['message_parts'].append(line)
        if current is not None:
            if current_multiline_lines > 0:
                current['multiline_lines'] = current_multiline_lines
                current['is_multiline'] = True
                multiline_messages += 1
            else:
                current['multiline_lines'] = 0
                current['is_multiline'] = False
            current['message'] = message_joiner.join(current['message_parts'])
            del current['message_parts']
            rows.append(current)
    except OSError as exc:
        return [], orphan_lines, multiline_messages, str(exc)
    return rows, orphan_lines, multiline_messages, None


def ingest_to_dataframe(root, csv_path=None, joiner=' \\n ', file_log_path=None):
    log_files = collect_jupyter_logs(root)
    rows = []
    total_orphans = 0
    total_multiline_messages = 0
    file_summaries = []
    for path in log_files:
        file_rows, orphan_lines, multiline_messages, read_error = ingest_jupyter_log(path, joiner)
        rows.extend(file_rows)
        total_orphans += orphan_lines
        total_multiline_messages += multiline_messages
        failed_messages = 0
        if read_error is not None:
            failed_messages = 1
        file_summaries.append({
            'path': path,
            'messages_ok': len(file_rows),
            'messages_failed': failed_messages,
            'error': read_error,
        })

    df = pd.DataFrame(
        rows,
        columns=[
            'timestamp',
            'time_only',
            'message',
            'path',
            'folder_timestamp',
            'multiline_lines',
            'is_multiline',
        ],
    )
    global df_ingest_jupyter_logs
    df_ingest_jupyter_logs = df

    if csv_path is not None:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    'timestamp',
                    'time_only',
                    'message',
                    'path',
                    'folder_timestamp',
                    'multiline_lines',
                    'is_multiline',
                ],
            )
            writer.writeheader()
            writer.writerows(rows)

    if file_log_path is None:
        file_log_path = os.path.join(os.getcwd(), 'ingest_jupyter_logs_file_summary.log')
    with open(file_log_path, 'w', encoding='utf-8') as f:
        for summary in file_summaries:
            error = summary['error'] or ''
            f.write(
                f"{summary['path']} | "
                f"MESSAGES_OK: {summary['messages_ok']} | "
                f"MESSAGES_FAILED: {summary['messages_failed']} | "
                f"ERROR: {error}\n"
            )

    stats = {
        'files': len(log_files),
        'messages': len(rows),
        'orphan_lines': total_orphans,
        'multiline_messages': total_multiline_messages,
    }
    return df, stats


def main():
    parser = argparse.ArgumentParser(
        description='Ingest Jupyter.log files under exthost/output_logging_ folders.'
    )
    parser.add_argument(
        '--root',
        default=get_default_root(),
        help='Root logs directory to scan.',
    )
    parser.add_argument(
        '--csv',
        default='exthost_output_logging_jupyter_messages.csv',
        help='CSV path to write parsed messages.',
    )
    parser.add_argument(
        '--joiner',
        default=' \\n ',
        help='String to join multiline message lines into one field.',
    )
    args = parser.parse_args()

    _, stats = ingest_to_dataframe(
        args.root,
        csv_path=args.csv,
        joiner=args.joiner,
        file_log_path=os.path.join(os.getcwd(), 'ingest_jupyter_logs_file_summary.log'),
    )
    print(f"LOG_FILES_FOUND: {stats['files']}")
    print(f"CSV_WRITTEN: {os.path.abspath(args.csv)}")
    print(f"MESSAGES_PARSED: {stats['messages']}")
    print(f"ORPHAN_LINES: {stats['orphan_lines']}")
    print(f"MULTILINE_MESSAGES: {stats['multiline_messages']}")


if __name__ == '__main__':
    main()
