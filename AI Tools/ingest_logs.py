import argparse
import os
import socket
import re

import pandas as pd

LINE_TS_PATTERNS = [
    re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<rest>.*)$'),
    re.compile(r'^(?P<ts>\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<rest>.*)$'),
    re.compile(r'^(?P<ts>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$'),
]
ALLOWED_TAGS = {
    'info',
    'error',
    'warning',
    'Model',
    'doInitialScan',
    'main',
}
SKIP_PATH_FRAGMENT = f"{os.sep}exthost{os.sep}output_logging_"


def get_default_root():
    appdata = os.environ.get('APPDATA')
    if not appdata:
        raise ValueError('APPDATA is not set; use --root or define APPDATA.')
    if not os.path.isdir(appdata):
        raise ValueError(f"APPDATA does not resolve to a path: {appdata}")
    return os.path.join(appdata, 'Code', 'logs')


def collect_log_files(root):
    log_files = []
    for dirpath, _, filenames in os.walk(root):
        if SKIP_PATH_FRAGMENT in dirpath.lower():
            continue
        for name in filenames:
            if name.lower().endswith('.log'):
                if name.lower().startswith(('ingest_errors', 'ingest_error_paths')):
                    continue
                log_files.append(os.path.join(dirpath, name))
    return log_files


def parse_log_line(line, folder_timestamp):
    tags = []
    line_to_match = line.lstrip()
    candidates = [line_to_match]
    digit_match = re.search(r'\d', line_to_match)
    if digit_match and digit_match.start() > 0:
        candidates.append(line_to_match[digit_match.start():])
    for pattern in LINE_TS_PATTERNS:
        match = None
        for candidate in candidates:
            match = pattern.match(candidate)
            if match:
                break
        if not match:
            continue
        ts_str = match.group('ts')
        if len(ts_str) in (8, 12):
            if folder_timestamp and len(folder_timestamp) >= 8:
                date_part = folder_timestamp[:8]
                ts_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:]} {ts_str}"
        rest = match.group('rest')
        tags = [
            tag for tag in re.findall(r'\[([^\]]+)\]', rest)
            if tag in ALLOWED_TAGS
        ]
        return ts_str, tags
    return '', []


def ingest_logs(root, log_files, error_log_path=None, stats=None):
    rows = []
    hostname = socket.gethostname()
    error_log = None
    if stats is None:
        stats = {}
    stats.setdefault('files', 0)
    stats.setdefault('lines_read', 0)
    stats.setdefault('orphan_lines', 0)
    stats.setdefault('read_errors', 0)
    stats.setdefault('error_paths', set())
    stats.setdefault('file_summaries', [])
    if error_log_path:
        error_log = open(error_log_path, 'w', encoding='utf-8')

    for full_path in log_files:
        stats['files'] += 1
        rel_path = os.path.relpath(full_path, root)
        parts = rel_path.split(os.sep)
        folder_timestamp = parts[0] if parts else ''
        source = os.path.basename(full_path)
        try:
            row_count_before = len(rows)
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                current = None
                for line in f:
                    stats['lines_read'] += 1
                    line = line.rstrip('\n')
                    ts_str, tags = parse_log_line(line, folder_timestamp)
                    if ts_str:
                        if current is not None:
                            rows.append(current)
                        current = {
                            'timestamp': ts_str,
                            'tags': tags,
                            'message': line,
                            'source': source,
                            'path': full_path,
                            'hostname': hostname,
                            'folder_timestamp': folder_timestamp,
                        }
                    else:
                        if current is None:
                            if error_log is not None:
                                error_log.write(f"{full_path}: {line}\n")
                            stats['orphan_lines'] += 1
                            stats['error_paths'].add(full_path)
                            continue
                        current['message'] += '\n' + line
                if current is not None:
                    rows.append(current)
            messages_ok = len(rows) - row_count_before
            stats['file_summaries'].append({
                'path': full_path,
                'messages_ok': messages_ok,
                'messages_failed': 0,
                'error': None,
            })
        except OSError as e:
            stats['read_errors'] += 1
            stats['error_paths'].add(full_path)
            rows.append({
                'timestamp': '',
                'tags': ['error'],
                'message': f"<READ_ERROR: {e}>",
                'source': source,
                'path': full_path,
                'hostname': hostname,
                'folder_timestamp': folder_timestamp,
            })
            stats['file_summaries'].append({
                'path': full_path,
                'messages_ok': 0,
                'messages_failed': 1,
                'error': str(e),
            })

    if error_log is not None:
        error_log.close()

    df = pd.DataFrame(
        rows,
        columns=['timestamp', 'tags', 'message', 'source', 'path', 'hostname', 'folder_timestamp'],
    )
    df['timestamp_dt'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['folder_timestamp_dt'] = pd.to_datetime(
        df['folder_timestamp'],
        format='%Y%m%dT%H%M%S',
        errors='coerce',
    )
    return df


def ingest_to_dataframe(root, error_log_path=None, output_dir=None, file_log_path=None):
    roots = []
    normalized_root = os.path.normpath(root)
    if os.path.basename(normalized_root).lower() == 'roaming':
        for name in ('Code', 'Cursor', 'Windsurf'):
            candidate = os.path.join(normalized_root, name, 'logs')
            if os.path.isdir(candidate):
                roots.append(candidate)
    if not roots:
        roots = [root]

    is_multi_root = len(roots) > 1
    if output_dir is None:
        output_dir = os.getcwd()

    dfs = []
    stats_by_root = []
    file_summaries = []
    for root_path in roots:
        log_files = collect_log_files(root_path)
        error_log_path_for_root = error_log_path
        if error_log_path_for_root is None:
            error_log_path_for_root = os.path.join(
                output_dir,
                f"ingest_errors_{os.path.basename(os.path.normpath(root_path))}.log",
            )
        else:
            error_log_path_for_root = os.path.join(
                output_dir,
                os.path.basename(error_log_path_for_root),
            )
        if is_multi_root:
            base, ext = os.path.splitext(error_log_path_for_root)
            error_log_path_for_root = (
                f"{base}_{os.path.basename(os.path.normpath(root_path))}{ext}"
            )

        error_paths_log_path = os.path.join(
            output_dir,
            f"ingest_error_paths_{os.path.basename(os.path.normpath(root_path))}.log",
        )
        stats = {}
        df = ingest_logs(
            root_path,
            log_files,
            error_log_path=error_log_path_for_root,
            stats=stats,
        )
        error_paths = sorted(stats.get('error_paths', set()))
        with open(error_paths_log_path, 'w', encoding='utf-8') as f:
            for path in error_paths:
                f.write(f"{path}\n")
        dfs.append(df)
        file_summaries.extend(stats.get('file_summaries', []))
        stats_by_root.append({
            'root': root_path,
            'files': stats.get('files', 0),
            'lines_read': stats.get('lines_read', 0),
            'errors': stats.get('orphan_lines', 0) + stats.get('read_errors', 0),
        })

    if dfs:
        combined_df = pd.concat(dfs, ignore_index=True)
    else:
        combined_df = pd.DataFrame(
            columns=[
                'timestamp',
                'tags',
                'message',
                'source',
                'path',
                'hostname',
                'folder_timestamp',
                'timestamp_dt',
                'folder_timestamp_dt',
            ],
        )
    global df_ingest_logs
    df_ingest_logs = combined_df
    if file_log_path is None:
        file_log_path = os.path.join(output_dir, 'ingest_logs_file_summary.log')
    with open(file_log_path, 'w', encoding='utf-8') as f:
        for summary in file_summaries:
            error = summary['error'] or ''
            f.write(
                f"{summary['path']} | "
                f"MESSAGES_OK: {summary['messages_ok']} | "
                f"MESSAGES_FAILED: {summary['messages_failed']} | "
                f"ERROR: {error}\n"
            )
    return combined_df, stats_by_root


def main():
    parser = argparse.ArgumentParser(description='Ingest VSCode .log files into a dataframe.')
    parser.add_argument(
        '--root',
        default=get_default_root(),
        help='Root logs directory to scan.'
    )
    parser.add_argument(
        '--error-log',
        default=None,
        help='Path to write orphaned log lines.'
    )
    args = parser.parse_args()

    df, stats_by_root = ingest_to_dataframe(
        args.root,
        error_log_path=args.error_log,
        output_dir=os.getcwd(),
        file_log_path=os.path.join(os.getcwd(), 'ingest_logs_file_summary.log'),
    )
    for root_stats in stats_by_root:
        print(f"LOG_ROOT: {root_stats['root']}")
        print(f"LOG_FILES_INGESTED: {root_stats['files']}")
        print(f"LOG_LINES_READ: {root_stats['lines_read']}")
        print(f"LOG_ERRORS: {root_stats['errors']}")
    print(f"DATAFRAME_SHAPE: {df.shape}")


if __name__ == '__main__':
    main()
