import argparse
import os

import ingest_codeql_logs
import ingest_jupyter_logs
import ingest_logs


def get_default_root():
    appdata = os.environ.get('APPDATA')
    if not appdata:
        raise ValueError('APPDATA is not set; use --root or define APPDATA.')
    if not os.path.isdir(appdata):
        raise ValueError(f"APPDATA does not resolve to a path: {appdata}")
    return os.path.join(appdata, 'Code', 'logs')


def main():
    parser = argparse.ArgumentParser(
        description='Run all VSCode log ingestors and build dataframes.'
    )
    parser.add_argument(
        '--root',
        default=get_default_root(),
        help='Root logs directory to scan.',
    )
    parser.add_argument(
        '--output-dir',
        default=os.getcwd(),
        help='Directory to write CSV and error log outputs.',
    )
    parser.add_argument(
        '--jupyter-joiner',
        default=' \\n ',
        help='String to join multiline Jupyter message lines into one field.',
    )
    args = parser.parse_args()

    output_dir = args.output_dir
    jupyter_csv = os.path.join(output_dir, 'exthost_output_logging_jupyter_messages.csv')
    codeql_csv = os.path.join(output_dir, 'codeql_messages.csv')

    df_logs, log_stats = ingest_logs.ingest_to_dataframe(
        args.root,
        error_log_path=None,
        output_dir=output_dir,
    )
    df_jupyter, jupyter_stats = ingest_jupyter_logs.ingest_to_dataframe(
        args.root,
        csv_path=jupyter_csv,
        joiner=args.jupyter_joiner,
    )
    df_codeql, codeql_stats = ingest_codeql_logs.ingest_to_dataframe(
        args.root,
        csv_path=codeql_csv,
    )

    print(f"INGEST_LOGS_ROWS: {len(df_logs)}")
    print(f"INGEST_JUPYTER_ROWS: {len(df_jupyter)}")
    print(f"INGEST_CODEQL_ROWS: {len(df_codeql)}")
    print(f"INGEST_LOGS_ROOTS: {len(log_stats)}")
    print(f"INGEST_JUPYTER_FILES: {jupyter_stats['files']}")
    print(f"INGEST_CODEQL_FILES: {codeql_stats['files']}")


if __name__ == '__main__':
    main()
