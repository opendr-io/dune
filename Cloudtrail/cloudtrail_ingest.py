import argparse
import csv
import gc
import gzip
import io
import json
import os
import pathlib
import re
import sys
import time
from argparse import Namespace
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse
import pandas as pd

try:
    import boto3
    from botocore.exceptions import ClientError
except ModuleNotFoundError as err:
    boto3 = None
    BOTO3_IMPORT_ERROR = err

    class ClientError(Exception):
        pass
else:
    BOTO3_IMPORT_ERROR = None


TOKEN_EXPIRED_CODES = {"ExpiredToken", "InvalidToken", "TokenRefreshRequired"}
DEFAULT_SELECT_COLS_FILE = pathlib.Path(__file__).with_name("cloudtrail_select_cols.txt")


def require_boto3():
    if boto3 is None:
        raise RuntimeError(
            "boto3 is required for S3 ingest. Install it in this Python environment "
            "or run the script on the AWS node where boto3 is available."
        ) from BOTO3_IMPORT_ERROR


def parse_s3_uri(s3_uri):
    parsed = urlparse(s3_uri.rstrip("/"))
    if parsed.scheme != "s3" or not parsed.netloc:
        raise ValueError(f"Invalid S3 URI: {s3_uri}")
    prefix = parsed.path.lstrip("/")
    return parsed.netloc, (prefix + "/") if prefix else ""


def iter_s3_objects(s3_client, bucket, prefix):
    continuation_token = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token
        page = s3_client.list_objects_v2(**kwargs)
        yield from page.get("Contents", [])
        if not page.get("IsTruncated"):
            break
        continuation_token = page.get("NextContinuationToken")


def date_from_s3_key(key):
    parts = key.split("/")
    for i in range(len(parts) - 2):
        year, month, day = parts[i : i + 3]
        if (
            len(year) == 4
            and year.isdigit()
            and len(month) == 2
            and month.isdigit()
            and len(day) == 2
            and day.isdigit()
        ):
            return f"{year}-{month}-{day}"
    return "unknown"


def account_id_from_prefix(prefix):
    parts = [part for part in prefix.split("/") if part]
    if len(parts) > 1 and parts[0] == "AWSLogs":
        return parts[1]
    return "unknown"


def safe_filename_part(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def get_field(record, field):
    value = record
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def extract_fields(record, select_cols):
    if not select_cols:
        return record
    result = {}
    for field in select_cols:
        val = get_field(record, field)
        if isinstance(val, (dict, list)):
            val = json.dumps(val, default=str)
        result[field] = val
    return result


def load_select_cols(path):
    cols = []
    path = pathlib.Path(path)
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cols.append(line)
    if not cols:
        raise ValueError(f"No selected columns found in {path}")
    return cols


def normalize_filter_pair(event_source, event_name):
    event_source = (event_source or "").strip()
    event_name = (event_name or "").strip()
    if not event_source or not event_name:
        return None
    return event_source, event_name


def record_matches_filter(record, filter_pairs):
    if not filter_pairs:
        return False
    return (record.get("eventSource"), record.get("eventName")) in filter_pairs


def load_filter_file(path):
    filter_pairs = set()
    if not path:
        return filter_pairs

    path = pathlib.Path(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [line for line in handle if line.strip() and not line.lstrip().startswith("#")]

    if not rows:
        return filter_pairs

    sample = "".join(rows[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t")
    except csv.Error:
        dialect = csv.excel

    reader = csv.reader(rows, dialect)
    first_row = next(reader, None)
    if first_row is None:
        return filter_pairs

    first_normalized = [cell.strip().lower().replace(" ", "") for cell in first_row]
    has_header = "eventsource" in first_normalized and "eventname" in first_normalized
    if has_header:
        source_idx = first_normalized.index("eventsource")
        name_idx = first_normalized.index("eventname")
    else:
        source_idx = 0
        name_idx = 1
        pair = normalize_filter_pair(
            first_row[source_idx] if len(first_row) > source_idx else None,
            first_row[name_idx] if len(first_row) > name_idx else None,
        )
        if pair:
            filter_pairs.add(pair)

    for row in reader:
        pair = normalize_filter_pair(
            row[source_idx] if len(row) > source_idx else None,
            row[name_idx] if len(row) > name_idx else None,
        )
        if pair:
            filter_pairs.add(pair)

    return filter_pairs


def objects_by_day(objects):
    grouped = {}
    for obj in objects:
        grouped.setdefault(date_from_s3_key(obj["Key"]), []).append(obj)
    return grouped


def output_path_for_day(output_dir, account_id, day, output_format):
    date_part = day.replace("-", "_")
    suffix = {"parquet": ".parquet", "pickle": ".pkl", "csv": ".csv"}[output_format]
    name = f"cloudtrail_{safe_filename_part(account_id)}_{date_part}{suffix}"
    return pathlib.Path(output_dir) / name


def write_frame(frame, path, output_format):
    path = pathlib.Path(path)
    tmp_path = path.with_name(path.name + ".tmp")
    if output_format == "parquet":
        frame.to_parquet(tmp_path, index=False)
    elif output_format == "pickle":
        frame.to_pickle(tmp_path)
    elif output_format == "csv":
        frame.to_csv(tmp_path, index=False)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
    os.replace(tmp_path, path)


def read_frame(path, output_format):
    if output_format == "parquet":
        return pd.read_parquet(path)
    if output_format == "pickle":
        return pd.read_pickle(path)
    if output_format == "csv":
        return pd.read_csv(path)
    raise ValueError(f"Unsupported output format: {output_format}")


def load_cloudtrail_day(task):
    require_boto3()
    bucket = task["bucket"]
    day = task["day"]
    day_objects = task["objects"]
    region_name = task["region_name"]
    select_cols = task["select_cols"]
    filter_pairs = task["filter_pairs"]
    datetime_col = task["datetime_col"]
    output_path = task["output_path"]
    output_format = task["output_format"]

    s3 = boto3.client("s3", region_name=region_name)
    chunks = []
    files = 0
    rows = 0
    compressed_bytes = 0
    download_seconds = 0.0
    parse_seconds = 0.0
    start = time.perf_counter()

    for obj in day_objects:
        key = obj["Key"]
        compressed_bytes += int(obj.get("Size", 0))
        t0 = time.perf_counter()
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        download_seconds += time.perf_counter() - t0

        t1 = time.perf_counter()
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
            payload = json.loads(gz.read().decode("utf-8"))

        file_rows = []
        for record in payload.get("Records", []):
            if record_matches_filter(record, filter_pairs):
                continue
            file_rows.append(extract_fields(record, select_cols) if select_cols else record)

        if file_rows:
            if select_cols:
                chunk = pd.DataFrame.from_records(file_rows, columns=select_cols)
            else:
                chunk = pd.json_normalize(file_rows, sep=".")
            rows += len(chunk)
            chunks.append(chunk)

        parse_seconds += time.perf_counter() - t1
        files += 1
        del body, payload, file_rows
        gc.collect()

    if chunks:
        day_frame = pd.concat(chunks, ignore_index=True)
    else:
        day_frame = pd.DataFrame(columns=select_cols or None)

    if datetime_col in day_frame.columns:
        day_frame[datetime_col] = pd.to_datetime(day_frame[datetime_col], utc=True, errors="coerce")

    write_frame(day_frame, output_path, output_format)
    elapsed = time.perf_counter() - start
    del day_frame, chunks
    gc.collect()

    return {
        "day": day,
        "output_path": str(output_path),
        "files": files,
        "rows": rows,
        "compressed_bytes": compressed_bytes,
        "elapsed_seconds": elapsed,
        "download_seconds": download_seconds,
        "parse_seconds": parse_seconds,
    }


def list_cloudtrail_objects(s3_uri, region_name):
    require_boto3()
    bucket, prefix = parse_s3_uri(s3_uri)
    s3 = boto3.client("s3", region_name=region_name)
    objects = [
        {"Key": obj["Key"], "Size": obj["Size"]}
        for obj in iter_s3_objects(s3, bucket, prefix)
        if obj["Key"].endswith(".json.gz")
    ]
    return bucket, prefix, objects


def print_identity(region_name):
    require_boto3()
    sts = boto3.client("sts", region_name=region_name)
    ident = sts.get_caller_identity()
    print(f"AWS identity: account={ident.get('Account')} arn={ident.get('Arn')}")


def print_day_plan(grouped):
    total_files = sum(len(objs) for objs in grouped.values())
    total_bytes = sum(obj["Size"] for objs in grouped.values() for obj in objs)
    print(f"Found {total_files:,} CloudTrail files")
    print(f"Total compressed size: {total_bytes:,} bytes ({total_bytes / 1024 ** 2:.2f} MB)")
    for day, objs in sorted(grouped.items()):
        day_bytes = sum(obj["Size"] for obj in objs)
        print(f"  {day}: {len(objs):,} files, {day_bytes / 1024 ** 2:.2f} MB")


def merge_outputs(output_paths, output_format, merge_output):
    frames = [read_frame(path, output_format) for path in output_paths]
    if not frames:
        raise ValueError("No completed day outputs to merge.")
    merged = pd.concat(frames, ignore_index=True)
    merge_output = pathlib.Path(merge_output)
    merge_format = merge_output.suffix.lower().lstrip(".")
    if merge_format in {"parquet", "pq"}:
        merged.to_parquet(merge_output, index=False)
    elif merge_format in {"pkl", "pickle"}:
        merged.to_pickle(merge_output)
    elif merge_format == "csv":
        merged.to_csv(merge_output, index=False)
    else:
        raise ValueError("Merge output extension must be .parquet, .pkl, or .csv")
    print(f"Merged {len(frames):,} day files into {merge_output} ({len(merged):,} rows)")


def parse_worker_counts(value):
    if not value:
        return None
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def run_once(args, worker_count):
    bucket, prefix, objects = list_cloudtrail_objects(args.s3_uri, args.region)
    account_id = args.account_id or account_id_from_prefix(prefix)
    grouped = objects_by_day(objects)
    print_day_plan(grouped)
    select_cols = load_select_cols(args.select_cols_file) if args.select_cols else None
    if select_cols:
        print(f"Selecting {len(select_cols):,} column(s) from {args.select_cols_file}")
    filter_pairs = load_filter_file(args.filter_file)
    cli_filter_pair = normalize_filter_pair(args.filter_event_source, args.filter_event_name)
    if cli_filter_pair:
        filter_pairs.add(cli_filter_pair)
    if filter_pairs:
        print(f"Dropping records matching {len(filter_pairs):,} eventSource/eventName filter pair(s)")

    output_dir = pathlib.Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    completed_paths = []
    tasks = []
    for day, day_objects in sorted(grouped.items()):
        output_path = output_path_for_day(output_dir, account_id, day, args.output_format)
        if output_path.exists() and not args.overwrite:
            print(f"Skipping {day}: {output_path} already exists")
            completed_paths.append(output_path)
            continue
        tasks.append(
            {
                "bucket": bucket,
                "day": day,
                "objects": day_objects,
                "region_name": args.region,
                "select_cols": select_cols,
                "filter_pairs": filter_pairs,
                "datetime_col": "eventTime",
                "output_path": str(output_path),
                "output_format": args.output_format,
            }
        )

    if not tasks:
        print("All day outputs already exist.")
        if args.merge_output:
            merge_outputs(sorted(completed_paths), args.output_format, args.merge_output)
        return {
            "workers": worker_count,
            "days_total": len(grouped),
            "days_skipped": len(completed_paths),
            "days_attempted": 0,
            "days_completed": 0,
            "rows": 0,
            "files": 0,
            "compressed_bytes": 0,
            "compressed_mb": 0.0,
            "elapsed_seconds": 0.0,
            "mb_per_second": None,
            "seconds_per_completed_day": None,
            "files_per_second": None,
            "rows_per_second": None,
            "download_seconds": 0.0,
            "parse_seconds": 0.0,
            "stopped_early": False,
        }

    print(f"Loading {len(tasks):,} days with {worker_count:,} process worker(s)")
    start = time.perf_counter()
    results = []
    stopped_early = False

    with ProcessPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(load_cloudtrail_day, task): task["day"] for task in tasks}
        for future in as_completed(futures):
            day = futures[future]
            try:
                result = future.result()
            except ClientError as err:
                code = err.response.get("Error", {}).get("Code")
                if code in TOKEN_EXPIRED_CODES:
                    print(f"Token expired while loading {day}; completed day files remain on disk.")
                    stopped_early = True
                    for pending in futures:
                        pending.cancel()
                    break
                raise
            results.append(result)
            completed_paths.append(pathlib.Path(result["output_path"]))
            mb = result["compressed_bytes"] / 1024 ** 2
            print(
                f"  {day} complete: {result['rows']:,} rows, {result['files']:,} files, "
                f"{mb:.2f} MB, {result['elapsed_seconds']:.1f}s"
            )

    elapsed = time.perf_counter() - start
    rows = sum(result["rows"] for result in results)
    files = sum(result["files"] for result in results)
    compressed_bytes = sum(result["compressed_bytes"] for result in results)
    mb = compressed_bytes / 1024 ** 2
    mb_s = mb / elapsed if elapsed > 0 else 0.0
    print(
        f"Run complete: {len(results):,}/{len(tasks):,} new days, {rows:,} rows, "
        f"{files:,} files, {mb:.2f} MB in {elapsed:.1f}s ({mb_s:.3f} MB/s)"
    )
    if stopped_early:
        print("Refresh credentials and rerun the same command to resume.")
    elif args.merge_output:
        merge_outputs(sorted(completed_paths), args.output_format, args.merge_output)

    return {
        "workers": worker_count,
        "days_total": len(grouped),
        "days_skipped": len([path for path in completed_paths if pathlib.Path(path).exists()]) - len(results),
        "days_attempted": len(tasks),
        "days_completed": len(results),
        "rows": rows,
        "files": files,
        "compressed_bytes": compressed_bytes,
        "compressed_mb": mb,
        "elapsed_seconds": elapsed,
        "mb_per_second": mb_s,
        "seconds_per_completed_day": elapsed / len(results) if results else None,
        "files_per_second": files / elapsed if elapsed > 0 else None,
        "rows_per_second": rows / elapsed if elapsed > 0 else None,
        "download_seconds": sum(result["download_seconds"] for result in results),
        "parse_seconds": sum(result["parse_seconds"] for result in results),
        "stopped_early": stopped_early,
    }


def build_parser():
    parser = argparse.ArgumentParser(description="Ingest CloudTrail .json.gz files from S3 by day.")
    parser.add_argument("--s3-uri", required=True, help="CloudTrail S3 prefix, for example s3://bucket/AWSLogs/.../CloudTrail/us-east-1/2026/04")
    parser.add_argument("--region", default="us-east-1", help="AWS client region")
    parser.add_argument("--workers", type=int, default=10, help="Process workers for day-level parallelism")
    parser.add_argument("--benchmark-workers", help="Comma-separated worker counts to run, for example 3,10,20,30")
    parser.add_argument("--benchmark-report", help="Optional CSV path for aggregate benchmark results")
    parser.add_argument("--output-dir", default=str(pathlib.Path(__file__).with_name("cloudtrail_days")))
    parser.add_argument("--output-format", choices=["parquet", "pickle", "csv"], default="parquet")
    parser.add_argument("--merge-output", help="Optional merged output path ending in .parquet, .pkl, or .csv")
    parser.add_argument("--account-id", help="Override account ID used in output filenames")
    parser.add_argument(
        "--select-cols-file",
        default=str(DEFAULT_SELECT_COLS_FILE),
        help="Text file of selected CloudTrail columns, one field per line. Blank lines and # comments are ignored.",
    )
    parser.add_argument("--filter-event-source")
    parser.add_argument("--filter-event-name")
    parser.add_argument(
        "--filter-file",
        help=(
            "CSV/TSV file of eventSource,eventName pairs to drop during ingest. "
            "Header row is optional; lines starting with # are ignored."
        ),
    )
    parser.add_argument("--no-select-cols", dest="select_cols", action="store_false", help="Keep full normalized records instead of selected columns")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing day output files")
    parser.add_argument("--no-identity", action="store_true", help="Skip sts:GetCallerIdentity check")
    parser.set_defaults(select_cols=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.no_identity:
        print_identity(args.region)

    worker_counts = parse_worker_counts(args.benchmark_workers) or [args.workers]
    summaries = []
    for worker_count in worker_counts:
        run_args = args
        if len(worker_counts) > 1:
            print("")
            print(f"Benchmark run: {worker_count} workers")
            run_args = Namespace(**vars(args))
            run_args.output_dir = str(pathlib.Path(args.output_dir) / f"workers_{worker_count}")
            run_args.merge_output = None
        summary = run_once(run_args, worker_count)
        summaries.append(summary)

    if len(worker_counts) > 1 and summaries:
        report = pd.DataFrame(summaries)
        report.insert(0, "completed_at_utc", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        print("")
        print("Benchmark summary:")
        cols = [
            "workers",
            "days_completed",
            "days_attempted",
            "rows",
            "files",
            "compressed_mb",
            "elapsed_seconds",
            "seconds_per_completed_day",
            "mb_per_second",
            "files_per_second",
            "rows_per_second",
            "download_seconds",
            "parse_seconds",
            "stopped_early",
        ]
        print(report.reindex(columns=cols).to_string(index=False))
        if args.benchmark_report:
            path = pathlib.Path(args.benchmark_report)
            path.parent.mkdir(parents=True, exist_ok=True)
            report.to_csv(path, index=False)
            print(f"Benchmark report written to {path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted; completed day output files remain on disk.", file=sys.stderr)
        raise
