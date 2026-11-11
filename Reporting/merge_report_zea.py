import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, time
from decimal import Decimal, InvalidOperation
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font


ACTIVE_STATES = ("ACTIVE_ON", "ACTIVE_SIL")
TEST_PATTERN = re.compile(r"(?P<date>\d{8})_test\.csv$", re.IGNORECASE)
HISTORY_PATTERN = re.compile(r"ults_history_(?P<date>\d{8})T.*\.csv$", re.IGNORECASE)


def read_csv(path, required_columns):
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        missing = set(required_columns) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path.name} is missing columns: {', '.join(sorted(missing))}")
        return list(reader)


def resolve_input_files(test_file, history_file, folder):
    if test_file is not None or history_file is not None:
        if test_file is None or history_file is None:
            raise ValueError("Provide both the test CSV and the history CSV.")
        return test_file.resolve(), history_file.resolve()

    tests = {}
    for path in folder.glob("*_test.csv"):
        match = TEST_PATTERN.fullmatch(path.name)
        if match:
            tests.setdefault(match.group("date"), []).append(path)

    histories = defaultdict(list)
    for path in folder.glob("ults_history_*.csv"):
        match = HISTORY_PATTERN.fullmatch(path.name)
        if match:
            histories[match.group("date")].append(path)

    dates = sorted(set(tests) & set(histories))
    if len(dates) != 1:
        raise ValueError(
            f"Expected exactly one matching date pair in {folder}, found {len(dates)}. "
            "Specify both input file paths to select a pair."
        )

    date = dates[0]
    if len(tests[date]) != 1 or len(histories[date]) != 1:
        raise ValueError(
            f"Found multiple input files for {date}. Specify the test and history CSV paths."
        )
    return tests[date][0].resolve(), histories[date][0].resolve()


def report_date(test_file, history_file):
    test_match = TEST_PATTERN.fullmatch(test_file.name)
    history_match = HISTORY_PATTERN.fullmatch(history_file.name)
    dates = {
        match.group("date")
        for match in (test_match, history_match)
        if match is not None
    }
    if len(dates) != 1:
        raise ValueError("Input filenames must contain the same YYYYMMDD date.")
    return datetime.strptime(dates.pop(), "%Y%m%d").date()


def get_operators(history_file, report_day):
    rows = read_csv(
        history_file,
        ("MACHINE_NAME", "operator_name", "reported_at"),
    )
    window_start = datetime.combine(report_day, time(9, 50))
    window_end = datetime.combine(report_day, time(10, 10))
    operators = {}
    for row in rows:
        try:
            reported_at = datetime.fromisoformat(row["reported_at"])
        except ValueError as error:
            raise ValueError(
                f"Invalid reported_at value in {history_file.name}: {row['reported_at']!r}"
            ) from error
        if window_start <= reported_at < window_end:
            machine = row["MACHINE_NAME"].strip()
            previous = operators.get(machine)
            if previous is None or reported_at > previous[0]:
                operators[machine] = (reported_at, row["operator_name"].strip())
    return {machine: operator for machine, (_, operator) in operators.items()}


def get_active_rows(test_file):
    rows = read_csv(
        test_file,
        ("tag", "state", "start", "end", "duration"),
    )
    by_tag = defaultdict(list)
    for row in rows:
        if row["state"].strip() in ACTIVE_STATES:
            by_tag[row["tag"].strip()].append(row)
    return by_tag


def aggregate_tag(tag, rows, operators):
    states = [state for state in ACTIVE_STATES if any(row["state"].strip() == state for row in rows)]
    starts = [row["start"].strip() for row in rows if row["start"].strip()]
    ends = [row["end"].strip() for row in rows if row["end"].strip()]
    durations = [row["duration"].strip() for row in rows if row["duration"].strip()]

    duration = ""
    if durations:
        try:
            duration = f"{sum((Decimal(value) for value in durations), Decimal('0')):.3f}"
        except InvalidOperation as error:
            raise ValueError(f"Invalid duration for tag {tag}") from error

    return {
        "tag": tag,
        "state": "|".join(states),
        "start": min(starts) if starts else "",
        "end": max(ends) if ends else "",
        "duration": duration,
        "operator": operators.get(tag, ""),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Merge Minetec and UGTRM CSV files into an Excel report."
    )
    parser.add_argument(
        "test_csv",
        nargs="?",
        type=Path,
        help="Minetec CSV (e.g. 20261111_test.csv); omit to auto-detect in the current folder.",
    )
    parser.add_argument(
        "history_csv",
        nargs="?",
        type=Path,
        help="UGTRM history CSV (e.g. ults_history_20261111T100000.csv).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output XLSX path. By default, create the report beside the test CSV.",
    )
    args = parser.parse_args()

    test_file, history_file = resolve_input_files(
        args.test_csv,
        args.history_csv,
        Path.cwd(),
    )
    report_day = report_date(test_file, history_file)
    output_file = args.output.resolve() if args.output else test_file.parent / (
        f"report_{report_day:%Y%m%d}_0950-1010_merged.xlsx"
    )
    if output_file.suffix.lower() != ".xlsx":
        raise ValueError("Output file must use the .xlsx extension.")

    operators = get_operators(history_file, report_day)
    by_tag = get_active_rows(test_file)
    fields = ("tag", "state", "start", "end", "duration", "operator")

    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Report"
    worksheet.append(fields)
    for cell in worksheet[1]:
        cell.font = Font(bold=True)

    for tag in sorted(by_tag):
        row = aggregate_tag(tag, by_tag[tag], operators)
        worksheet.append([row[field] for field in fields])

    worksheet.freeze_panes = "A2"
    worksheet.auto_filter.ref = worksheet.dimensions
    for column, width in {"A": 16, "B": 24, "C": 22, "D": 22, "E": 14, "F": 22}.items():
        worksheet.column_dimensions[column].width = width
    workbook.save(output_file)

    unmatched = sum(tag not in operators for tag in by_tag)
    print(f"Report created: {output_file}")
    print(f"Unique tags: {len(by_tag)}")
    print(f"Tags without an operator match: {unmatched}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
