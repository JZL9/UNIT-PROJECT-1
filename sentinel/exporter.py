import os

from sentinel.models import now_text

EXPORT_FOLDER = "reports"
LINE = "-" * 50


def write_file(filename, lines):
    """Save the lines into a text file inside the reports folder. Return its path."""
    os.makedirs(EXPORT_FOLDER, exist_ok=True)
    path = os.path.join(EXPORT_FOLDER, filename)
    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))
    return path


def export_case(case, reports):
    """Write a full report for one case. Return the file path."""
    linked = list(filter(lambda report: report.report_id in case.report_ids, reports))
    lines = [
        "SENTINELCLI — CASE REPORT",
        "=" * 50,
        f"Case:      #{case.case_id} — {case.title}",
        f"Status:    {case.status}",
        f"Created:   {case.created_at}",
        f"Exported:  {now_text()}",
        f"Avg risk:  {case.average_risk(reports)}/100",
        "",
        "NOTES",
        LINE,
    ]
    lines.extend(map(lambda note: f"- {note}", case.notes or ["(no notes)"]))
    lines.extend(["", f"LINKED REPORTS ({len(linked)})", LINE])

    for report in linked:
        lines.append(f"#{report.report_id} | {report.created_at} | {report.user} | "
                     f"{report.scan_type} | risk {report.risk}/100")
        lines.append(f"   Target:  {report.target}")
        lines.append(f"   Summary: {report.summary}")
        lines.extend(map(lambda detail: f"   {detail}", report.details))
        lines.append("")

    return write_file(f"case_{case.case_id}_{now_text()[:10]}.txt", lines)


def export_summary(stats):
    """Write a summary of the whole system using the dashboard stats. Return the file path."""
    lines = [
        "SENTINELCLI — SECURITY SUMMARY",
        "=" * 50,
        f"Exported:      {now_text()}",
        f"Users:         {stats['users']}",
        f"Reports:       {stats['total_reports']}",
        f"Threats:       {stats['threats']}",
        f"Open cases:    {stats['open_cases']}",
        "",
        "REPORTS BY TYPE",
        LINE,
    ]
    lines.extend(map(lambda pair: f"- {pair[0]}: {pair[1]}", stats["by_type"].items()))
    lines.extend(["", "RISK LEVELS", LINE])
    lines.extend(map(lambda pair: f"- {pair[0]}: {pair[1]}", stats["by_status"].items()))
    lines.extend(["", "MOST ACTIVE REPORTERS", LINE])
    lines.extend(map(lambda pair: f"- {pair[0]}: {pair[1]} report(s)", stats["top_reporters"]))

    if stats["password_checks"]:
        lines.extend(["", "PASSWORDS", LINE,
                      f"- {stats['leaked_passwords']} of {stats['password_checks']} checked passwords were leaked"])

    return write_file(f"summary_{now_text()[:10]}.txt", lines)