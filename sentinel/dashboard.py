def count_by(items, key_func):
    """Count items by a key. Example: {'url': 7, 'password': 2}."""
    counts = {}
    for item in items:
        key = key_func(item)
        counts[key] = counts.get(key, 0) + 1
    return counts


def top_items(counts, limit=3):
    """Return the biggest (name, count) pairs, largest first."""
    return sorted(counts.items(), key=lambda pair: pair[1], reverse=True)[:limit]


def build_stats(reports, cases):
    """Calculate every number the dashboard needs."""
    password_reports = list(filter(lambda report: report.scan_type == "password", reports))
    leaked = list(filter(lambda report: report.status == "danger", password_reports))
    tags = []
    for report in reports:
        tags.extend(report.tags())

    return {
        "total_reports": len(reports),
        "users": len(set(map(lambda report: report.user, reports))),
        "threats": len(list(filter(lambda report: report.is_dangerous(), reports))),
        "open_cases": len(list(filter(lambda case: case.status != "closed", cases))),
        "by_type": count_by(reports, lambda report: report.scan_type),
        "by_status": count_by(reports, lambda report: report.status),
        "top_reporters": top_items(count_by(reports, lambda report: report.user)),
        "top_tags": top_items(count_by(tags, lambda tag: tag)),
        "password_checks": len(password_reports),
        "leaked_passwords": len(leaked),
        "latest": sorted(reports, key=lambda report: report.created_at, reverse=True)[:3],
    }