from difflib import SequenceMatcher

LINK_POINTS = {
    "same_target": 50,
    "same_ip": 50,
    "similar_name": 25,
    "same_tag": 10,
}
SIMILAR_NAME_LEVEL = 0.7
LINK_THRESHOLD = 50


def is_ip(host):
    """Rough check: '1.2.3.4' is an IP, 'bad.com' is not."""
    return host.replace(".", "").isdigit()


def name_similarity(first_host, second_host):
    """How similar two domain names are, from 0.0 to 1.0 (IPs are not compared)."""
    if not first_host or not second_host:
        return 0
    if is_ip(first_host) or is_ip(second_host):
        return 0
    return SequenceMatcher(None, first_host, second_host).ratio()


def link_score(first, second):
    """Compare two URL reports. Return (score, evidence) showing how linked they are."""
    score = 0
    evidence = []
    first_ip = first.indicators.get("ip")
    first_host = first.indicators.get("host")
    second_host = second.indicators.get("host")

    if first.target == second.target:
        score += LINK_POINTS["same_target"]
        evidence.append("Same URL reported")

    if first_ip and first_ip == second.indicators.get("ip"):
        score += LINK_POINTS["same_ip"]
        evidence.append(f"Same IP address ({first_ip})")

    similarity = name_similarity(first_host, second_host)
    if first_host != second_host and similarity >= SIMILAR_NAME_LEVEL:
        score += LINK_POINTS["similar_name"]
        evidence.append(f"Similar domain names ({round(similarity * 100)}%)")

    shared_tags = set(first.tags()) & set(second.tags())
    if shared_tags:
        score += LINK_POINTS["same_tag"]
        evidence.append(f"Same threat tag ({', '.join(sorted(shared_tags))})")

    return min(score, 100), evidence


def suspicious_url_reports(reports):
    """Only URL reports that are not safe can be part of a campaign."""
    return list(filter(lambda report: report.scan_type == "url" and report.status != "safe", reports))


def collect_group(report, reports, group):
    """Recursively add every report linked to this one, directly or through others."""
    group.append(report)
    for other in reports:
        if other in group:
            continue
        score, _ = link_score(report, other)
        if score >= LINK_THRESHOLD:
            collect_group(other, reports, group)
    return group


def build_campaign(group):
    """Summarize a group: its reports, users, evidence and confidence."""
    evidence = []
    best = 0
    for index, first in enumerate(group):
        for second in group[index + 1:]:
            score, reasons = link_score(first, second)
            best = max(best, score)
            for reason in reasons:
                if reason not in evidence:
                    evidence.append(reason)
    return {
        "reports": group,
        "users": sorted(set(map(lambda report: report.user, group))),
        "evidence": evidence,
        "confidence": best,
    }


def find_campaigns(reports):
    """Group suspicious reports into campaigns of 2 or more linked reports."""
    candidates = suspicious_url_reports(reports)
    seen = []
    campaigns = []
    for report in candidates:
        if report in seen:
            continue
        group = collect_group(report, candidates, [])
        seen.extend(group)
        if len(group) >= 2:
            campaigns.append(build_campaign(group))
    return campaigns