from sentinel.scanners.base import Scanner


def combine_results(reputation, website):
    """Merge the URLhaus result and the website inspection into one final result."""
    high = max(reputation["risk"], website["risk"])
    low = min(reputation["risk"], website["risk"])
    risk = min(100, high + low // 2)

    stronger = reputation if reputation["risk"] > website["risk"] else website

    details = [f"🗂️ Reputation: {reputation['summary']}"]
    details.extend(reputation.get("details", []))
    details.extend(website.get("details", []))

    return {
        "status": Scanner.status_from_risk(risk),
        "risk": risk,
        "summary": stronger["summary"],
        "details": details,
        "advice": stronger["advice"],
        "indicators": website.get("indicators", {}),
    }