"""GitHub Security Advisories scraper — no API key required."""
import httpx
from sentinelscout.models import IOCResult, Source, Severity
from sentinelscout.sources import BaseSource

GH_ADV_API = "https://api.github.com/advisories"


class GitHubAdvSource(BaseSource):
    name = "github_adv"
    source = Source.GITHUB_ADV

    async def query(self, indicator: str) -> IOCResult:
        try:
            async with httpx.AsyncClient(timeout=15, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}) as client:
                # Try searching by ecosystem + keyword
                r = await client.get(GH_ADV_API, params={"ecosystem": "pip", "keyword": indicator})
                if r.status_code == 422:
                    return IOCResult(source=self.source, indicator=indicator, found=False)
                if r.status_code == 404:
                    return IOCResult(source=self.source, indicator=indicator, found=False)
                r.raise_for_status()
                advisories = r.json()

            if not advisories:
                return IOCResult(source=self.source, indicator=indicator, found=False)

            items = []
            max_sev = Severity.UNKNOWN
            for adv in advisories[:5]:
                ghsa_id = adv.get("ghsa_id", "?")
                cve_id = adv.get("cve_id", "N/A")
                sev = _parse_severity(adv.get("severity", "unknown"))
                if sev.value > max_sev.value:
                    max_sev = sev
                desc = (adv.get("description", "") or "")[:120]
                items.append(f"[{ghsa_id}/{cve_id}] {sev.name} — {desc}")

            summary = "\n".join(items) if items else "No advisories found."
            return IOCResult(
                source=self.source,
                indicator=indicator,
                found=True,
                severity=max_sev,
                confidence=0.9,
                summary=summary,
                raw_data={"advisories": [a["ghsa_id"] for a in advisories]},
            )
        except Exception as e:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary=f"Error: {e}")


def _parse_severity(s: str) -> Severity:
    return {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}.get(
        s.lower(), Severity.UNKNOWN
    )