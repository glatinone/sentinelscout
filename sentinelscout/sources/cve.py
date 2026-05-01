"""NVD CVE feed scraper — no API key required."""
import httpx
from sentinelscout.models import IOCResult, Source, Severity
from sentinelscout.sources import BaseSource

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVESource(BaseSource):
    name = "nvd_cve"
    source = Source.CVE

    async def query(self, indicator: str) -> IOCResult:
        # indicator can be a CVE ID (CVE-YYYY-NNNNN) or keyword
        params = {"keywordSearch": indicator, "resultsPerPage": 5}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(NVD_API, params=params)
                r.raise_for_status()
                data = r.json()
                vulns = data.get("vulnerabilities", [])

            if not vulns:
                return IOCResult(source=self.source, indicator=indicator, found=False)

            items = []
            for v in vulns[:5]:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "?")
                desc = cve.get("descriptions", [{}])
                en_desc = next((d["value"] for d in desc if d.get("lang") == "en"), desc[0].get("value", ""))
                metrics = cve.get("metrics", {})
                cvss = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2", [])
                score = cvss[0]["cvssData"]["baseScore"] if cvss else 0.0
                sev = _score_to_severity(score)
                items.append(f"[{cve_id}] CVSS {score} — {en_desc[:120]}")

            summary = "\n".join(items)
            sev_list = []
            for cv in vulns:
                m = cv.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entry = m.get(key)
                    if entry:
                        sev_list.append(_score_to_severity(entry[0]["cvssData"]["baseScore"]))
                        break
            severity = max(sev_list, default=Severity.UNKNOWN)

            return IOCResult(
                source=self.source,
                indicator=indicator,
                found=True,
                severity=severity,
                confidence=0.9,
                summary=summary,
                raw_data={"cves": [v["cve"]["id"] for v in vulns]},
            )
        except Exception as e:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary=f"Error: {e}")


def _score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.UNKNOWN