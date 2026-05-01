"""VirusTotal API client — requires VIRUSTOTAL_API_KEY."""
import httpx
from sentinelscout.models import IOCResult, Source, Severity
from sentinelscout.sources import BaseSource
from sentinelscout import config


class VirusTotalSource(BaseSource):
    name = "virustotal"
    source = Source.VIRUSTOTAL

    async def query(self, indicator: str) -> IOCResult:
        if not config.VIRUSTOTAL_API_KEY:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary="No API key configured")

        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
        # VirusTotal v3: separate endpoints for ip/domain/hash
        if _looks_like_ip(indicator):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif _looks_like_hash(indicator):
            endpoint = f"https://www.virustotal.com/api/v3/files/{indicator}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{indicator}"

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(endpoint, headers=headers)
                if r.status_code == 404:
                    return IOCResult(source=self.source, indicator=indicator, found=False)
                r.raise_for_status()
                data = r.json().get("data", {}).get("attributes", {})

            last_analysis_stats = data.get("last_analysis_stats", {})
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            total = sum(last_analysis_stats.values())
            confidence = malicious / total if total else 0

            sev = Severity.CRITICAL if malicious > 50 else Severity.HIGH if malicious > 10 else Severity.MEDIUM if (malicious + suspicious) > 0 else Severity.LOW

            categories = data.get("categories", {})
            cat_str = ", ".join(list(categories.values())[:4]) or "none"

            summary = f"{malicious}/{total} engines flagged | Categories: {cat_str}"

            return IOCResult(
                source=self.source, indicator=indicator, found=True, severity=sev, confidence=confidence, summary=summary, raw_data=last_analysis_stats,
            )
        except Exception as e:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary=f"Error: {e}")


def _looks_like_ip(s: str) -> bool:
    return s.count(".") == 3 and all(p.isdigit() for p in s.split("."))


def _looks_like_hash(s: str) -> bool:
    return len(s) in (32, 40, 64, 128) and all(c in "0123456789abcdefABCDEF" for c in s)