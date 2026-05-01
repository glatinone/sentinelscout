"""AlienVault OTX API client — requires ALIENVAULT_API_KEY."""
import httpx
from sentinelscout.models import IOCResult, Source, Severity
from sentinelscout.sources import BaseSource
from sentinelscout import config


class AlienVaultSource(BaseSource):
    name = "alienvault"
    source = Source.ALIENVAULT

    async def query(self, indicator: str) -> IOCResult:
        if not config.ALIENVAULT_API_KEY:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary="No API key configured")

        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{_type_for_indicator(indicator)}/{indicator}"
        headers = {"X-OTX-API-KEY": config.ALIENVAULT_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(endpoint, headers=headers)
                if r.status_code == 404:
                    return IOCResult(source=self.source, indicator=indicator, found=False)
                r.raise_for_status()
                data = r.json()

            pulses = data.get("pulse_info", {}).get("pulses", [])
            if not pulses:
                return IOCResult(source=self.source, indicator=indicator, found=False)

            tags = []
            related_ips = []
            for p in pulses[:5]:
                tags.extend(p.get("tags", [])[:3])
                for ind in p.get("indicators", []):
                    if ind.get("type") == "IPv4":
                        related_ips.append(ind["indicator"])
            tags = list(dict.fromkeys(tags))[:6]

            sev = Severity.HIGH if len(pulses) >= 3 else Severity.MEDIUM if pulses else Severity.LOW
            summary = f"{len(pulses)} pulse(s) | Tags: {', '.join(tags) or 'none'} | Related IPs: {', '.join(related_ips[:3]) or 'none'}"

            return IOCResult(source=self.source, indicator=indicator, found=True, severity=sev, confidence=0.85, summary=summary, raw_data={"pulses": len(pulses)})
        except Exception as e:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary=f"Error: {e}")


def _type_for_indicator(indicator: str) -> str:
    if indicator.count(".") == 3 and all(p.isdigit() for p in indicator.split(".")):
        return "IPv4"
    if len(indicator) in (32, 40, 64, 128) and all(c in "0123456789abcdefABCDEF" for c in indicator.lower()):
        return "filehash-md5"
    return "domain"