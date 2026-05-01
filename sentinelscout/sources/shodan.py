"""Shodan API client — requires SHODAN_API_KEY."""
import httpx
from sentinelscout.models import IOCResult, Source, Severity
from sentinelscout.sources import BaseSource
from sentinelscout import config


class ShodanSource(BaseSource):
    name = "shodan"
    source = Source.SHODAN

    async def query(self, indicator: str) -> IOCResult:
        if not config.SHODAN_API_KEY:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary="No API key configured")

        # Shodan only works with IPs
        if "." not in indicator or not all(p.isdigit() for p in indicator.split(".")):
            return IOCResult(source=self.source, indicator=indicator, found=False, summary="Shodan only supports IP addresses")

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"https://api.shodan.io/shodan/host/{indicator}", params={"key": config.SHODAN_API_KEY})
                if r.status_code == 404:
                    return IOCResult(source=self.source, indicator=indicator, found=False)
                r.raise_for_status()
                data = r.json()

            ports = data.get("ports", [])[:6]
            org = data.get("org", "N/A")
            isp = data.get("isp", "N/A")
            tags = ", ".join(data.get("tags", [])[:4]) or "none"

            summary = f"{len(ports)} open ports: {ports} | Org: {org} | ISP: {isp} | Tags: {tags}"
            return IOCResult(source=self.source, indicator=indicator, found=True, severity=Severity.MEDIUM, confidence=0.8, summary=summary, raw_data={"ports": ports})
        except Exception as e:
            return IOCResult(source=self.source, indicator=indicator, found=False, summary=f"Error: {e}")