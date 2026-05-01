"""AI correlation engine — uses OpenAI to analyze and score IOCs."""
import httpx
from sentinelscout.models import AnalysisReport
from sentinelscout import config


async def analyze(report: AnalysisReport) -> AnalysisReport:
    if not config.OPENAI_API_KEY:
        report.ai_summary = "[AI analysis skipped — set OPENAI_API_KEY in .env to enable]"
        return report

    source_lines = "\n".join(
        f"- {r.source.value}: {r.summary or 'No data'}" for r in report.sources
    )
    prompt = (
        f"You are a threat intelligence analyst. Summarize and score the following IOC query results.\n"
        f"Indicator: {report.indicator}\n"
        f"Source results:\n{source_lines}\n\n"
        f"Provide: 1) A 2-3 sentence summary, 2) A threat score 0-100, 3) A severity label (LOW/MEDIUM/HIGH/CRITICAL)."
    )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {config.OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 300,
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            # Simple parse: expect "Summary:", "Score:", "Severity:" sections
            report.ai_summary = content.strip()
            # Try to extract numeric score
            for line in content.split("\n"):
                if "score" in line.lower() and any(c.isdigit() for c in line):
                    try:
                        report.threat_score = int("".join(filter(str.isdigit, line)))
                    except ValueError:
                        pass
    except Exception as e:
        report.ai_summary = f"[AI analysis failed: {e}]"

    return report