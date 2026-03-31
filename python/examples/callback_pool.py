"""ScanPool with on_result callback — no manual iteration needed."""

import asyncio

from nucleisdk import ScanEngine, TemplateBytesEntry


async def main():
    findings = []

    async def on_result(lr):
        """Called automatically for each pool result."""
        r = lr.result
        if r.error:
            print(f"  [{lr.label}] ERROR: {r.error}")
        else:
            print(f"  [{lr.label}] [{r.severity}] {r.template_id} - {r.matched_url}")
            if r.is_high_or_above():
                findings.append(lr)

    async with ScanEngine(rate_limit=100, no_interactsh=True, silent=True) as engine:
        # Callback mode — results dispatched automatically
        pool = await engine.scan_pool(workers=5, on_result=on_result)

        # Submit scans dynamically
        await pool.submit(
            "CVE-2024-1234",
            targets=["https://target-a.example.com"],
            template_bytes=[TemplateBytesEntry("CVE-2024-1234", b"""
id: CVE-2024-1234
info:
  name: Example RCE
  severity: critical
  author: scanner
  tags: cve,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/debug"
    matchers:
      - type: word
        words:
          - "stack trace"
""")],
        )

        await pool.submit(
            "wordpress-scan",
            targets=["https://wordpress.example.com"],
            tags=["wordpress"],
            protocol_types="http",
        )

        # Close waits for all jobs to finish; callback fires for each result
        await pool.close()

        stats = await pool.stats()
        print(f"\nPool stats: {stats.submitted} submitted, {stats.completed} completed")
        print(f"High+ findings: {len(findings)}")


if __name__ == "__main__":
    asyncio.run(main())
