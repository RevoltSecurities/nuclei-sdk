"""ScanPool example — async continuous dynamic scanning from Python."""

import asyncio

from nucleisdk import ScanEngine, TemplateBytesEntry

# Simulated vulnerability feed items
vuln_feed = [
    {
        "target": "https://help.accumn.ai",
        "cve_id": "CVE-2024-1234",
        "template": b"""
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
""",
    },
    {
        "target": "https://help.accumn.ai",
        "cve_id": "CVE-2024-5678",
        "template": b"""
id: CVE-2024-5678
info:
  name: Example SSRF
  severity: high
  author: scanner
  tags: cve,ssrf
http:
  - method: GET
    path:
      - "{{BaseURL}}/webhook?url=http://169.254.169.254"
    matchers:
      - type: word
        words:
          - "ami-id"
""",
    },
]


async def main():
    # Setup engine once
    engine = ScanEngine(
        rate_limit=100,
        timeout=10,
        no_interactsh=True,
        silent=True,
    )
    await engine.setup()

    # Create pool with 5 workers
    pool = await engine.scan_pool(workers=5)

    # Consume results in background
    consumer = asyncio.create_task(consume_results(pool))

    # Submit jobs dynamically (simulating a vuln feed)
    for item in vuln_feed:
        await pool.submit(
            label=item["cve_id"],
            targets=[item["target"]],
            template_bytes=[
                TemplateBytesEntry(name=item["cve_id"], data=item["template"])
            ],
        )
        print(f"Submitted: {item['cve_id']} -> {item['target']}")

    # Also submit a filter-based scan
    await pool.submit(
        label="Tech scan",
        targets=["https://www.aspero.in/"],
        tags=["tech"],
        protocol_types="http",
    )
    print("Submitted: Tech scan")

    # Close pool (waits for all jobs to finish)
    await pool.close()

    # Wait for result consumer
    await consumer

    # Print stats
    stats = await pool.stats()
    print(f"\n--- Pool Stats ---")
    print(f"  Submitted: {stats.submitted}")
    print(f"  Completed: {stats.completed}")
    print(f"  Failed:    {stats.failed}")
    print(f"  Pending:   {stats.pending}")

    await engine.close()


async def consume_results(pool):
    """Read and print results from the pool."""
    async for lr in pool.results():
        r = lr.result
        if r.error:
            print(f"  [{lr.label}] ERROR: {r.error}")
        else:
            print(f"  [{lr.label}] [{r.severity}] {r.template_id} - {r.matched_url}")


if __name__ == "__main__":
    asyncio.run(main())
