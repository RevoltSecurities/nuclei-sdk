"""Basic async scan example using the nuclei-sdk Python client."""

import asyncio

from nucleisdk import ScanEngine


async def main():
    # Create engine with configuration
    engine = ScanEngine(
        rate_limit=100,
        timeout=10,
        no_interactsh=True,
        silent=True,
    )

    # One-time heavy initialization
    await engine.setup()

    # Lightweight scan — same engine, shared resources
    print("=== HTTP CVE Scan ===")
    async for result in engine.scan(
        targets=["https://go-yubi.com"],
        tags=["wordpress"],
        protocol_types="http",
    ):
        if result.error:
            print(f"  ERROR: {result.error}")
        else:
            print(f"  [{result.severity}] {result.template_id} - {result.matched_url}")

    # Another scan using the same engine (no re-initialization)
    print("\n=== SSL Scan ===")
    async for result in engine.scan(
        targets=["go-yubi.com:443"],
        protocol_types="ssl",
    ):
        if result.error:
            print(f"  ERROR: {result.error}")
        else:
            print(f"  [{result.severity}] {result.template_id}")

    await engine.close()
    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
