"""
CyberDefense Package Entry Point
================================
Executed when running `python -m cyberdefense` or `uv run python -m cyberdefense`.
"""

import sys
import asyncio
import uvicorn
from cyberdefense.config import settings, setup_logging

if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

def main():
    setup_logging(settings)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    print("=" * 64)
    print("[CyberDefense] Starting Autonomous SOAR-Lite Platform...")
    print(f"[Dashboard] Available at: http://{settings.dashboard.host}:{settings.dashboard.port}")
    print(f"[AI Analyst] Configured LLM Provider: {settings.llm.provider.upper()}")
    print("=" * 64)
    uvicorn.run(
        "cyberdefense.server:app",
        host=settings.dashboard.host,
        port=settings.dashboard.port,
        reload=False,
        loop="asyncio",
    )

if __name__ == "__main__":
    main()
