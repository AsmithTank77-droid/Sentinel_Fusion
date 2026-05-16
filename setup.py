"""
setup.py — Sentinel Fusion package definition.

Install in editable mode for local development:
    pip install -e .

This registers the `sentinel` CLI command globally so you can run it
from any directory without specifying the full module path.
"""

from setuptools import find_namespace_packages, setup

setup(
    name="sentinel-fusion",
    version="1.0.0",
    description="SOC-grade detection, correlation, and reporting platform.",
    packages=find_namespace_packages(),
    python_requires=">=3.12",
    install_requires=[
        "fastapi==0.136.1",
        "uvicorn[standard]==0.46.0",
        "pydantic==2.13.4",
        "pydantic-settings==2.14.1",
        "typer==0.25.1",
        "rich==15.0.0",
        "aiofiles==24.1.0",
    ],
    extras_require={
        "dev": [
            "httpx==0.28.1",
            "pytest==9.0.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "sentinel=interface.cli:main_entry",
        ],
    },
)
