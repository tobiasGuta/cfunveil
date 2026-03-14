from setuptools import setup, find_packages

setup(
    name="cfunveil",
    version="1.0.0",
    description="CloudFlare Origin IP Discovery Tool for Bug Bounty",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.0",
        "aiodns>=3.1.0",
        "shodan>=1.28.0",
        "click>=8.1.0",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "cfunveil=main:main",
        ],
    },
    python_requires=">=3.11",
)
