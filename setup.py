from setuptools import setup, find_packages

setup(
    name="reconx",
    version="3.0.0",
    description="AI-powered web pentest toolkit - CLI + GUI + AI mentor",
    author="darkvict0r",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "httpx[http2]>=0.27.0",
        "rich>=13.0.0",
        "fastapi>=0.110.0",
        "uvicorn>=0.29.0",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "reconx=reconx.cli:main",
        ],
    },
)