"""Setup script for bot-signer-oversight."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bot-signer-oversight",
    version="0.1.0",
    author="Shiloh Heurich",
    author_email="sheurich@fastly.com",
    description="Multi-format keyless signing using OIDC",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "python-gnupg>=0.5.1",
        "PyYAML>=6.0",
        "requests>=2.31.0",
        "click>=8.1.0",
    ],
    entry_points={
        "console_scripts": [
            "signer=signer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
