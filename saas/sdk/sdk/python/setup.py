"""DevGuard Python SDK Setup"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="devguard",
    version="0.1.0",
    author="DevGuard",
    author_email="support@devguard.ai",
    description="AI Safety & Team Controls for Small Dev Teams",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/devguard/devguard-python",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Scientific/Engineering :: Artificial Intelligence"
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-asyncio>=0.21.0",
            "black>=22.0",
            "isort>=5.0",
            "flake8>=4.0"
        ],
        "openai": [
            "openai>=1.0.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "devguard=devguard.cli:main",
        ],
    },
)