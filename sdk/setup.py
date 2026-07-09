from setuptools import setup, find_packages

setup(
    name="votal",
    version="0.1.0",
    description="Votal Shield SDK — RBAC + data policies for LLM agents",
    author="Votal AI",
    author_email="support@votal.ai",
    url="https://github.com/sundi133/llm-shield",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=["requests>=2.28"],
    extras_require={
        "langchain": ["langchain>=0.1", "langchain-openai>=0.1"],
        "openai": ["openai>=1.0"],
        "all": ["langchain>=0.1", "langchain-openai>=0.1", "openai>=1.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
)
