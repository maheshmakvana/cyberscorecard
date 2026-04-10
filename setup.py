from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cyberscorecard",
    version="1.0.0",
    author="",
    description="SMB cybersecurity governance scorecard — CIS Controls v8 assessment, risk findings, maturity scoring, and remediation roadmap for small businesses",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cyberscorecard-py/cyberscorecard",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    install_requires=[
        "pydantic>=2.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
    ],
    keywords=[
        "cybersecurity governance", "CIS controls", "security scorecard python",
        "SMB security assessment", "cyber risk scoring",
        "security maturity model", "NIST CSF python",
        "cybersecurity compliance SMB", "security posture assessment",
        "vulnerability management python",
    ],
)
