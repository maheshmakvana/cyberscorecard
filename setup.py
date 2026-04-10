from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cyberscorecard",
    version="1.2.2",
    author="",
    description="SMB cybersecurity governance scorecard — CIS Controls v8, Zero Trust scoring, IR playbook generation, threat intelligence feed, attack surface mapping, compliance gap analysis",
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
        "vulnerability management python", "zero trust architecture python",
        "zero trust scorecard", "incident response playbook python",
        "threat intelligence feed python", "NIST SP 800-207",
        "cybersecurity automation SMB", "attack surface mapping",
    ],
)
