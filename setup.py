from pathlib import Path
from setuptools import setup

HERE = Path(__file__).parent.resolve()

SPIRIT_SUBPACKAGES = [
    "core", "integrations", "ast_engine", "scoring",
    "storage", "phantom", "provenance", "config_analysis",
    "git", "remediation", "reporting",
]

package_dir = {"models": "models"}
packages = ["models"]

for pkg in SPIRIT_SUBPACKAGES:
    package_dir[pkg] = f"spirit/{pkg}"
    packages.append(pkg)

with open(HERE / "requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="spiritcli",
    version="3.1.1",
    description="Spirit CLI: Real-Time Dependency Security Intelligence for Banking",
    long_description=(HERE / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    package_dir=package_dir,
    packages=packages,
    py_modules=["spirit"],
    install_requires=requirements,
    entry_points={
        "console_scripts": ["spirit=spirit:cli"],
    },
)