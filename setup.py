from setuptools import setup

# Each of these currently lives at spirit/<name>/ but is imported as a bare
# top-level package (e.g. "from core import Engine", "from integrations.docker
# import ..."). package_dir maps the import name to its real location on disk
# without touching any existing import statement.
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

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="spiritcli",
    version="3.1.1",
    description="Spirit CLI: Real-Time Dependency Security Intelligence for Banking",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    package_dir=package_dir,
    packages=packages,
    py_modules=["spirit"],   # the root spirit.py file, unchanged
    install_requires=requirements,
    entry_points={
        "console_scripts": ["spirit=spirit:cli"],
    },
)