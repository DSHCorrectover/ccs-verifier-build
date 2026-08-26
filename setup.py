"""
Build script for ccs-verifier.

Compiles proprietary modules (audit_cli, builtin_rules) to native extensions
via Cython. The .py source files for proprietary modules are REMOVED from the
build directory before wheel packaging — only the compiled .so/.pyd ships.
"""
from setuptools import setup, find_packages, Extension
from setuptools.command.build_py import build_py as _build_py
from Cython.Build import cythonize
import sys
import os

PROPRIETARY_MODULES = ["audit_cli", "builtin_rules"]

# Platform-specific compile args
if sys.platform == "win32":
    extra_compile_args = ["/O2"]
else:
    extra_compile_args = ["-O3"]

extensions = [
    Extension(
        f"ccs_verifier.{mod}",
        [f"ccs_verifier/{mod}.py"],
        extra_compile_args=extra_compile_args,
    )
    for mod in PROPRIETARY_MODULES
]


class build_py(_build_py):
    """After copying .py files, remove proprietary .py (we keep only .so/.pyd)."""

    def run(self):
        super().run()
        for mod in PROPRIETARY_MODULES:
            py_in_build = os.path.join(self.build_lib, "ccs_verifier", f"{mod}.py")
            if os.path.exists(py_in_build):
                os.remove(py_in_build)
                print(f"[build_py] removed proprietary source: {py_in_build}")


setup(
    packages=find_packages(),
    ext_modules=cythonize(
        extensions,
        compiler_directives={"language_level": "3"},
        build_dir="build/cython",
    ),
    cmdclass={"build_py": build_py},
    package_data={"ccs_verifier": ["reference_issuer.json"]},
    zip_safe=False,
)
