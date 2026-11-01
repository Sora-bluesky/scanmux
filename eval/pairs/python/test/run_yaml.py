"""Regression harness for the PyYAML full_load code-execution advisory
(CVE-2020-14343 / PYSEC-2021-142). argv: <vendored-package-dir> <payload.yaml>.

The payload only drives yaml.full_load to write a marker value to the file named
by SCANMUX_MARKER_PATH, never a shell command. 5.3.1 executes it; 5.4 rejects the
python/object/new tag with a ConstructorError. Output is a single protocol line so
the Node oracle can tell an unusable library apart from the absent/present signal.
"""
import sys


def main():
    package_dir, payload_path = sys.argv[1], sys.argv[2]
    sys.path.insert(0, package_dir)
    try:
        import yaml
    except Exception:
        print("IMPORT_FAIL")
        return
    with open(payload_path, "r", encoding="ascii") as handle:
        document = handle.read()
    try:
        yaml.full_load(document)
    except Exception:
        print("LOAD_ERROR")
        return
    print("LOADED")


if __name__ == "__main__":
    main()
