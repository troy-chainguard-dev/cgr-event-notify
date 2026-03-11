#!/usr/bin/env bash
#
# Packages Lambda function source into zip files for Terraform.
# Terraform's archive_file data source handles this automatically during
# plan/apply, but this script is useful for CI or manual verification.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/.build"

mkdir -p "$BUILD_DIR"

for func_dir in "${REPO_ROOT}"/lambda/*/; do
    func_name="$(basename "$func_dir")"
    zip_path="${BUILD_DIR}/${func_name}.zip"

    echo "Packaging ${func_name} -> ${zip_path}"

    if [ -f "${func_dir}/requirements.txt" ] && grep -qvE '^\s*(#|$)' "${func_dir}/requirements.txt"; then
        pkg_dir="${func_dir}/package"
        rm -rf "$pkg_dir"
        pip install -q -r "${func_dir}/requirements.txt" -t "$pkg_dir"
        (cd "$pkg_dir" && zip -qr "$zip_path" .)
        (cd "$func_dir" && zip -qg "$zip_path" handler.py)
        rm -rf "$pkg_dir"
    else
        (cd "$func_dir" && zip -qr "$zip_path" handler.py)
    fi

    echo "  -> $(du -h "$zip_path" | cut -f1) compressed"
done

echo ""
echo "All Lambda packages written to ${BUILD_DIR}/"
