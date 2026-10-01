#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
readonly ROOT

/usr/bin/python3 "${ROOT}/infra/ansible/validate.py"
/usr/bin/python3 -m unittest discover \
    -s "${ROOT}/infra/ansible/tests" \
    -p 'test_*.py'

if command -v ansible-playbook >/dev/null 2>&1; then
    ANSIBLE_CONFIG="${ROOT}/infra/ansible/ansible.cfg" \
        ansible-playbook --syntax-check "${ROOT}/infra/ansible/site.yml"
else
    printf 'SKIP ansible-playbook syntax (not installed locally)\n'
fi

if command -v ansible-lint >/dev/null 2>&1; then
    ANSIBLE_CONFIG="${ROOT}/infra/ansible/ansible.cfg" \
        ansible-lint "${ROOT}/infra/ansible/site.yml"
else
    printf 'SKIP ansible-lint (not installed locally)\n'
fi
