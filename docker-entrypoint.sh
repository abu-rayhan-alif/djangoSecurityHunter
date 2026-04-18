#!/bin/sh
set -e
# GitHub Actions passes action inputs as INPUT_* (e.g. INPUT_SETTINGS for `settings`).
if [ -n "${INPUT_SETTINGS:-}" ]; then
  exec django_security_hunter "$@" --settings "$INPUT_SETTINGS" --allow-project-code
else
  exec django_security_hunter "$@"
fi
