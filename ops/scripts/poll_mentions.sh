#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  set +a
fi

BASE_URL="${TP_BASE_URL:-https://tinypeople.mesh.net.nz}"
API_KEY="${TP_KEY:-${TINYPEOPLE_API_KEY:-}}"
SCAN_LIMIT="${TP_SCAN_LIMIT:-20}"
LOOKBACK_LIMIT="${TP_LOOKBACK_LIMIT:-60}"
MAX_REPLIES="${TP_MAX_REPLIES:-1}"
OUTPUT_MODE="${TP_OUTPUT_MODE:-full}"
CURL_BIN="${CURL_BIN:-curl}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

CHANNEL_IDS=()
if [[ "$#" -gt 0 ]]; then
  for arg in "$@"; do
    if [[ -n "${arg}" ]]; then
      CHANNEL_IDS+=("${arg}")
    fi
  done
elif [[ -n "${TP_CHANNEL_IDS:-}" ]]; then
  IFS=',' read -r -a CHANNEL_IDS <<< "${TP_CHANNEL_IDS}"
elif [[ -n "${TP_CHANNEL_ID:-}" ]]; then
  CHANNEL_IDS=("${TP_CHANNEL_ID}")
fi

usage() {
  cat <<'EOF'
Usage:
  poll_mentions.sh CHANNEL_ID [CHANNEL_ID ...]

Environment:
  TP_KEY or TINYPEOPLE_API_KEY   Required API key for X-TinyPeople-Key
  TP_BASE_URL                    Optional, defaults to https://tinypeople.mesh.net.nz
  ENV_FILE                       Optional, defaults to REPO_ROOT/.env
  TP_CHANNEL_ID                  Optional single-channel fallback when args are omitted
  TP_CHANNEL_IDS                 Optional comma-separated channel list when args are omitted
  TP_SCAN_LIMIT                  Optional, defaults to 20
  TP_LOOKBACK_LIMIT              Optional, defaults to 60
  TP_MAX_REPLIES                 Optional, defaults to 1
  TP_OUTPUT_MODE                 Optional: full, summary, failures
  PYTHON_BIN                     Optional, defaults to python3

Examples:
  TP_KEY=your_key ./poll_mentions.sh 1495644139805474907
  TP_KEY=your_key ./poll_mentions.sh 1495644139805474907 1495644139805474908
  TP_CHANNEL_IDS=1495644139805474907,1495644139805474908 ./poll_mentions.sh
EOF
}

if [[ "$#" -gt 0 && ( "${1}" == "-h" || "${1}" == "--help" ) ]]; then
  usage
  exit 0
fi

if [[ "${#CHANNEL_IDS[@]}" -eq 0 ]]; then
  echo "poll_mentions.sh: missing CHANNEL_ID or TP_CHANNEL_IDS" >&2
  usage >&2
  exit 2
fi

if [[ -z "${API_KEY}" ]]; then
  echo "poll_mentions.sh: set TP_KEY or TINYPEOPLE_API_KEY in the environment or ${ENV_FILE}" >&2
  exit 2
fi

if [[ "${OUTPUT_MODE}" != "full" && "${OUTPUT_MODE}" != "summary" && "${OUTPUT_MODE}" != "failures" ]]; then
  echo "poll_mentions.sh: TP_OUTPUT_MODE must be one of: full, summary, failures" >&2
  exit 2
fi

if [[ "${OUTPUT_MODE}" == "summary" && ! command -v "${PYTHON_BIN}" >/dev/null 2>&1 ]]; then
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "poll_mentions.sh: summary mode requires python3 or python in PATH" >&2
    exit 2
  fi
fi

FAILURES=0

for raw_channel_id in "${CHANNEL_IDS[@]}"; do
  CHANNEL_ID="$(printf '%s' "${raw_channel_id}" | tr -d '[:space:]')"
  if [[ -z "${CHANNEL_ID}" ]]; then
    continue
  fi

  QUERY_URL="${BASE_URL%/}/discord/mentions/respond?channel_id=${CHANNEL_ID}&scan_limit=${SCAN_LIMIT}&lookback_limit=${LOOKBACK_LIMIT}&max_replies=${MAX_REPLIES}"
  TMP_BODY="$(mktemp)"

  HTTP_CODE="$("${CURL_BIN}" -sS -o "${TMP_BODY}" -w "%{http_code}" \
    -H "X-TinyPeople-Key: ${API_KEY}" \
    "${QUERY_URL}")"

  if [[ "${OUTPUT_MODE}" == "full" ]]; then
    printf '=== channel_id=%s http=%s ===\n' "${CHANNEL_ID}" "${HTTP_CODE}"
    cat "${TMP_BODY}"
    printf '\n'
  fi

  if [[ "${OUTPUT_MODE}" == "summary" ]]; then
    "${PYTHON_BIN}" - <<'PY' "${TMP_BODY}" "${CHANNEL_ID}" "${HTTP_CODE}"
import json
import sys

body_path, channel_id, http_code = sys.argv[1:4]
try:
    with open(body_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
except Exception as exc:
    print(f"channel_id={channel_id} http={http_code} summary=parse_error:{type(exc).__name__}")
    sys.exit(0)

reply_count = payload.get("reply_count")
skipped = payload.get("skipped")
if isinstance(reply_count, int):
    skipped_count = len(skipped) if isinstance(skipped, list) else 0
    print(
        f"channel_id={channel_id} http={http_code} "
        f"reply_count={reply_count} skipped_count={skipped_count}"
    )
else:
    error = payload.get("error", "unknown_error")
    print(f"channel_id={channel_id} http={http_code} error={error}")
PY
  fi

  if [[ "${OUTPUT_MODE}" == "failures" && ( "${HTTP_CODE}" -lt 200 || "${HTTP_CODE}" -ge 300 ) ]]; then
    printf '=== channel_id=%s http=%s ===\n' "${CHANNEL_ID}" "${HTTP_CODE}"
    cat "${TMP_BODY}"
    printf '\n'
  fi

  rm -f "${TMP_BODY}"

  if [[ "${HTTP_CODE}" -lt 200 || "${HTTP_CODE}" -ge 300 ]]; then
    echo "poll_mentions.sh: request failed for channel ${CHANNEL_ID} with HTTP ${HTTP_CODE}" >&2
    FAILURES=1
  fi
done

exit "${FAILURES}"
