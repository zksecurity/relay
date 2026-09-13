#!/usr/bin/env bash
# Run from Bash or directly; no Java installation or ceremony files required.
set -euo pipefail
if [[ $# != 1 || ! -f "$1" ]]; then
  echo 'Usage: models/onboarding/check.sh /absolute/path/to/tla2tools.jar' >&2
  exit 2
fi
model_dir=$(cd "$(dirname "$0")" && pwd -P)
jar_dir=$(cd "$(dirname "$1")" && pwd -P)
jar="$jar_dir/$(basename "$1")"
expected=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
actual=$(shasum -a 256 "$jar")
[[ "${actual%% *}" == "$expected" ]] || { echo 'Unexpected TLC jar hash' >&2; exit 2; }
logs=$(mktemp -d "${TMPDIR:-/tmp}/relay-model-check.XXXXXX")
echo "Checker logs retained: $logs"
image=eclipse-temurin@sha256:a80c51f2d09a3e7e00d521f1c817bbceb6b3be94109b4a784d46078099882dda
for config in current proposed reach-success reach-send-only; do
  status=0
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --memory 1g --cpus 2 \
    --tmpfs /tmp:rw,nosuid,nodev,size=128m \
    --mount "type=bind,src=$model_dir,dst=/model,readonly" \
    --mount "type=bind,src=$jar,dst=/tla2tools.jar,readonly" \
    --workdir /model "$image" java -XX:+UseParallelGC -Xmx512m \
    -jar /tla2tools.jar -workers 1 -metadir /tmp/tlc \
    -config "$config.cfg" Onboarding.tla >"$logs/$config.log" 2>&1 || status=$?
  if [[ "$config" == proposed ]]; then
    if [[ $status != 0 ]] || ! grep -q 'Model checking completed. No error has been found.' "$logs/$config.log"; then
      cat "$logs/$config.log"; exit 1
    fi
    echo 'PASS: proposed model satisfies the four bounded safety checks'
  else
    case "$config" in
      current) invariant=StorageBeforeRecommendation ;;
      reach-success) invariant=NeverFinished ;;
      reach-send-only) invariant=NoUnacknowledgedSend ;;
    esac
    if [[ $status != 12 ]] || ! grep -q "Error: Invariant $invariant is violated." "$logs/$config.log"; then
      cat "$logs/$config.log"; exit 1
    fi
    echo "PASS: $config produced the expected $invariant counterexample"
  fi
done
echo 'Model checks only. Run TestOnboardingModelContract separately to check the real CLI recommendation.'
