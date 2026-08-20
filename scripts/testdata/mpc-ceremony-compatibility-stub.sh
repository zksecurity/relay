#!/usr/bin/env bash
# Minimal CLI-contract fixture for Relay's own ceremony-kit tests. Real kit
# validation always supplies an independently released mpc-ceremony binary.
set -euo pipefail

ceremony_id=sha256:1111111111111111111111111111111111111111111111111111111111111111

flag_value() {
  local wanted=$1
  shift
  while [[ $# -gt 0 ]]; do
    if [[ $1 == "$wanted" && $# -ge 2 ]]; then
      printf '%s\n' "$2"
      return 0
    fi
    shift
  done
  return 1
}

if [[ ${1:-} == rehearsal && ${2:-} == init ]]; then
  out_dir=
  shift 2
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --created-at) shift 2 ;;
      --out-dir) out_dir=$2; shift 2 ;;
      *) exit 2 ;;
    esac
  done
  [[ -n "$out_dir" && ! -e "$out_dir" ]] || exit 1
  mkdir -p "$out_dir/public/phase1" "$out_dir/config" "$out_dir/keys"
  printf '{}\n' >"$out_dir/public/ceremony.json"
  printf 'fixture\n' >"$out_dir/public/ceremony.sig"
  printf 'fixture\n' >"$out_dir/public/coordinator-public-key.hex"
  printf '{}\n' >"$out_dir/public/phase1/chain-0000.json"
  printf 'fixture\n' >"$out_dir/public/phase1/chain-0000.sig"
  printf '{}\n' >"$out_dir/config/environment.json"
  printf 'fixture\n' >"$out_dir/keys/coordinator.ed25519.private.hex"
  printf 'fixture\n' >"$out_dir/keys/participant-01.ed25519.private.hex"
  chmod 0600 \
    "$out_dir/keys/coordinator.ed25519.private.hex" \
    "$out_dir/keys/participant-01.ed25519.private.hex"
  exit 0
fi

if [[ ${1:-} == --format && ${2:-} == json && ${3:-} == inspect ]]; then
  case "${4:-}" in
    definition)
      printf '{"schema":"proof-tool-mpc-command-result-v1","ok":true,"command":"inspect definition","ceremony_id":"%s","definition_inspection":{"schema":"proof-tool-mpc-definition-inspection-v1","ceremony_id":"%s","mode":"rehearsal","phase1_participants":["participant-01"],"phase2_participants":["participant-01"],"r1cs":{"name":"fixture.ccs","digest":{"sha256":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":1}}}}\n' \
        "$ceremony_id" "$ceremony_id"
      ;;
    participant)
      printf '{"schema":"proof-tool-mpc-command-result-v1","ok":true,"command":"inspect participant","ceremony_id":"%s","participant_inspection":{"schema":"proof-tool-mpc-participant-inspection-v1","ceremony_id":"%s","participant_id":"participant-01","key_id":"participant-01-key","public_key_fingerprint":"sha256:3333333333333333333333333333333333333333333333333333333333333333","phase1_position":1,"phase2_position":1}}\n' \
        "$ceremony_id" "$ceremony_id"
      ;;
    chain)
      chain=$(flag_value --chain "${@:5}") || exit 2
      if [[ $chain == *phase1/chain-0001.json ]]; then
        printf '{"schema":"proof-tool-mpc-command-result-v1","ok":true,"command":"inspect chain","ceremony_id":"%s","phase":"phase1","chain_inspection":{"schema":"proof-tool-mpc-chain-inspection-v1","ceremony_id":"%s","phase":"phase1","accepted_count":1,"artifacts":[],"records":[{"index":1,"record_id":"fixture-record-01","participant_id":"participant-01","artifacts":[]}]}}\n' \
          "$ceremony_id" "$ceremony_id"
      else
        printf '{"schema":"proof-tool-mpc-command-result-v1","ok":true,"command":"inspect chain","ceremony_id":"%s","phase":"phase1","chain_inspection":{"schema":"proof-tool-mpc-chain-inspection-v1","ceremony_id":"%s","phase":"phase1","accepted_count":0,"artifacts":[],"records":[]}}\n' \
          "$ceremony_id" "$ceremony_id"
      fi
      ;;
    *) exit 2 ;;
  esac
  exit 0
fi

if [[ ${1:-} == phase1 && ${2:-} == contribute ]]; then
  out_dir=$(flag_value --out-dir "$@") || exit 2
  [[ ! -e $out_dir ]] || exit 1
  mkdir -p "$out_dir"
  printf 'fixture contribution\n' >"$out_dir/contribution.bin"
  printf '{}\n' >"$out_dir/attestation.json"
  printf 'fixture\n' >"$out_dir/attestation.sig"
  exit 0
fi

if [[ ${1:-} == phase1 && ${2:-} == attest-erasure ]]; then
  candidate_dir=$(flag_value --candidate-dir "$@") || exit 2
  [[ -d $candidate_dir ]] || exit 1
  printf '{}\n' >"$candidate_dir/erasure.json"
  printf 'fixture\n' >"$candidate_dir/erasure.sig"
  exit 0
fi

if [[ ${1:-} == phase1 && ${2:-} == verify ]]; then
  transcript_dir=$(flag_value --transcript-dir "$@") || exit 2
  candidate_dir=$(flag_value --candidate-dir "$@") || exit 2
  [[ -d $candidate_dir && ! -e $transcript_dir/phase1/chain-0001.json ]] || exit 1
  printf '{}\n' >"$transcript_dir/phase1/chain-0001.json"
  printf 'fixture\n' >"$transcript_dir/phase1/chain-0001.sig"
  exit 0
fi

if [[ ${1:-} == help || ${1:-} == --help || ${1:-} == -h ]]; then
  printf 'mpc-ceremony compatibility fixture\n'
  exit 0
fi

exit 2
