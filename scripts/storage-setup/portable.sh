#!/usr/bin/env bash
# Portable primitives for administrator storage setup scripts.

portable_sha256_stdin() {
  local output digest
  if command -v sha256sum >/dev/null 2>&1; then
    output=$(sha256sum) || return 1
  elif command -v shasum >/dev/null 2>&1; then
    output=$(shasum -a 256) || return 1
  else
    printf 'Neither sha256sum nor shasum is available.\n' >&2
    return 1
  fi
  digest=${output%% *}
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$digest"
}

portable_realpath() {
  local path=$1 resolved
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* ]] || return 1
  if command -v realpath >/dev/null 2>&1; then
    resolved=$(realpath "$path") || return 1
  elif command -v perl >/dev/null 2>&1; then
    resolved=$(perl -MCwd=abs_path -e '
      my $path = abs_path($ARGV[0]);
      exit 1 unless defined $path;
      print $path;
    ' "$path") || return 1
  else
    printf 'Neither realpath nor Perl Cwd is available.\n' >&2
    return 1
  fi
  [[ -n "$resolved" && "$resolved" != *$'\n'* && "$resolved" != *$'\r'* ]] || return 1
  printf '%s\n' "$resolved"
}

portable_stat_mode() {
  case "$(uname -s)" in
    Darwin) stat -f '%Lp' "$1" ;;
    *) stat -c '%a' -- "$1" ;;
  esac
}

portable_stat_uid() {
  case "$(uname -s)" in
    Darwin) stat -f '%u' "$1" ;;
    *) stat -c '%u' -- "$1" ;;
  esac
}

portable_stat_links() {
  case "$(uname -s)" in
    Darwin) stat -f '%l' "$1" ;;
    *) stat -c '%h' -- "$1" ;;
  esac
}

portable_read_single_line() {
  local path=$1 first='' second=''
  {
    IFS= read -r first || [[ -n "$first" ]] || return 1
    if IFS= read -r second || [[ -n "$second" ]]; then
      return 1
    fi
  } <"$path"
  [[ -n "$first" ]] || return 1
  printf '%s' "$first"
}
