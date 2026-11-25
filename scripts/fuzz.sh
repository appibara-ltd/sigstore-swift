#!/usr/bin/env bash
# Builds the libFuzzer harness in Fuzz/ and runs each target for
# FUZZ_SECONDS (default 30), seeded from the test fixtures. Linux only (the
# swift.org Linux toolchain ships libFuzzer; Xcode's does not).
#
#   FUZZ_SECONDS=600 scripts/fuzz.sh [target ...]
#
# Crashes and slow inputs are written to .build/fuzz/artifacts/<target>/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.build/fuzz"
SECONDS_PER_TARGET="${FUZZ_SECONDS:-30}"
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=(json protojson bundle trustedroot statement rfc3161 note tuf pathmatch mldsa)
fi

swift build -c release --package-path "$ROOT/Fuzz" --scratch-path "$OUT/build" \
  -Xswiftc -sanitize=fuzzer,address -Xswiftc -parse-as-library
BIN="$OUT/build/release/SigstoreFuzz"
FIX="$ROOT/Tests/SigstoreTests/Fixtures"

seed() {  # seed <target> <dir>
  local t="$1" dir="$2"
  mkdir -p "$dir"
  case "$t" in
    json|protojson|bundle)
      find "$FIX" -name '*.sigstore.json' -exec cp {} "$dir/" \; ;;
    trustedroot)
      cp "$FIX"/trusted_root.json "$FIX"/github_trusted_root.json "$dir/" ;;
    statement)
      python3 - "$FIX" "$dir" <<'PY'
import base64, json, pathlib, sys
fix, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for i, p in enumerate(fix.rglob("*.sigstore.json")):
    b = json.loads(p.read_text())
    if "dsseEnvelope" in b:
        (out / f"stmt{i}").write_bytes(base64.b64decode(b["dsseEnvelope"]["payload"]))
PY
      ;;
    rfc3161)
      python3 - "$FIX" "$dir" <<'PY'
import base64, json, pathlib, sys
fix, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for i, p in enumerate(fix.rglob("*.sigstore.json")):
    b = json.loads(p.read_text())
    for j, t in enumerate(b["verificationMaterial"].get("timestampVerificationData", {}).get("rfc3161Timestamps", [])):
        (out / f"tsr{i}_{j}").write_bytes(base64.b64decode(t["signedTimestamp"]))
PY
      ;;
    note)
      python3 - "$FIX" "$dir" <<'PY'
import json, pathlib, sys
fix, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for i, p in enumerate(fix.rglob("*.sigstore.json")):
    for j, e in enumerate(json.loads(p.read_text())["verificationMaterial"].get("tlogEntries", [])):
        cp = e.get("inclusionProof", {}).get("checkpoint", {}).get("envelope")
        if cp:
            (out / f"note{i}_{j}").write_text(cp)
PY
      ;;
    tuf)
      cp "$FIX"/tuf-repo.github.com/*.json "$dir/" ;;
    pathmatch)
      printf 'a/*.json\0a/b.json' > "$dir/seed1"; printf 'targets/[a-z]?\0targets/x1' > "$dir/seed2" ;;
    mldsa)
      head -c 2500 /dev/urandom > "$dir/seed1" ;;
  esac
}

status=0
for t in "${TARGETS[@]}"; do
  corpus="$OUT/corpus/$t"
  artifacts="$OUT/artifacts/$t/"
  seed "$t" "$corpus"
  mkdir -p "$artifacts"
  echo "== fuzzing $t for ${SECONDS_PER_TARGET}s"
  # LeakSanitizer needs ptrace, which containers usually lack.
  if ! ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}" SIGSTORE_FUZZ_TARGET="$t" "$BIN" "$corpus" -max_total_time="$SECONDS_PER_TARGET" \
      -max_len=65536 -timeout=10 -rss_limit_mb=2048 -artifact_prefix="$artifacts" -print_final_stats=1; then
    echo "!! $t found a failing input (see $artifacts)"
    status=1
  fi
done
exit $status
