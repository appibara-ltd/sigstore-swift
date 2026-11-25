#!/usr/bin/env bash
# Regenerates Sources/SigstoreProtobufSpecs from sigstore/protobuf-specs.
#
# Requirements: git, curl, protoc (>= 3.x), protoc-gen-swift whose version
# matches the swift-protobuf dependency in Package.swift.
#   brew install protobuf swift-protobuf
#
# Pins:
#   PROTOBUF_SPECS_REF: the protobuf-specs commit sigstore-go v1.4.1 depends on
#     (go.mod: github.com/sigstore/protobuf-specs v0.5.3-0.20261112181914-a84bc5ff572a).
#   GOOGLEAPIS_REF: googleapis commit providing google/api/field_behavior.proto.
set -euo pipefail

PROTOBUF_SPECS_REF="${PROTOBUF_SPECS_REF:-a84bc5ff572a7619fc7f14d720c422cccee7b456}"
GOOGLEAPIS_REF="${GOOGLEAPIS_REF:-25fb8ea2d4bfa8fd41e24b28029e34a4adc35db0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/Sources/SigstoreProtobufSpecs/Generated"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git -C "$WORK" init -q specs
git -C "$WORK/specs" fetch -q --depth 1 https://github.com/sigstore/protobuf-specs.git "$PROTOBUF_SPECS_REF"
git -C "$WORK/specs" checkout -q FETCH_HEAD

mkdir -p "$WORK/include/google/api"
curl -fsSL -o "$WORK/include/google/api/field_behavior.proto" \
  "https://raw.githubusercontent.com/googleapis/googleapis/${GOOGLEAPIS_REF}/google/api/field_behavior.proto"

PROTOC_INCLUDE="$(dirname "$(command -v protoc)")/../include"

rm -rf "$OUT"
mkdir -p "$OUT"
protoc \
  -I "$WORK/specs/protos" \
  -I "$WORK/include" \
  -I "$PROTOC_INCLUDE" \
  --swift_opt=Visibility=Public \
  --swift_opt=FileNaming=PathToUnderscores \
  --swift_out="$OUT" \
  google/api/field_behavior.proto \
  "$WORK"/specs/protos/*.proto

{
  echo "protobuf-specs: $PROTOBUF_SPECS_REF"
  echo "googleapis: $GOOGLEAPIS_REF"
  echo "protoc: $(protoc --version)"
  echo "protoc-gen-swift: $(protoc-gen-swift --version)"
} > "$OUT/VERSIONS.txt"

echo "Generated into $OUT"
