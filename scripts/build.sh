#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(tr -d '[:space:]' < VERSION)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION must be x.y.z" >&2; exit 1; }
IFS=. read -r MAJOR MINOR PATCH <<< "$VERSION"
VERSION_CODE=$((MAJOR * 10000 + MINOR * 100 + PATCH))
mkdir -p dist
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -R module/. "$STAGE/"
mkdir -p "$STAGE/bin"
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$STAGE/bin/gofile-bridge" ./cmd/bridge
chmod 755 "$STAGE/bin/gofile-bridge" "$STAGE/service.sh"
sed -i -e "s/^version=.*/version=$VERSION/" -e "s/^versionCode=.*/versionCode=$VERSION_CODE/" "$STAGE/module.prop"
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
  printf 'updateJson=https://raw.githubusercontent.com/%s/main/update.json\n' "$GITHUB_REPOSITORY" >> "$STAGE/module.prop"
fi
python3 - "$STAGE" "dist/gofile-vlc-bridge-v$VERSION.zip" <<'PYZIP'
import pathlib,sys,zipfile
root=pathlib.Path(sys.argv[1]); target=pathlib.Path(sys.argv[2]);
with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=8) as z:
 for p in sorted(root.rglob('*')):
  if p.is_file():
   info=zipfile.ZipInfo(p.relative_to(root).as_posix())
   info.external_attr=(0o100755 if p.name in ('service.sh','gofile-bridge') else 0o100644)<<16
   z.writestr(info,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=8)
print(target)
PYZIP
