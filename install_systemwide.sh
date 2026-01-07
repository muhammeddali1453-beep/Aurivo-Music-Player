#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Kullanım:
  ./install_systemwide.sh [--bin /path/to/aurivo]
  ./install_systemwide.sh --user [--bin /path/to/aurivo]

Ne yapar?
  - Aurivo çalıştırılabilirini /usr/local/bin/aurivo olarak kurar
  - aurivo.desktop dosyasını /usr/local/share/applications altına kurar
  - aurivo ikonunu /usr/local/share/icons/hicolor/48x48/apps altına kurar
  - (varsa) desktop veritabanı / ikon cache günceller

--user modu:
  - Root gerektirmez; ~/.local altına kurar (Linux masaüstünde normal uygulama gibi görünür)
  - Kurulum sonrası menüden çıkması için oturumu kapat/aç gerekebilir

Not:
  - Varsayılan ikon kaynağı: ./icons/media-playback-start.png
  - Varsayılan binary kaynağı: ./aurivo veya ./build/aurivo_linux/aurivo veya ./dist/aurivo/aurivo
EOF
}

BIN_SRC=""
USER_MODE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      USER_MODE=1
      shift
      ;;
    --bin)
      BIN_SRC="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Bilinmeyen argüman: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# Root yetkisi gerek (sistem geneli kurulum)
if [[ "$USER_MODE" -eq 0 && ${EUID:-0} -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E -- "$0" "$@"
  fi
  echo "HATA: root yetkisi gerekli (ve sudo bulunamadı)." >&2
  echo "İpucu: root yoksa kullanıcı kurulumu için: ./install_systemwide.sh --user" >&2
  exit 1
fi

DESKTOP_SRC="$ROOT_DIR/aurivo.desktop"
if [[ ! -f "$DESKTOP_SRC" ]]; then
  echo "HATA: aurivo.desktop bulunamadı: $DESKTOP_SRC" >&2
  exit 1
fi

if [[ -z "$BIN_SRC" ]]; then
  for candidate in \
    "$ROOT_DIR/aurivo" \
    "$ROOT_DIR/build/aurivo_linux/aurivo" \
    "$ROOT_DIR/dist/aurivo/aurivo" \
  ; do
    if [[ -x "$candidate" ]]; then
      BIN_SRC="$candidate"
      break
    fi
  done
fi

if [[ -z "$BIN_SRC" || ! -e "$BIN_SRC" ]]; then
  echo "HATA: Kurulacak binary bulunamadı." >&2
  echo "  --bin ile yol verin (örn: --bin ./aurivo)" >&2
  exit 1
fi

# Eğer BIN_SRC bir "bundle" içindeyse (örn: dist/aurivo/aurivo), tek dosya kopyalamak yetmez.
# Bu durumda tüm klasörü kurup, ~/.local/bin/aurivo için wrapper üretiriz.
BIN_SRC_ABS="$(cd -- "$(dirname -- "$BIN_SRC")" && pwd)/$(basename -- "$BIN_SRC")"
BIN_SRC_DIR="$(cd -- "$(dirname -- "$BIN_SRC_ABS")" && pwd)"
IS_BUNDLE=0
if [[ -f "$BIN_SRC_DIR/aurivo.bin" || -d "$BIN_SRC_DIR/_internal" ]]; then
  IS_BUNDLE=1
fi

ICON_SRC=""
ICON_SOURCES=()

# Tercih: Aurivo ikon seti (çoklu boyut)
for candidate in \
  "$ROOT_DIR/icons/aurivo.svg" \
  "$ROOT_DIR/icons/aurivo_512.png" \
  "$ROOT_DIR/icons/aurivo.png" \
  "$ROOT_DIR/icons/aurivo_256.png" \
  "$ROOT_DIR/icons/aurivo_128.png" \
  "$ROOT_DIR/icons/aurivo_64.png" \
  "$ROOT_DIR/icons/aurivo_48.png" \
  "$ROOT_DIR/icons/aurivo_32.png" \
  "$ROOT_DIR/icons/aurivo_24.png" \
  "$ROOT_DIR/icons/aurivo_16.png" \
; do
  if [[ -f "$candidate" ]]; then
    ICON_SOURCES+=("$candidate")
  fi
done

# Fallback: eski ikon
if [[ ${#ICON_SOURCES[@]} -eq 0 ]]; then
  for candidate in \
    "$ROOT_DIR/icons/media-playback-start.png" \
    "$ROOT_DIR/dist/aurivo/_internal/media-playback-start.png" \
    "$ROOT_DIR/dist/aurivo/media-playback-start.png" \
  ; do
    if [[ -f "$candidate" ]]; then
      ICON_SOURCES+=("$candidate")
      break
    fi
  done
fi

if [[ ${#ICON_SOURCES[@]} -eq 0 ]]; then
  echo "HATA: Kurulacak ikon bulunamadı." >&2
  echo "Beklenen: icons/aurivo_*.png veya icons/aurivo.png" >&2
  exit 1
fi

if [[ "$USER_MODE" -eq 1 ]]; then
  BIN_DST="$HOME/.local/bin/aurivo"
  DESKTOP_DST_DIR="$HOME/.local/share/applications"
  ICON_DST_DIR="$HOME/.local/share/icons/hicolor/48x48/apps"
  PIXMAPS_DIR="$HOME/.local/share/pixmaps"
  APP_DST_DIR="$HOME/.local/share/aurivo"
else
  BIN_DST="/usr/local/bin/aurivo"
  DESKTOP_DST_DIR="/usr/local/share/applications"
  ICON_DST_DIR="/usr/local/share/icons/hicolor/48x48/apps"
  PIXMAPS_DIR="/usr/local/share/pixmaps"
  APP_DST_DIR="/usr/local/share/aurivo"
fi

# User modunda hicolor tema kökünde index.theme yoksa GNOME bu temayı görmezden gelebilir.
# Minimal bir index.theme oluşturarak ikonların doğru ölçeklerde seçilmesini sağlar.
if [[ "$USER_MODE" -eq 1 ]]; then
  ICON_THEME_ROOT="$HOME/.local/share/icons/hicolor"
  if [[ ! -f "$ICON_THEME_ROOT/index.theme" ]]; then
    install -d "$ICON_THEME_ROOT"
    cat > "$ICON_THEME_ROOT/index.theme" <<'EOF'
[Icon Theme]
Name=Hicolor
Comment=Fallback icon theme
Directories=16x16/apps,24x24/apps,32x32/apps,48x48/apps,64x64/apps,128x128/apps,256x256/apps,512x512/apps,scalable/apps

[16x16/apps]
Size=16
Context=Applications
Type=Fixed

[24x24/apps]
Size=24
Context=Applications
Type=Fixed

[32x32/apps]
Size=32
Context=Applications
Type=Fixed

[48x48/apps]
Size=48
Context=Applications
Type=Fixed

[64x64/apps]
Size=64
Context=Applications
Type=Fixed

[128x128/apps]
Size=128
Context=Applications
Type=Fixed

[256x256/apps]
Size=256
Context=Applications
Type=Fixed

[512x512/apps]
Size=512
Context=Applications
Type=Fixed

[scalable/apps]
MinSize=16
MaxSize=512
Context=Applications
Type=Scalable
EOF
  fi
fi

install -d "$DESKTOP_DST_DIR" "$ICON_DST_DIR" "$PIXMAPS_DIR"

if [[ "$USER_MODE" -eq 1 ]]; then
  install -d "$HOME/.local/bin"
fi

if [[ "$IS_BUNDLE" -eq 1 ]]; then
  # Bundle klasörünü komple kur
  install -d "$APP_DST_DIR"
  rm -rf "$APP_DST_DIR/app"
  mkdir -p "$APP_DST_DIR/app"
  cp -a "$BIN_SRC_DIR/." "$APP_DST_DIR/app/"

  # PATH'e konacak wrapper: kurulu bundle içinden çalıştır
  cat >"$BIN_DST" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="__AURIVO_APP_DIR__"
cd "$APP_DIR"
exec ./aurivo "\$@"
EOF
  sed -i "s|__AURIVO_APP_DIR__|$APP_DST_DIR/app|g" "$BIN_DST"
  chmod 0755 "$BIN_DST"
else
  install -m 0755 "$BIN_SRC" "$BIN_DST"
fi

install -m 0644 "$DESKTOP_SRC" "$DESKTOP_DST_DIR/aurivo.desktop"

# İkonları doğru hicolor boyutlarına kur (var olan boyutlar kadar)
installed_any_icon=0

# PNG boyutları
for size in 16 24 32 48 64 128 256 512; do
  src=""
  if [[ -f "$ROOT_DIR/icons/aurivo_${size}.png" ]]; then
    src="$ROOT_DIR/icons/aurivo_${size}.png"
  elif [[ "$size" -eq 256 && -f "$ROOT_DIR/icons/aurivo.png" ]]; then
    # aurivo.png çoğunlukla 256x256
    src="$ROOT_DIR/icons/aurivo.png"
  fi

  if [[ -n "$src" ]]; then
    dst_dir="${ICON_DST_DIR%/48x48/apps}/${size}x${size}/apps"
    install -d "$dst_dir"
    install -m 0644 "$src" "$dst_dir/aurivo.png"
    installed_any_icon=1
  fi
done

# Scalable (opsiyonel)
if [[ -f "$ROOT_DIR/icons/aurivo.svg" ]]; then
  scalable_dir="${ICON_DST_DIR%/48x48/apps}/scalable/apps"
  install -d "$scalable_dir"
  install -m 0644 "$ROOT_DIR/icons/aurivo.svg" "$scalable_dir/aurivo.svg"
  installed_any_icon=1
fi

# Pixmaps fallback (en az bir PNG)
if [[ -f "$ROOT_DIR/icons/aurivo.png" ]]; then
  install -m 0644 "$ROOT_DIR/icons/aurivo.png" "$PIXMAPS_DIR/aurivo.png"
  installed_any_icon=1
elif [[ -f "$ROOT_DIR/icons/aurivo_128.png" ]]; then
  install -m 0644 "$ROOT_DIR/icons/aurivo_128.png" "$PIXMAPS_DIR/aurivo.png"
  installed_any_icon=1
fi

if [[ "$installed_any_icon" -ne 1 ]]; then
  # En son çare: listeden ilk bulunanı 48x48'a koy
  install -m 0644 "${ICON_SOURCES[0]}" "$ICON_DST_DIR/aurivo.png"
  install -m 0644 "${ICON_SOURCES[0]}" "$PIXMAPS_DIR/aurivo.png"
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$DESKTOP_DST_DIR" || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  if [[ "$USER_MODE" -eq 1 ]]; then
    # User hicolor temasında index.theme olmayabilir; uyarı vermesin diye sadece varsa çalıştır.
    if [[ -f "$HOME/.local/share/icons/hicolor/index.theme" ]]; then
      gtk-update-icon-cache -f "$HOME/.local/share/icons/hicolor" || true
    fi
  else
    gtk-update-icon-cache -f /usr/local/share/icons/hicolor || true
  fi
fi

echo "OK: Kurulum tamamlandı"
echo " - Binary : $BIN_DST"
if [[ "$IS_BUNDLE" -eq 1 ]]; then
  echo " - AppDir : $APP_DST_DIR/app"
fi
echo " - Desktop: $DESKTOP_DST_DIR/aurivo.desktop"
echo " - Icon   : ${ICON_DST_DIR%/48x48/apps}/*/apps/aurivo.png"

if [[ "$USER_MODE" -eq 1 ]]; then
  echo "Not: ~/.local/bin PATH içinde olmalı (gerekirse terminali yeniden açın)."
fi
