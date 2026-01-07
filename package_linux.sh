#!/bin/bash
# Aurivo Linux Paketi - Sıkıştırma Script'i

echo "📦 Aurivo Linux paketi sıkıştırılıyor..."

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="${1:-v2.0}"

if [ ! -d "dist/aurivo" ]; then
	echo "HATA: dist/aurivo bulunamadı. Önce ./build_linux.sh çalıştırın."
	exit 1
fi

cd dist

# Tar.gz oluştur
tar -czf "Aurivo-Linux-${VERSION}.tar.gz" aurivo/

# Boyut bilgisi
echo ""
echo "✓ Paket hazır: Aurivo-Linux-${VERSION}.tar.gz"
ls -lh "Aurivo-Linux-${VERSION}.tar.gz"
echo ""
echo "📋 Dağıtım için:"
echo "  - Kullanıcıya README.txt göster"
echo "  - GStreamer bağımlılıkları kurulu olmalı"
echo "  - Çalıştırma: ./aurivo"
