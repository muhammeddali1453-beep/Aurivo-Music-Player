# Repository'yi Private (Kapalı Kaynak) Yapma Rehberi

## GitHub Web Üzerinden

1. **Repository Ayarlarına Git**
   ```
   https://github.com/muhammeddali1453-beep/Angolla-Music-Player/settings
   ```

2. **En Alta Kaydır** → "Danger Zone" bölümüne git

3. **"Change repository visibility"** butonuna tıkla

4. **"Make private"** seç

5. **Repository adını yazarak onayla**: `muhammeddali1453-beep/Angolla-Music-Player`

6. **"I understand, make this repository private"** butonuna tıkla

## Önemli Notlar

### ✅ Private Olunca Ne Değişir?
- Sadece sen görebilirsin
- Davet ettiğin kişiler görebilir
- GitHub releases hala indirilebilir (eğer izin verirsen)
- Issues/discussions kapalı olur

### 📋 Checklist (Private Yapmadan Önce)

- [ ] Tüm hassas bilgiler silindi (API keys, şifreler)
- [ ] README.md güncel
- [ ] LICENSE dosyası eklendi
- [ ] .gitignore düzgün ayarlandı
- [ ] Son commit'ler push edildi

### 🔓 Tekrar Public Yapmak İstersan
Aynı ayarlardan "Make public" seçeneği var.

### 🔐 İzin Sistemi (Private'ken)

Collaborator eklemek için:
```
Settings → Collaborators → Add people
```

## Hibrit Çözüm: Public Repo + Private Source

Eğer hem release'leri paylaşmak hem de kaynak kodunu gizlemek istiyorsan:

1. **İki Repo Oluştur**:
   - `Angolla-Music-Player` (public) → Sadece README, INSTALL, releases
   - `Angolla-Music-Player-Source` (private) → Kaynak kod

2. **Public Repo İçeriği**:
   ```
   README.md
   INSTALL.md
   LICENSE
   .github/workflows/release.yml  (release automation)
   ```

3. **Build Pipeline**:
   - Private repo'da geliştir
   - Build yap
   - Public repo'ya sadece binary ekle

## Komut Satırı Kontrolü

```bash
# Repository durumunu kontrol et
gh repo view muhammeddali1453-beep/Angolla-Music-Player --json visibility

# Private yap (gh cli ile)
gh repo edit muhammeddali1453-beep/Angolla-Music-Player --visibility private

# Public yap
gh repo edit muhammeddali1453-beep/Angolla-Music-Player --visibility public
```

## Lisans ve Private Repo

Private repo olsa bile LICENSE dosyası önemli çünkü:
- Collaborator'lar için kurallar belirler
- Gelecekte public yapılırsa hazır
- Binary dağıtımı için hukuki koruma

---

**Son Karar**: Repository'yi private yap, binary'leri GitHub Releases'te public tut.
