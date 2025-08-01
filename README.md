# 🚀 MikroTik Yönetim Paneli

Modern, güvenli ve kullanıcı dostu MikroTik yönetim web arayüzü.

## ✨ Özellikler

### 🔐 **Güvenlik**
- MikroTik native authentication
- Session tabanlı kimlik doğrulama
- Direct MikroTik API bağlantısı
- Protected routes
- Güvenli çıkış sistemi

### 🌐 **NAT Yönetimi**
- Port yönlendirme kuralları ekleme/silme/düzenleme
- Görsel tablo arayüzü
- Gerçek zamanlı MikroTik entegrasyonu

### 📊 **IP Monitoring**
- DHCP lease takibi
- ARP tablosu görüntüleme
- IP kullanım durumu (10.10.10.x ve 20.20.20.x)
- Görsel IP grid'i
- Canlı arama ve filtreleme

### 🎨 **Modern Arayüz**
- Responsive tasarım
- Gradient arka planlar
- Smooth animasyonlar
- Font Awesome ikonları
- Flash mesajları

## 📁 Dosya Yapısı

```
mikrotik-panel/
│
├── app.py                       # Ana Flask uygulaması
├── mikrotik.py                  # MikroTik bağlantı fonksiyonları
├── requirements.txt             # Python bağımlılıkları
├── README.md                    # Bu dosya
├── SECURITY.md                  # Güvenlik rehberi
│
├── static/                      # Static dosyalar
│   └── css/                     # CSS dosyaları
│       ├── edit_rule.css        # Düzenleme sayfası stilleri
│       └── ip_monitor.css       # IP monitör stilleri
│
└── templates/                   # HTML şablonları
    ├── base.html               # Ana layout
    ├── login.html              # Giriş sayfası
    ├── index.html              # NAT kuralları
    ├── edit_rule.html          # Kural düzenleme
    ├── ip_monitor.html         # IP monitoring
    └── profile.html            # Kullanıcı profili
```

## 🛠️ Kurulum

# 1. Scripti çalıştır
curl -sSL https://raw.githubusercontent.com/KULLANICI/mikrotik-panel/main/install.sh | sudo bash

# 2. MikroTik bilgileri sor
📡 MikroTik Router IP Adresi: 192.168.1.1
🚪 MikroTik API Portu: 8728
🌐 Web Panel Portu: 5050
🔐 API bağlantısını test etmek istiyor musunuz? [y/N]: y
   Kullanıcı Adı: admin
   Şifre: ********
   ✅ MikroTik API portu erişilebilir

# 3. Yapılandırma özeti
📋 MikroTik Yapılandırma Özeti:
   🏠 MikroTik IP Adresi : 192.168.1.1
   🚪 MikroTik API Port  : 8728
   🌐 Web Panel Portu    : 5050
   🔗 Panel Erişim URL   : http://SERVER_IP:5050

Bu ayarlarla kuruluma devam etmek istiyor musunuz? [Y/n]: Y

# 4. Otomatik kurulum başlar
========== ADIM 1: SİSTEM KONTROLÜ ==========
========== ADIM 2: PAKET KURULUMU ==========
========== ADIM 3: KAYNAK DOSYALAR =========
========== ADIM 4: KULLANICI VE DİZİN ======
========== ADIM 5: PYTHON ORTAMI ===========
========== ADIM 6: SİSTEM SERVİSLERİ =======
========== ADIM 7: SERVİS BAŞLATMA =========
========== ADIM 8: DOĞRULAMA ===============
========== ADIM 9: RAPOR ===================


### Manuel kurulum
### 1. **Repoyu klonlayın**
```bash
dnf install python3-pip -y
git clone https://github.com/mratsag/mikrotik-web
cd mikrotik-web

```

### 2. **Python sanal ortamı oluşturun**
```bash

python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. **Bağımlılıkları yükleyin**
```bash
pip install -r requirements.txt
```

### 4. **Klasörleri oluşturun**
```bash
mkdir -p static/css templates
```

### 5. **Dosyaları yerleştirin**
- `app.py` → ana klasöre
- `*.html` dosyaları → `templates/` klasörüne
- `*.css` dosyaları → `static/css/` klasörüne

### 6. **MikroTik API'yi etkinleştirin**
MikroTik cihazınızda API'yi etkinleştirin:

```bash
# MikroTik Terminal'de çalıştırın:
/ip service enable api
/ip service set api port=8728
```

### 7. **Uygulamayı çalıştırın**
```bash
python app.py
```

### 8. **Tarayıcıda açın**
```
http://localhost:5050
```

## 🔑 Giriş Bilgileri

**MikroTik cihazınızın kullanıcı adı ve şifresini kullanın:**

| Alan | Açıklama | Örnek |
|------|----------|-------|
| **MikroTik IP** | Cihazınızın IP adresi | 192.168.254.142 |
| **Kullanıcı Adı** | MikroTik kullanıcı adı | admin |
| **Şifre** | MikroTik şifresi | (sizin şifreniz) |

⚠️ **Bu bilgiler MikroTik cihazınızın gerçek giriş bilgileridir!**

## 🖥️ Sayfalar

### 📝 **Login Sayfası** (`/login`)
- Modern glassmorphism tasarım
- MikroTik IP adresi girişi
- Native MikroTik authentication
- "Beni hatırla" özelliği
- Animasyonlu particles
- IP format validation

### 🏠 **Ana Sayfa** (`/`)
- NAT kuralları listesi
- Yeni kural ekleme formu
- Düzenleme/silme işlemleri
- Real-time MikroTik senkronizasyonu

### 📊 **IP Monitör** (`/ip_monitor`)
- DHCP lease tablosu
- ARP tablosu
- IP kullanım istatistikleri
- Görsel IP grid (10.10.10.x ve 20.20.20.x)

### ⚙️ **Kural Düzenleme** (`/edit_rule`)
- Mevcut kural bilgilerini düzenleme
- Form validasyonu
- Yardımcı metinler

### 👤 **Profil** (`/profile`)
- MikroTik sistem bilgileri
- Bağlantı durumu
- Cihaz özellikleri (CPU, RAM, Board)
- RouterOS versiyon bilgisi
- Uptime ve zaman bilgileri
- Güvenlik önerileri

## 🔧 Yapılandırma

### MikroTik API Ayarları
MikroTik'inizde API'yi etkinleştirin:
```
/ip service enable api
/ip service set api port=8728
```

### Güvenlik Ayarları
- Güçlü şifreler kullanın
- API erişimini kısıtlayın
- Firewall kurallarınızı kontrol edin
- RouterOS'u güncel tutun

## 🐛 Sorun Giderme

### **MikroTik'e bağlanamıyorum**
- IP adresi doğru mu kontrol edin
- API portu açık mı? (8728)
- Kullanıcı adı/şifre doğru mu?
- Firewall API'yi engelliyor mu?
- MikroTik cihazı erişilebilir durumda mı?

### **Giriş yapamıyorum**
- MikroTik kullanıcı bilgilerinizi doğru girdiğinizden emin olun
- IP adresi format kontrolü yapın (xxx.xxx.xxx.xxx)
- MikroTik API servisinin çalıştığını kontrol edin

### **Sayfa yüklenmez**
- Python sanal ortamı aktif mi?
- Bağımlılıklar yüklü mü?
- Port 5050 kullanımda mı?

### **CSS yüklenmez**
- `static/css/` klasörü var mı?
- CSS dosyaları doğru konumda mı?
- Flask static files çalışıyor mu?

## 🚀 Üretim Deployment

### 1. **Güvenlik ayarlarını yapın**
```python
# SECRET_KEY'i değiştirin
app.secret_key = 'super-gizli-production-key'

# HTTPS kullanın
app.run(host='0.0.0.0', port=5050, ssl_context='adhoc')
```

### 2. **Gunicorn ile çalıştırın**
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5050 app:app
```

### 3. **Firewall ayarları**
```bash
# Sadece gerekli portları açın
# 5050 (Web arayüz)
# 8728 (MikroTik API)
```

## 📱 Özellikler

- ✅ Responsive design (mobil uyumlu)
- ✅ Modern UI/UX
- ✅ Real-time data
- ✅ Search & filter
- ✅ Error handling
- ✅ Flash messages
- ✅ Session management
- ✅ MikroTik native authentication
- ✅ System information display
- ✅ IP format validation

## 🤝 Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 👨‍💻 Geliştirici

**Murat Sağ** ❤️

- Modern UI/UX Design
- Flask Backend Development  
- MikroTik API Integration
- Security Implementation

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## 📞 Destek

Sorunlar için GitHub Issues kullanın veya iletişime geçin.

---

**🎉 MikroTik Panel v1.0 - Professional Network Management** 🎉
