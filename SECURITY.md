# 🔒 MikroTik Panel Güvenlik Rehberi

## 🛡️ Güvenlik Özellikleri

### ✅ **Mevcut Güvenlik Önlemleri:**
- MikroTik native authentication
- Session tabanlı kimlik doğrulama
- Protected routes (decorator'lar ile)
- Session timeout (1 saat)
- Güvenli çıkış (session temizleme)
- Hata mesajları güvenli şekilde gösteriliyor
- IP format validation

### ⚠️ **Üretim İçin Önemli Ayarlar:**

## 1. 🔑 SECRET_KEY'i Değiştirin

```python
# Üretimde mutlaka değiştirin!
app.secret_key = 'SUPER_GIZLI_ANAHTAR_BURAYA_YAZIN'

# Veya ortam değişkeni kullanın:
import os
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-key')
```

## 2. 🌐 HTTPS Kullanın

```python
# Flask uygulamasını HTTPS ile çalıştırın
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, ssl_context='adhoc')
```

## 3. 🔧 MikroTik Güvenliği

### MikroTik Cihazında:
```bash
# Güçlü şifre kullanın
/user set admin password="cok-guclu-sifre-123!"

# API erişimini kısıtlayın
/ip service set api address=192.168.1.0/24

# Gereksiz servisleri kapatın
/ip service disable telnet,ftp,www

# Firewall kuralları ekleyin
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=8728 src-address=192.168.1.0/24
/ip firewall filter add chain=input action=drop protocol=tcp dst-port=8728
```

## 4. 🎯 Ağ Güvenliği

### Firewall Ayarları:
```bash
# Sadece gerekli portları açın
# 5050 (Web panel)
# 8728 (MikroTik API)

# VPN kullanımı önerilir
# Güvenlik kameralarına erişim gibi
```

## 5. 📝 Loglama (Opsiyonel)

```python
import logging

logging.basicConfig(
    filename='mikrotik_panel.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

# Login logları
@app.route('/login', methods=['POST'])
def login():
    if login_successful:
        app.logger.info(f'Login: {username} from {request.remote_addr}')
    else:
        app.logger.warning(f'Failed login: {username} from {request.remote_addr}')
```

## 6. 🔄 Oturum Yönetimi

```python
from datetime import timedelta

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS için
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

## 7. 🚀 Üretim Deployment

### Gunicorn ile çalıştırın:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5050 app:app
```

### Systemd service oluşturun:
```ini
[Unit]
Description=MikroTik Panel
After=network.target

[Service]
User=mikrotik
WorkingDirectory=/path/to/mikrotik-panel
ExecStart=/path/to/venv/bin/gunicorn -w 4 -b 0.0.0.0:5050 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

## 8. 📊 Monitoring (Opsiyonel)

```python
# Basit monitoring
@app.before_request
def before_request():
    app.logger.info(f'Request: {request.method} {request.path} from {request.remote_addr}')

# Sistem kaynaklarını kontrol et
import psutil

@app.route('/health')
def health_check():
    return {
        'status': 'healthy',
        'cpu': psutil.cpu_percent(),
        'memory': psutil.virtual_memory().percent
    }
```

## ⚠️ **Güvenlik Kontrol Listesi**

- [ ] SECRET_KEY değiştirildi
- [ ] HTTPS aktif
- [ ] MikroTik güçlü şifre
- [ ] API erişimi kısıtlandı
- [ ] Gereksiz servisler kapatıldı
- [ ] Firewall kuralları eklendi
- [ ] Loglama aktif (opsiyonel)
- [ ] Session güvenliği yapılandırıldı
- [ ] Monitoring aktif (opsiyonel)

## 🎯 **En Önemli Güvenlik Kuralları**

1. **MikroTik şifresini güçlü yapın**
2. **API erişimini kısıtlayın**
3. **HTTPS kullanın**
4. **SECRET_KEY'i değiştirin**
5. **Firewall kurallarını kontrol edin**

Bu kadar! Basit ama etkili güvenlik. 🛡️