#!/bin/bash

# MikroTik Panel Otomatik Kurulum Script'i
# AlmaLinux 9.4 için hazırlanmıştır
# Kullanım: curl -sSL https://raw.githubusercontent.com/KULLANICI/mikrotik-panel/main/install.sh | bash
# Veya: wget -O - https://raw.githubusercontent.com/KULLANICI/mikrotik-panel/main/install.sh | bash

set -e  # Hata durumunda script'i durdur

# Renkli çıktılar için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global değişkenler
INSTALL_DIR="/opt/mikrotik-panel"
SERVICE_USER="mikrotik"
SERVICE_NAME="mikrotik-panel"
WEB_PORT="5050"
TEMP_DIR="/tmp/mikrotik-panel-install"
LOG_FILE="/var/log/mikrotik-panel-install.log"

# Logo ve başlık
print_logo() {
    echo -e "${BLUE}"
    echo "
███╗   ███╗██╗██╗  ██╗██████╗  ██████╗ ████████╗██╗██╗  ██╗
████╗ ████║██║██║ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝██║██║ ██╔╝
██╔████╔██║██║█████╔╝ ██████╔╝██║   ██║   ██║   ██║█████╔╝ 
██║╚██╔╝██║██║██╔═██╗ ██╔══██╗██║   ██║   ██║   ██║██╔═██╗ 
██║ ╚═╝ ██║██║██║  ██╗██║  ██║╚██████╔╝   ██║   ██║██║  ██╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚═╝  ╚═╝

    ██████╗  █████╗ ███╗   ██╗███████╗██╗     
    ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║     
    ██████╔╝███████║██╔██╗ ██║█████╗  ██║     
    ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║     
    ██║     ██║  ██║██║ ╚████║███████╗███████╗
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"
    echo -e "${NC}"
}

# Log fonksiyonu
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

# Hata yakalama fonksiyonu
error_exit() {
    echo -e "${RED}❌ HATA: $1${NC}" >&2
    log_message "HATA: $1"
    cleanup
    exit 1
}

# Temizlik fonksiyonu
cleanup() {
    echo -e "${BLUE}🧹 Geçici dosyalar temizleniyor...${NC}"
    rm -rf $TEMP_DIR
}

# Sistem uyumluluğu kontrolü
check_system_compatibility() {
    echo -e "${BLUE}🔍 Sistem uyumluluğu kontrol ediliyor...${NC}"
    
    # OS kontrolü
    if [[ -f /etc/redhat-release ]]; then
        OS_VERSION=$(cat /etc/redhat-release)
        echo "   ✅ Kaynak dosyalar oluşturuldu"
    log_message "Kaynak dosyalar başarıyla oluşturuldu"
}

# Sistem paketlerini güncelle ve kur
install_system_packages() {
    echo -e "${BLUE}📦 Sistem paketleri kuruluyor...${NC}"
    
    # Package manager güncelleme
    if command -v dnf &> /dev/null; then
        dnf update -y &>> $LOG_FILE
        dnf install -y epel-release &>> $LOG_FILE
        dnf install -y python3 python3-pip python3-venv git curl wget \
                       firewalld systemd nginx supervisor &>> $LOG_FILE
    elif command -v yum &> /dev/null; then
        yum update -y &>> $LOG_FILE
        yum install -y epel-release &>> $LOG_FILE
        yum install -y python3 python3-pip python3-venv git curl wget \
                       firewalld systemd nginx supervisor &>> $LOG_FILE
    else
        error_exit "Desteklenen paket yöneticisi bulunamadı (dnf/yum)"
    fi
    
    # Python pip güncelleme
    python3 -m pip install --upgrade pip &>> $LOG_FILE
    
    echo "   ✅ Sistem paketleri kuruldu"
    log_message "Sistem paketleri başarıyla kuruldu"
}

# Servis kullanıcısı oluştur
create_service_user() {
    echo -e "${BLUE}👤 Servis kullanıcısı oluşturuluyor...${NC}"
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d $INSTALL_DIR -m $SERVICE_USER
        echo "   ✅ Kullanıcı '$SERVICE_USER' oluşturuldu"
    else
        echo "   ⚠️  Kullanıcı '$SERVICE_USER' zaten mevcut"
    fi
    
    # Kullanıcı gruplarına ekleme
    usermod -a -G systemd-journal $SERVICE_USER
    
    log_message "Servis kullanıcısı hazırlandı: $SERVICE_USER"
}

# Uygulama dosyalarını kur
install_application_files() {
    echo -e "${BLUE}📁 Uygulama dosyları kuruluyor...${NC}"
    
    # Eski kurulumu temizle
    if [[ -d $INSTALL_DIR ]]; then
        echo "   🧹 Eski kurulum temizleniyor..."
        systemctl stop $SERVICE_NAME 2>/dev/null || true
        rm -rf $INSTALL_DIR
    fi
    
    # Yeni dizin oluştur
    mkdir -p $INSTALL_DIR
    
    # Dosyaları kopyala
    cp -r $TEMP_DIR/* $INSTALL_DIR/
    
    # Sahiplik ayarları
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    chmod -R 755 $INSTALL_DIR
    chmod 644 $INSTALL_DIR/app.py
    
    echo "   ✅ Uygulama dosyları kuruldu: $INSTALL_DIR"
    log_message "Uygulama dosyları kuruldu: $INSTALL_DIR"
}

# Python Virtual Environment kur
setup_python_environment() {
    echo -e "${BLUE}🐍 Python Virtual Environment kuruluyor...${NC}"
    
    # Virtual environment oluştur
    sudo -u $SERVICE_USER python3 -m venv $INSTALL_DIR/venv
    
    # Pip güncelle
    sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install --upgrade pip &>> $LOG_FILE
    
    # Gereksinimleri kur
    if [[ -f $INSTALL_DIR/requirements.txt ]]; then
        sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install -r $INSTALL_DIR/requirements.txt &>> $LOG_FILE
        echo "   ✅ Python paketleri kuruldu"
    else
        # Fallback - temel paketleri manuel kur
        sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install Flask==3.0.0 librouteros==3.2.1 gunicorn==21.2.0 &>> $LOG_FILE
        echo "   ✅ Temel Python paketleri kuruldu"
    fi
    
    log_message "Python Virtual Environment hazırlandı"
}

# Systemd service dosyası oluştur
create_systemd_service() {
    echo -e "${BLUE}⚙️  Systemd service yapılandırılıyor...${NC}"
    
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=MikroTik Panel Web Application
Documentation=https://github.com/KULLANICI/mikrotik-panel
After=network.target network-online.target
Wants=network-online.target
RequiresMountsFor=$INSTALL_DIR

[Service]
Type=exec
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONPATH=$INSTALL_DIR
Environment=FLASK_ENV=production
Environment=FLASK_APP=app.py
Environment=PORT=$WEB_PORT
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --bind 0.0.0.0:$WEB_PORT --workers 4 --timeout 120 --keepalive 2 --max-requests 1000 --preload app:app
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

# Output kontrolü
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mikrotik-panel

# Güvenlik ayarları
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Kaynak limitleri
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
    
    echo "   ✅ Systemd service dosyası oluşturuldu"
    log_message "Systemd service yapılandırıldı"
}

# Firewall yapılandırması
configure_firewall() {
    echo -e "${BLUE}🛡️  Firewall yapılandırılıyor...${NC}"
    
    # Firewall'ı etkinleştir
    systemctl enable firewalld &>> $LOG_FILE
    systemctl start firewalld &>> $LOG_FILE
    
    # Port açma
    firewall-cmd --permanent --add-port=$WEB_PORT/tcp &>> $LOG_FILE
    
    # HTTP ve HTTPS portları (opsiyonel)
    firewall-cmd --permanent --add-service=http &>> $LOG_FILE
    firewall-cmd --permanent --add-service=https &>> $LOG_FILE
    
    # Kuralları yeniden yükle
    firewall-cmd --reload &>> $LOG_FILE
    
    # Firewall durumunu kontrol et
    if firewall-cmd --list-ports | grep -q "$WEB_PORT/tcp"; then
        echo "   ✅ Firewall port $WEB_PORT açıldı"
    else
        echo "   ⚠️  Firewall port açılımı doğrulanamadı"
    fi
    
    log_message "Firewall yapılandırıldı - Port: $WEB_PORT"
}

# Nginx reverse proxy yapılandırması (opsiyonel)
configure_nginx() {
    echo -e "${BLUE}🌍 Nginx reverse proxy yapılandırılıyor...${NC}"
    
    # Nginx'i etkinleştir
    systemctl enable nginx &>> $LOG_FILE
    
    # Nginx config dosyası oluştur
    cat > /etc/nginx/conf.d/mikrotik-panel.conf << EOF
server {
    listen 80;
    server_name _;
    
    # Güvenlik başlıkları
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Static dosyalar için cache
    location /static/ {
        alias $INSTALL_DIR/static/;
        expires 1d;
        add_header Cache-Control "public, immutable";
    }
    
    # Ana uygulama
    location / {
        proxy_pass http://127.0.0.1:$WEB_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeout ayarları
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer ayarları
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # Health check
    location /health {
        proxy_pass http://127.0.0.1:$WEB_PORT/health;
        access_log off;
    }
}
EOF
    
    # Nginx yapılandırmasını test et
    if nginx -t &>> $LOG_FILE; then
        systemctl start nginx &>> $LOG_FILE
        echo "   ✅ Nginx reverse proxy yapılandırıldı"
    else
        echo "   ⚠️  Nginx yapılandırma hatası, atlanıyor..."
    fi
    
    log_message "Nginx reverse proxy yapılandırıldı"
}

# Log rotation yapılandırması
configure_log_rotation() {
    echo -e "${BLUE}📝 Log rotation yapılandırılıyor...${NC}"
    
    cat > /etc/logrotate.d/mikrotik-panel << EOF
/var/log/mikrotik-panel/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    create 644 $SERVICE_USER $SERVICE_USER
}
EOF
    
    # Log dizini oluştur
    mkdir -p /var/log/mikrotik-panel
    chown $SERVICE_USER:$SERVICE_USER /var/log/mikrotik-panel
    
    echo "   ✅ Log rotation yapılandırıldı"
    log_message "Log rotation yapılandırıldı"
}

# Service'i başlat
start_services() {
    echo -e "${BLUE}🚀 Servisler başlatılıyor...${NC}"
    
    # Systemd daemon yenile
    systemctl daemon-reload
    
    # MikroTik Panel servisini etkinleştir ve başlat
    systemctl enable $SERVICE_NAME &>> $LOG_FILE
    systemctl start $SERVICE_NAME
    
    # Başlatma sonrası bekleme
    echo "   ⏳ Servis başlatılması bekleniyor..."
    sleep 10
    
    # Service durumu kontrol
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "   ✅ MikroTik Panel servisi başlatıldı"
    else
        echo "   ❌ MikroTik Panel servisi başlatılamadı"
        echo "   📋 Servis logları:"
        journalctl -u $SERVICE_NAME --no-pager -n 20
        error_exit "Servis başlatma hatası"
    fi
    
    log_message "Servisler başlatıldı"
}

# Post-installation configuration
post_installation_setup() {
    echo -e "${BLUE}🔧 Kurulum sonrası yapılandırma...${NC}"
    
    # Sistem kaynaklarını optimize et
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    echo "net.core.somaxconn=65535" >> /etc/sysctl.conf
    sysctl -p &>> $LOG_FILE
    
    # Cron job ekle (günlük sağlık kontrolü)
    cat > /etc/cron.d/mikrotik-panel << EOF
# MikroTik Panel günlük sağlık kontrolü
0 2 * * * $SERVICE_USER curl -s http://localhost:$WEB_PORT/health > /dev/null || systemctl restart $SERVICE_NAME
EOF
    
    # SELinux yapılandırması (eğer aktifse)
    if command -v getenforce &> /dev/null && [[ $(getenforce) != "Disabled" ]]; then
        setsebool -P httpd_can_network_connect 1 &>> $LOG_FILE
        semanage port -a -t http_port_t -p tcp $WEB_PORT &>> $LOG_FILE 2>&1 || true
    fi
    
    echo "   ✅ Kurulum sonrası yapılandırma tamamlandı"
    log_message "Post-installation setup tamamlandı"
}

# Kurulum doğrulama
verify_installation() {
    echo -e "${BLUE}🔍 Kurulum doğrulanıyor...${NC}"
    
    local verification_failed=0
    
    # Service durumu
    if systemctl is-active --quiet $SERVICE_NAME; then
        SERVICE_STATUS="${GREEN}✅ Aktif${NC}"
    else
        SERVICE_STATUS="${RED}❌ Pasif${NC}"
        verification_failed=1
    fi
    
    # Port dinleme kontrolü
    if ss -tlnp | grep -q ":$WEB_PORT"; then
        PORT_STATUS="${GREEN}✅ Dinliyor${NC}"
    else
        PORT_STATUS="${RED}❌ Kapalı${NC}"
        verification_failed=1
    fi
    
    # Web erişim testi
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$WEB_PORT 2>/dev/null || echo "000")
    if [[ $http_code == "200" ]] || [[ $http_code == "302" ]]; then
        WEB_STATUS="${GREEN}✅ Erişilebilir${NC}"
    else
        WEB_STATUS="${RED}❌ Erişilemiyor (HTTP: $http_code)${NC}"
        verification_failed=1
    fi
    
    # Disk kullanımı
    local disk_usage=$(df $INSTALL_DIR | awk 'NR==2{print $5}' | sed 's/%//')
    if [[ $disk_usage -lt 90 ]]; then
        DISK_STATUS="${GREEN}✅ Normal (%$disk_usage)${NC}"
    else
        DISK_STATUS="${YELLOW}⚠️  Yüksek (%$disk_usage)${NC}"
    fi
    
    # Bellek kullanımı
    local mem_usage=$(free | awk 'NR==2{printf "%.0f", $3/$2*100}')
    if [[ $mem_usage -lt 80 ]]; then
        MEM_STATUS="${GREEN}✅ Normal (%$mem_usage)${NC}"
    else
        MEM_STATUS="${YELLOW}⚠️  Yüksek (%$mem_usage)${NC}"
    fi
    
    if [[ $verification_failed -eq 1 ]]; then
        echo -e "${RED}❌ Kurulum doğrulama başarısız!${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Kurulum doğrulama başarılı!${NC}"
        return 0
    fi
}

# Kurulum raporu oluştur
generate_installation_report() {
    local server_ip=$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1{print $7}' || echo "127.0.0.1")
    local install_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Terminal raporu
    clear
    print_logo
    
    echo -e "${GREEN}"
    echo "
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║               🎉 KURULUM BAŞARIYLA TAMAMLANDI! 🎉             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    "
    echo -e "${NC}"
    
    echo -e "${CYAN}📋 KURULUM RAPORU:${NC}"
    echo "=" * 70
    echo -e "   📅 Kurulum Zamanı  : ${YELLOW}$install_time${NC}"
    echo -e "   🖥️  Sunucu IP       : ${YELLOW}$server_ip${NC}"
    echo -e "   🌐 Web Adresi      : ${YELLOW}http://$server_ip:$WEB_PORT${NC}"
    echo -e "   ⚙️  Service Durumu  : $SERVICE_STATUS"
    echo -e "   🔌 Port Durumu     : $PORT_STATUS"
    echo -e "   🌍 Web Erişimi     : $WEB_STATUS"
    echo -e "   💾 Disk Kullanımı  : $DISK_STATUS"
    echo -e "   🧠 Bellek Kullanımı: $MEM_STATUS"
    echo -e "   📁 Kurulum Yeri    : ${YELLOW}$INSTALL_DIR${NC}"
    echo -e "   👤 Service User    : ${YELLOW}$SERVICE_USER${NC}"
    echo -e "   🔄 Otomatik Başlatma: ${GREEN}✅ Aktif${NC}"
    echo "=" * 70
    
    echo -e "${GREEN}🚀 MikroTik Panel başarılı bir şekilde kuruldu!${NC}"
    echo -e "${CYAN}🌐 Panel şu adreste çalışıyor: ${YELLOW}http://$server_ip:$WEB_PORT${NC}"
    echo ""
    
    echo -e "${BLUE}📱 ERİŞİM BİLGİLERİ:${NC}"
    echo -e "   • Yerel erişim      : ${YELLOW}http://localhost:$WEB_PORT${NC}"
    echo -e "   • Ağ erişimi        : ${YELLOW}http://$server_ip:$WEB_PORT${NC}"
    echo -e "   • Nginx proxy (80)  : ${YELLOW}http://$server_ip${NC}"
    echo ""
    
    echo -e "${PURPLE}🔧 YÖNETİM KOMUTLARI:${NC}"
    echo -e "   • Durumu kontrol et : ${YELLOW}systemctl status $SERVICE_NAME${NC}"
    echo -e "   • Logları görüntüle : ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
    echo -e "   • Yeniden başlat    : ${YELLOW}systemctl restart $SERVICE_NAME${NC}"
    echo -e "   • Durdur           : ${YELLOW}systemctl stop $SERVICE_NAME${NC}"
    echo -e "   • Güncellemeler    : ${YELLOW}cd $INSTALL_DIR && git pull${NC}"
    echo ""
    
    echo -e "${YELLOW}🔒 GÜVENLİK TAVSİYELERİ:${NC}"
    echo -e "   • MikroTik cihazınızda güçlü şifre kullanın"
    echo -e "   • API erişimini sadece güvenilir IP'lere kısıtlayın"
    echo -e "   • Firewall kurallarınızı düzenli kontrol edin"
    echo -e "   • RouterOS'u güncel tutun"
    echo -e "   • SSL sertifikası ekleyerek HTTPS kullanın"
    echo ""
    
    echo -e "${CYAN}📞 DESTEK VE KAYNAK:${NC}"
    echo -e "   • GitHub     : ${YELLOW}https://github.com/KULLANICI/mikrotik-panel${NC}"
    echo -e "   • Dokümantasyon: ${YELLOW}$INSTALL_DIR/README.md${NC}"
    echo -e "   • Log Dosyası   : ${YELLOW}$LOG_FILE${NC}"
    echo -e "   • Servis Logları: ${YELLOW}journalctl -u $SERVICE_NAME${NC}"
    echo ""
    
    # Dosya raporunu oluştur
    cat > $INSTALL_DIR/installation-report.txt << EOF
MikroTik Panel Kurulum Raporu
================================
Kurulum Zamanı: $install_time
Sunucu IP: $server_ip
Web Adresi: http://$server_ip:$WEB_PORT
Kurulum Dizini: $INSTALL_DIR
Service Kullanıcısı: $SERVICE_USER
Service Adı: $SERVICE_NAME

Kurulum Bileşenleri:
- Flask Web Framework: ✅
- MikroTik API Library: ✅
- Gunicorn WSGI Server: ✅
- Nginx Reverse Proxy: ✅
- Systemd Service: ✅
- Firewall Configuration: ✅
- Log Rotation: ✅

Yönetim Komutları:
systemctl status $SERVICE_NAME
systemctl restart $SERVICE_NAME
journalctl -u $SERVICE_NAME -f

Erişim Bilgileri:
- Ana Panel: http://$server_ip:$WEB_PORT
- Sağlık Kontrolü: http://$server_ip:$WEB_PORT/health
- Nginx Proxy: http://$server_ip (port 80)

Güvenlik Notları:
- MikroTik API bağlantıları şifrelenmemiştir
- Güçlü şifreler kullanın
- Firewall kurallarını kontrol edin
- SSL sertifikası ekleyin (HTTPS için)

Bu rapor otomatik olarak oluşturulmuştur.
EOF
    
    chown $SERVICE_USER:$SERVICE_USER $INSTALL_DIR/installation-report.txt
    
    # Log dosyasına kurulum başarısını kaydet
    log_message "=== KURULUM BAŞARIYLA TAMAMLANDI ==="
    log_message "Sunucu IP: $server_ip"
    log_message "Web Adresi: http://$server_ip:$WEB_PORT"
    log_message "Kurulum Dizini: $INSTALL_DIR"
    log_message "Service: $SERVICE_NAME (aktif)"
}

# Ana kurulum fonksiyonu
main() {
    print_logo
    
    echo -e "${GREEN}🚀 MikroTik Panel Otomatik Kurulum Script'i${NC}"
    echo -e "${CYAN}📅 Versiyon: 1.0 - $(date +'%Y-%m-%d')${NC}"
    echo -e "${YELLOW}🔧 AlmaLinux 9.4 için optimize edilmiştir${NC}"
    echo "=" * 70
    
    # Root kontrolü
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}❌ Bu script root kullanıcısı ile çalıştırılmalıdır!${NC}"
       echo -e "${YELLOW}💡 Kullanım: sudo $0${NC}"
       exit 1
    fi
    
    # Log dosyasını başlat
    echo "MikroTik Panel Kurulum Başlangıç: $(date)" > $LOG_FILE
    
    # Sistem bilgilerini göster
    echo -e "${BLUE}🖥️  Sistem Bilgileri:${NC}"
    echo "   OS: $(cat /etc/redhat-release 2>/dev/null || echo 'Bilinmeyen Linux')"
    echo "   Hostname: $(hostname)"
    echo "   IP: $(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1{print $7}' || echo '127.0.0.1')"
    echo "   Kullanıcı: $(whoami)"
    echo "   Arch: $(uname -m)"
    echo ""
    
    # Kullanıcı onayı
    echo -e "${YELLOW}⚠️  Bu script aşağıdaki işlemleri yapacak:${NC}"
    echo "   • Sistem paketlerini güncelleyecek"
    echo "   • Python3 ve gerekli paketleri kuracak"
    echo "   • MikroTik Panel kaynak kodlarını oluşturacak"
    echo "   • Servis kullanıcısı oluşturacak ($SERVICE_USER)"
    echo "   • Systemd service yapılandıracak"
    echo "   • Nginx reverse proxy kuracak"
    echo "   • Firewall ayarlarını yapacak (port $WEB_PORT)"
    echo "   • Otomatik başlatmayı aktifleştirecek"
    echo ""
    
    read -p "$(echo -e "${GREEN}Devam etmek istiyor musunuz? [y/N]: ${NC}")" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}❌ Kurulum iptal edildi.${NC}"
        exit 1
    fi
    
    # Kurulum başlangıcı
    echo ""
    echo -e "${GREEN}🎯 MikroTik Panel kurulumu başlatılıyor...${NC}"
    echo "📋 Tüm işlemler log dosyasına kaydediliyor: $LOG_FILE"
    sleep 3
    
    # Kurulum adımları
    trap cleanup EXIT
    
    echo -e "\n${CYAN}========== ADIM 1: SİSTEM KONTROLÜ ==========${NC}"
    check_system_compatibility
    check_port_availability
    
    echo -e "\n${CYAN}========== ADIM 2: PAKET KURULUMU ==========${NC}"
    install_system_packages
    
    echo -e "\n${CYAN}========== ADIM 3: KAYNAK DOSYALAR =========${NC}"
    rm -rf $TEMP_DIR
    mkdir -p $TEMP_DIR
    cd $TEMP_DIR
    create_source_files
    
    echo -e "\n${CYAN}========== ADIM 4: KULLANICI VE DİZİN ======${NC}"
    create_service_user
    install_application_files
    
    echo -e "\n${CYAN}========== ADIM 5: PYTHON ORTAMI ===========${NC}"
    setup_python_environment
    
    echo -e "\n${CYAN}========== ADIM 6: SİSTEM SERVİSLERİ =======${NC}"
    create_systemd_service
    configure_firewall
    configure_nginx
    configure_log_rotation
    
    echo -e "\n${CYAN}========== ADIM 7: SERVİS BAŞLATMA =========${NC}"
    start_services
    
    echo -e "\n${CYAN}========== ADIM 8: KURULUM SONRASI =========${NC}"
    post_installation_setup
    
    echo -e "\n${CYAN}========== ADIM 9: DOĞRULAMA ===============${NC}"
    if verify_installation; then
        echo -e "\n${CYAN}========== ADIM 10: RAPOR ==================${NC}"
        generate_installation_report
        
        echo -e "${GREEN}✅ Kurulum başarılı! Panel çalışıyor.${NC}"
        echo -e "${GREEN}🎯 Tarayıcınızda http://$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1{print $7}' || echo '127.0.0.1'):$WEB_PORT adresini ziyaret edin.${NC}"
        exit 0
    else
        echo -e "${RED}❌ Kurulum tamamlandı ancak doğrulama başarısız!${NC}"
        echo -e "${YELLOW}🔧 Lütfen logları kontrol edin: journalctl -u $SERVICE_NAME${NC}"
        echo -e "${YELLOW}📋 Detaylı log: $LOG_FILE${NC}"
        exit 1
    fi
}

# Script'i çalıştır
main "$@" Desteklenen OS: $OS_VERSION"
    else
        error_exit "Desteklenmeyen işletim sistemi. Bu script Red Hat tabanlı sistemler için tasarlanmıştır."
    fi
    
    # Python3 varlığı kontrolü
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        echo "   ✅ Python bulundu: $PYTHON_VERSION"
    fi
    
    # Network bağlantısı kontrolü
    if ping -c 1 8.8.8.8 &> /dev/null; then
        echo "   ✅ İnternet bağlantısı aktif"
    else
        error_exit "İnternet bağlantısı gerekli. Lütfen ağ bağlantınızı kontrol edin."
    fi
    
    # Disk alanı kontrolü
    AVAILABLE_SPACE=$(df / | awk 'NR==2{print $4}')
    if [[ $AVAILABLE_SPACE -gt 1048576 ]]; then  # 1GB = 1048576 KB
        echo "   ✅ Yeterli disk alanı mevcut"
    else
        error_exit "En az 1GB boş disk alanı gerekli."
    fi
    
    log_message "Sistem uyumluluk kontrolü başarılı"
}

# Port kontrolü
check_port_availability() {
    echo -e "${BLUE}🔌 Port $WEB_PORT uygunluk kontrolü...${NC}"
    
    if ss -tlnp | grep -q ":$WEB_PORT"; then
        echo -e "${YELLOW}⚠️  Port $WEB_PORT kullanımda. Çakışan servis durduruluyor...${NC}"
        # Port kullanan servisi bul ve durdur
        PID=$(ss -tlnp | grep ":$WEB_PORT" | awk '{print $6}' | cut -d',' -f2 | cut -d'=' -f2)
        if [[ -n $PID ]]; then
            kill -9 $PID 2>/dev/null || true
            sleep 2
        fi
    fi
    
    if ! ss -tlnp | grep -q ":$WEB_PORT"; then
        echo "   ✅ Port $WEB_PORT kullanılabilir"
    else
        error_exit "Port $WEB_PORT hala kullanımda. Manuel müdahale gerekli."
    fi
}

# Kaynak dosyaları oluştur fonksiyonu
# create_source_files() fonksiyonunu bu versiyonla değiştirin

create_source_files() {
    echo -e "${BLUE}📝 Kaynak dosyalar oluşturuluyor...${NC}"
    
    # GitHub'dan indirmeyi dene
    if command -v git &> /dev/null; then
        echo "   🔄 GitHub'dan kaynak kodları indiriliyor..."
        if git clone https://github.com/KULLANICI/mikrotik-panel.git $TEMP_DIR &>> $LOG_FILE; then
            echo "   ✅ GitHub'dan başarıyla indirildi"
            return 0
        else
            echo "   ⚠️  GitHub indirme başarısız, yerel dosyalar oluşturuluyor..."
        fi
    fi
    
    # Dizin yapısını oluştur
    mkdir -p $TEMP_DIR/{templates,static/{css,js}}
    
    # requirements.txt - Güncel versiyonlar
    cat > $TEMP_DIR/requirements.txt << 'EOF'
Flask==3.0.0
librouteros==3.2.1
gunicorn==21.2.0
Werkzeug==3.0.0
EOF

    # Ana Flask uygulaması - TAM VERSİYON
    cat > $TEMP_DIR/app.py << 'EOF'
from flask import Flask, render_template, request, redirect, url_for, session, flash
from librouteros import connect
from functools import wraps
import secrets
import os

app = Flask(__name__)

# Güvenlik yapılandırması
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 saat

# MikroTik bağlantı bilgileri
MIKROTIK_HOST = '192.168.254.142'
MIKROTIK_PORT = 8728

def mikrotik_login(username=None, password=None, host=None):
    """MikroTik'e bağlanır. Eğer kullanıcı bilgileri verilmezse session'dan alır."""
    try:
        if username and password:
            # Giriş için test bağlantısı
            return connect(
                host=host or MIKROTIK_HOST,
                username=username,
                password=password,
                port=MIKROTIK_PORT,
                encoding='utf-8'
            )
        else:
            # Normal işlemler için session'dan bilgileri al
            return connect(
                host=session.get('mikrotik_host', MIKROTIK_HOST),
                username=session['mikrotik_user'],
                password=session['mikrotik_pass'],
                port=MIKROTIK_PORT,
                encoding='utf-8'
            )
    except Exception as e:
        raise Exception(f"MikroTik bağlantı hatası: {str(e)}")

# Template context için request objesini kullanılabilir yap
@app.context_processor
def inject_request():
    return dict(request=request)

# Login gerekli decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'mikrotik_user' not in session:
            flash('Bu sayfaya erişmek için giriş yapmalısınız.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'mikrotik_user' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        mikrotik_host = request.form.get('mikrotik_host', MIKROTIK_HOST).strip()
        remember_me = request.form.get('remember_me') == 'on'
        
        if not username or not password:
            flash('Kullanıcı adı ve şifre gereklidir!', 'error')
            return render_template('login.html')
        
        try:
            # MikroTik'e bağlanarak kullanıcı doğrulaması yap
            api = mikrotik_login(username, password, mikrotik_host)
            
            # Bağlantı başarılı ise sistem bilgilerini al
            system_resource = list(api.path('system', 'resource'))[0]
            system_identity = list(api.path('system', 'identity'))[0]
            
            # Session'a kullanıcı bilgilerini kaydet
            session['mikrotik_user'] = username
            session['mikrotik_pass'] = password  # Dikkat: Gerçek uygulamada encrypt edilmeli
            session['mikrotik_host'] = mikrotik_host
            session['user_name'] = username
            session['system_name'] = system_identity.get('name', 'MikroTik')
            session['board_name'] = system_resource.get('board-name', 'Unknown')
            
            if remember_me:
                session.permanent = True
            
            flash(f'Hoş geldiniz, {username}! {system_identity.get("name", "MikroTik")} sistemine bağlandınız.', 'success')
            
            # Next parametresi varsa oraya yönlendir
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f'Giriş başarısız: {str(e)}', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_name = session.get('user_name', 'Kullanıcı')
    session.clear()
    flash(f'Güvenli çıkış yapıldı. Görüşürüz {user_name}!', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    try:
        api = mikrotik_login()
        nat_rules = list(api.path('ip', 'firewall', 'nat'))
        return render_template('index.html', rules=nat_rules)
    except Exception as e:
        flash(f'MikroTik bağlantı hatası: {str(e)}', 'error')
        return render_template('index.html', rules=[])

@app.route('/add_rule', methods=['POST'])
@login_required
def add_rule():
    try:
        name = request.form['name']
        dst_port = request.form['external_port']
        to_ip = request.form['internal_ip']
        to_port = request.form['internal_port']

        api = mikrotik_login()

        api.path('ip', 'firewall', 'nat').add(
            **{
                'chain': 'dstnat',
                'action': 'dst-nat',
                'protocol': 'tcp',
                'dst-port': dst_port,
                'to-addresses': to_ip,
                'to-ports': to_port,
                'comment': name
            }
        )
        
        flash(f'"{name}" kuralı başarıyla eklendi!', 'success')
    except Exception as e:
        flash(f'Kural eklenirken hata oluştu: {str(e)}', 'error')

    return redirect(url_for('index'))

@app.route('/delete_rule', methods=['POST'])
@login_required
def delete_rule():
    rule_id = request.form.get('rule_id')
    try:
        api = mikrotik_login()
        api.path('ip', 'firewall', 'nat').remove(rule_id)
        flash('Kural başarıyla silindi!', 'success')
    except Exception as e:
        flash(f'Kural silinirken hata oluştu: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/ip_monitor')
@login_required
def ip_monitor():
    try:
        api = mikrotik_login()
        
        # DHCP lease'leri al
        dhcp_leases = list(api.path('ip', 'dhcp-server', 'lease'))
        
        # ARP tablosunu al
        arp_table = list(api.path('ip', 'arp'))
        
        # IP adresi listesini al
        addresses = list(api.path('ip', 'address'))
        
        # Tüm IP aralıklarını tanımla
        target_ranges = ['10.10.10.', '20.20.20.', '192.168.254.']
        
        # DHCP lease'leri filtrele
        filtered_leases = []
        for lease in dhcp_leases:
            ip = lease.get('address', '')
            if any(ip.startswith(range_prefix) for range_prefix in target_ranges):
                filtered_leases.append(lease)
        
        # ARP tablosunu filtrele
        filtered_arp = []
        for arp in arp_table:
            ip = arp.get('address', '')
            if any(ip.startswith(range_prefix) for range_prefix in target_ranges):
                filtered_arp.append(arp)
        
        # IP kullanım durumunu analiz et
        used_ips = set()
        for lease in filtered_leases:
            if lease.get('address'):
                used_ips.add(lease.get('address'))
        
        for arp in filtered_arp:
            if arp.get('address'):
                used_ips.add(arp.get('address'))
        
        return render_template('ip_monitor.html', 
                             dhcp_leases=filtered_leases, 
                             arp_table=filtered_arp,
                             used_ips=sorted(used_ips),
                             addresses=addresses)
    except Exception as e:
        flash(f'IP veriler yüklenirken hata oluştu: {str(e)}', 'error')
        return render_template('ip_monitor.html', 
                             dhcp_leases=[], 
                             arp_table=[],
                             used_ips=[],
                             addresses=[])

@app.route('/profile')
@login_required
def profile():
    try:
        api = mikrotik_login()
        # Sistem bilgilerini al
        system_resource = list(api.path('system', 'resource'))[0]
        system_identity = list(api.path('system', 'identity'))[0]
        system_clock = list(api.path('system', 'clock'))[0]
        
        system_info = {
            'identity': system_identity.get('name', 'MikroTik'),
            'board_name': system_resource.get('board-name', 'Unknown'),
            'version': system_resource.get('version', 'Unknown'),
            'architecture': system_resource.get('architecture-name', 'Unknown'),
            'cpu': system_resource.get('cpu', 'Unknown'),
            'cpu_count': system_resource.get('cpu-count', 'Unknown'),
            'memory': system_resource.get('total-memory', 'Unknown'),
            'uptime': system_resource.get('uptime', 'Unknown'),
            'current_time': system_clock.get('time', 'Unknown'),
            'date': system_clock.get('date', 'Unknown')
        }
        
        return render_template('profile.html', system_info=system_info)
    except Exception as e:
        flash(f'Sistem bilgileri alınırken hata oluştu: {str(e)}', 'error')
        return render_template('profile.html', system_info={})

@app.route('/health')
def health():
    """Sağlık kontrolü endpoint'i"""
    try:
        # Temel sistem kontrolü
        return {
            'status': 'healthy',
            'version': '1.0.0',
            'mikrotik_host': session.get('mikrotik_host', 'Not configured'),
            'timestamp': str(datetime.utcnow()) if 'datetime' in globals() else 'Unknown'
        }, 200
    except Exception as e:
        return {'status': 'error', 'message': str(e)}, 500

if __name__ == '__main__':
    print("🚀 MikroTik Panel başlatılıyor...")
    print(f"📡 MikroTik Host: {MIKROTIK_HOST}:{MIKROTIK_PORT}")
    print(f"🌐 Web Server: http://0.0.0.0:{os.environ.get('PORT', 5050)}")
    print("🔧 Production Mode: Aktif")
    print("=" * 50)
    
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)
EOF

    # Base HTML şablonu
    cat > $TEMP_DIR/templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}MikroTik Panel{% endblock %}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            display: flex;
            flex-direction: column;
        }
        .container { max-width: 1400px; margin: 0 auto; flex: 1; }
        .header { text-align: center; color: white; margin-bottom: 40px; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .nav-buttons { display: flex; justify-content: center; gap: 20px; margin-bottom: 40px; }
        .nav-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 12px 25px;
            border: none;
            border-radius: 25px;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s ease;
            font-weight: 600;
        }
        .nav-btn:hover { background: rgba(255,255,255,0.3); transform: translateY(-2px); }
        .nav-btn.active { background: white; color: #667eea; }
        .card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 30px;
            margin-bottom: 30px;
            transition: transform 0.3s ease;
        }
        .card:hover { transform: translateY(-5px); }
        .alert {
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
    </style>
    {% block extra_css %}{% endblock %}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> {% block page_title %}MikroTik Panel{% endblock %}</h1>
            <p>{% block page_subtitle %}Ağ cihazlarınızı kolayca yönetin{% endblock %}</p>
            
            {% if session.mikrotik_user %}
            <div style="margin-top: 20px; background: rgba(255,255,255,0.2); padding: 10px 20px; border-radius: 25px; display: inline-block;">
                <i class="fas fa-user-cog"></i> 
                <strong>{{ session.user_name }}@{{ session.system_name or 'MikroTik' }}</strong>
                <span style="opacity: 0.8; margin-left: 10px;">({{ session.mikrotik_host }})</span>
                <a href="{{ url_for('logout') }}" style="color: white; margin-left: 15px; text-decoration: none; opacity: 0.8;" 
                   onclick="return confirm('Çıkış yapmak istediğinizden emin misiniz?')">
                    <i class="fas fa-sign-out-alt"></i> Çıkış
                </a>
            </div>
            {% endif %}
        </div>

        <div class="nav-buttons">
            <a href="/" class="nav-btn {% if request.endpoint == 'index' %}active{% endif %}">
                <i class="fas fa-home"></i> NAT Kuralları
            </a>
            <a href="/ip_monitor" class="nav-btn {% if request.endpoint == 'ip_monitor' %}active{% endif %}">
                <i class="fas fa-chart-line"></i> IP Monitör
            </a>
            <a href="/profile" class="nav-btn {% if request.endpoint == 'profile' %}active{% endif %}">
                <i class="fas fa-user-cog"></i> Profil
            </a>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div style="margin-bottom: 30px;">
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">
                            {% if category == 'success' %}
                                <i class="fas fa-check-circle"></i>
                            {% elif category == 'error' %}
                                <i class="fas fa-exclamation-circle"></i>
                            {% elif category == 'warning' %}
                                <i class="fas fa-exclamation-triangle"></i>
                            {% else %}
                                <i class="fas fa-info-circle"></i>
                            {% endif %}
                            {{ message }}
                        </div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <div style="text-align: center; color: white; padding: 30px 20px; margin-top: 50px; background: rgba(255, 255, 255, 0.1); border-radius: 15px;">
        <div style="display: flex; justify-content: center; align-items: center; gap: 15px; flex-wrap: wrap;">
            <div style="display: flex; align-items: center; gap: 10px; font-size: 1.1rem; font-weight: 600;">
                <i class="fas fa-code" style="font-size: 1.5rem; color: #ffd700;"></i>
                MikroTik Panel v1.0
            </div>
            <div style="height: 30px; width: 2px; background: rgba(255, 255, 255, 0.3);"></div>
            <div style="display: flex; align-items: center; gap: 8px; font-size: 1rem;">
                <i class="fas fa-heart" style="color: #ff6b6b;"></i>
                Tasarlayan: <strong>Murat Sağ</strong>
            </div>
        </div>
    </div>

    {% block extra_js %}{% endblock %}
</body>
</html>
EOF

    # Login sayfası
    cat > $TEMP_DIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MikroTik Panel - Giriş</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        .particles { position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; }
        .particle {
            position: absolute;
            width: 4px; height: 4px;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            animation: float 6s ease-in-out infinite;
        }
        .particle:nth-child(1) { left: 20%; animation-delay: 0s; }
        .particle:nth-child(2) { left: 40%; animation-delay: 2s; }
        .particle:nth-child(3) { left: 60%; animation-delay: 4s; }
        .particle:nth-child(4) { left: 80%; animation-delay: 1s; }
        .particle:nth-child(5) { left: 10%; animation-delay: 3s; }
        @keyframes float {
            0%, 100% { transform: translateY(100vh) rotate(0deg); opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { transform: translateY(-100px) rotate(360deg); opacity: 0; }
        }
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
            padding: 50px;
            width: 100%;
            max-width: 450px;
            position: relative;
            z-index: 10;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .login-header { text-align: center; margin-bottom: 40px; }
        .login-logo {
            background: linear-gradient(135deg, #667eea, #764ba2);
            width: 80px; height: 80px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        .login-logo i { font-size: 2.5rem; color: white; }
        .login-title { font-size: 2rem; color: #333; margin-bottom: 10px; font-weight: 700; }
        .login-subtitle { color: #666; font-size: 1rem; }
        .form-group { margin-bottom: 25px; position: relative; }
        .form-label { display: block; margin-bottom: 8px; color: #555; font-weight: 600; font-size: 0.95rem; }
        .form-input {
            width: 100%;
            padding: 15px 20px 15px 50px;
            border: 2px solid #e1e5e9;
            border-radius: 12px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }
        .form-input:focus {
            outline: none;
            border-color: #667eea;
            background: white;
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
            transform: translateY(-1px);
        }
        .form-icon {
            position: absolute;
            left: 18px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            font-size: 1.1rem;
        }
        .remember-forgot {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            font-size: 0.9rem;
        }
        .remember-me {
            display: flex;
            align-items: center;
            gap: 8px;
            color: #666;
        }
        .remember-me input[type="checkbox"] { width: 18px; height: 18px; accent-color: #667eea; }
        .forgot-password { color: #667eea; text-decoration: none; transition: color 0.3s ease; }
        .forgot-password:hover { color: #764ba2; }
        .login-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }
        .login-btn:active { transform: translateY(0); }
        .login-btn i { margin-right: 10px; }
        .alert {
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 25px;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .system-info {
            text-align: center;
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid #e1e5e9;
            color: #666;
            font-size: 0.85rem;
        }
        .system-info strong { color: #333; }
        @media (max-width: 768px) {
            .login-container { margin: 20px; padding: 40px 30px; }
            .login-title { font-size: 1.5rem; }
        }
    </style>
</head>
<body>
    <div class="particles">
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>
    </div>

    <div class="login-container">
        <div class="login-header">
            <div class="login-logo">
                <i class="fas fa-shield-alt"></i>
            </div>
            <h1 class="login-title">MikroTik Panel</h1>
            <p class="login-subtitle">MikroTik cihazınıza bağlanın</p>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {% if category == 'success' %}
                            <i class="fas fa-check-circle"></i>
                        {% elif category == 'error' %}
                            <i class="fas fa-exclamation-circle"></i>
                        {% elif category == 'warning' %}
                            <i class="fas fa-exclamation-triangle"></i>
                        {% else %}
                            <i class="fas fa-info-circle"></i>
                        {% endif %}
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form method="POST">
            <div class="form-group">
                <label for="mikrotik_host" class="form-label">
                    <i class="fas fa-server"></i> MikroTik IP Adresi
                </label>
                <div style="position: relative;">
                    <input type="text" 
                           id="mikrotik_host" 
                           name="mikrotik_host" 
                           class="form-input" 
                           placeholder="192.168.254.142"
                           value="192.168.254.142"
                           required>
                    <i class="fas fa-server form-icon"></i>
                </div>
            </div>

            <div class="form-group">
                <label for="username" class="form-label">
                    <i class="fas fa-user"></i> MikroTik Kullanıcı Adı
                </label>
                <div style="position: relative;">
                    <input type="text" 
                           id="username" 
                           name="username" 
                           class="form-input" 
                           placeholder="admin"
                           required
                           autocomplete="username">
                    <i class="fas fa-user form-icon"></i>
                </div>
            </div>

            <div class="form-group">
                <label for="password" class="form-label">
                    <i class="fas fa-lock"></i> MikroTik Şifresi
                </label>
                <div style="position: relative;">
                    <input type="password" 
                           id="password" 
                           name="password" 
                           class="form-input" 
                           placeholder="MikroTik şifrenizi girin"
                           required
                           autocomplete="current-password">
                    <i class="fas fa-lock form-icon"></i>
                </div>
            </div>

            <div class="remember-forgot">
                <label class="remember-me">
                    <input type="checkbox" name="remember_me">
                    Beni Hatırla
                </label>
                <a href="#" class="forgot-password">Şifremi Unuttum</a>
            </div>

            <button type="submit" class="login-btn">
                <i class="fas fa-sign-in-alt"></i>
                Giriş Yap
            </button>
        </form>

        <div class="system-info">
            <strong>MikroTik Panel v1.0</strong><br>
            Tasarlayan: <strong>Murat Sağ</strong> ❤️
        </div>
    </div>
</body>
</html>
EOF

    # Ana sayfa şablonu
    cat > $TEMP_DIR/templates/index.html << 'EOF'
{% extends "base.html" %}

{% block title %}NAT Kuralları - MikroTik{% endblock %}
{% block page_title %}MikroTik NAT Yönetimi{% endblock %}
{% block page_subtitle %}Port yönlendirme kurallarını kolayca yönetin{% endblock %}

{% block extra_css %}
<style>
    .form-row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
    }
    .form-group { margin-bottom: 20px; }
    label {
        display: block;
        margin-bottom: 5px;
        font-weight: 600;
        color: #555;
    }
    input[type="text"], input[type="number"] {
        width: 100%;
        padding: 12px 15px;
        border: 2px solid #e1e5e9;
        border-radius: 8px;
        font-size: 1rem;
        transition: all 0.3s ease;
        background: #f8f9fa;
    }
    input[type="text"]:focus, input[type="number"]:focus {
        outline: none;
        border-color: #667eea;
        background: white;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    .btn {
        padding: 12px 25px;
        border: none;
        border-radius: 8px;
        font-size: 1rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 8px;
    }
    .btn-primary {
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
    }
    .btn-primary:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
    }
    .btn-edit {
        background: linear-gradient(135deg, #f093fb, #f5576c);
        color: white;
        padding: 8px 15px;
        font-size: 0.9rem;
    }
    .btn-edit:hover { transform: translateY(-1px); }
    .btn-delete {
        background: linear-gradient(135deg, #ff6b6b, #ee5a52);
        color: white;
        padding: 8px 15px;
        font-size: 0.9rem;
    }
    .btn-delete:hover { transform: translateY(-1px); }
    .table-container {
        overflow-x: auto;
        border-radius: 10px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    }
    table {
        width: 100%;
        border-collapse: collapse;
        background: white;
    }
    th {
        background: linear-gradient(135deg, #667eea, #764ba2);
        color: white;
        padding: 15px;
        font-weight: 600;
        text-align: left;
        border: none;
    }
    th:first-child { border-radius: 10px 0 0 0; }
    th:last-child { border-radius: 0 10px 0 0; }
    td {
        padding: 12px 15px;
        border-bottom: 1px solid #e9ecef;
        color: #333;
    }
    tr:hover { background: #f8f9fa; }
    tr:last-child td { border-bottom: none; }
    .action-buttons {
        display: flex;
        gap: 10px;
        justify-content: center;
    }
    .badge {
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-tcp { background: #e3f2fd; color: #1976d2; }
    .badge-udp { background: #f3e5f5; color: #7b1fa2; }
    .badge-dstnat { background: #e8f5e8; color: #388e3c; }
    .card-title {
        font-size: 1.5rem;
        color: #333;
        margin-bottom: 20px;
        display: flex;
        align-items: center;
        gap: 10px;
        border-bottom: 2px solid #f0f0f0;
        padding-bottom: 15px;
    }
    .card-title i { color: #667eea; }
</style>
{% endblock %}

{% block content %}
<div class="card">
    <div class="card-title">
        <i class="fas fa-plus-circle"></i>
        Yeni Port Yönlendirme Kuralı
    </div>
    <form action="/add_rule" method="post">
        <div class="form-row">
            <div class="form-group">
                <label for="name">
                    <i class="fas fa-tag"></i> Kural Adı
                </label>
                <input type="text" id="name" name="name" required placeholder="Örn: Web Server">
            </div>
            <div class="form-group">
                <label for="external_port">
                    <i class="fas fa-door-open"></i> Dış Port
                </label>
                <input type="number" id="external_port" name="external_port" required placeholder="80">
            </div>
            <div class="form-group">
                <label for="internal_ip">
                    <i class="fas fa-server"></i> Hedef IP Adresi
                </label>
                <input type="text" id="internal_ip" name="internal_ip" required placeholder="192.168.1.100">
            </div>
            <div class="form-group">
                <label for="internal_port">
                    <i class="fas fa-door-closed"></i> Hedef Port
                </label>
                <input type="number" id="internal_port" name="internal_port" required placeholder="8080">
            </div>
        </div>
        <button type="submit" class="btn btn-primary">
            <i class="fas fa-plus"></i> Kural Ekle
        </button>
    </form>
</div>

<div class="card">
    <div class="card-title">
        <i class="fas fa-list"></i>
        Mevcut NAT Kuralları
    </div>
    
    {% if rules %}
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th><i class="fas fa-link"></i> Chain</th>
                    <th><i class="fas fa-map-marker-alt"></i> Kaynak Adres</th>
                    <th><i class="fas fa-bullseye"></i> Hedef Adres</th>
                    <th><i class="fas fa-layer-group"></i> Protokol</th>
                    <th><i class="fas fa-door-open"></i> Hedef Port</th>
                    <th><i class="fas fa-cogs"></i> Aksiyon</th>
                    <th><i class="fas fa-comment"></i> Yorum</th>
                    <th><i class="fas fa-tools"></i> İşlemler</th>
                </tr>
            </thead>
            <tbody>
                {% for rule in rules %}
                <tr>
                    <td>{{ rule.get('chain', '') }}</td>
                    <td>{{ rule.get('src-address', '-') }}</td>
                    <td>{{ rule.get('dst-address', '-') }}</td>
                    <td>
                        {% if rule.get('protocol') %}
                            <span class="badge badge-{{ rule.get('protocol', '').lower() }}">
                                {{ rule.get('protocol', '').upper() }}
                            </span>
                        {% else %}
                            -
                        {% endif %}
                    </td>
                    <td>{{ rule.get('dst-port', '-') }}</td>
                    <td>
                        {% if rule.get('action') %}
                            <span class="badge badge-{{ rule.get('action', '').lower() }}">
                                {{ rule.get('action', '') }}
                            </span>
                        {% else %}
                            -
                        {% endif %}
                    </td>
                    <td>{{ rule.get('comment', '-') }}</td>
                    <td>
                        <div class="action-buttons">
                            <form action="/delete_rule" method="post" style="display:inline;" 
                                  onsubmit="return confirm('Bu kuralı silmek istediğinizden emin misiniz?')">
                                <input type="hidden" name="rule_id" value="{{ rule['.id'] }}">
                                <button type="submit" class="btn btn-delete">
                                    <i class="fas fa-trash"></i> Sil
                                </button>
                            </form>
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% else %}
    <div style="text-align: center; padding: 40px; color: #666;">
        <i class="fas fa-inbox" style="font-size: 4rem; color: #ddd; margin-bottom: 20px; display: block;"></i>
        <h3>Henüz NAT kuralı bulunmuyor</h3>
        <p>Yukarıdaki formu kullanarak ilk kuralınızı ekleyebilirsiniz.</p>
    </div>
    {% endif %}
</div>
{% endblock %}
EOF

    # IP Monitor sayfası
    cat > $TEMP_DIR/templates/ip_monitor.html << 'EOF'
{% extends "base.html" %}

{% block title %}IP Monitör - MikroTik{% endblock %}
{% block page_title %}IP Adres Monitörü{% endblock %}
{% block page_subtitle %}Ağ üzerindeki IP adreslerini takip edin{% endblock %}

{% block content %}
<div class="card">
    <div class="card-title">
        <i class="fas fa-server"></i>
        DHCP Lease'leri
    </div>
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th><i class="fas fa-globe"></i> IP Adresi</th>
                    <th><i class="fas fa-ethernet"></i> MAC Adresi</th>
                    <th><i class="fas fa-desktop"></i> Hostname</th>
                    <th><i class="fas fa-clock"></i> Lease Süresi</th>
                    <th><i class="fas fa-info-circle"></i> Durum</th>
                </tr>
            </thead>
            <tbody>
                {% for lease in dhcp_leases %}
                <tr>
                    <td><strong>{{ lease.get('address', '-') }}</strong></td>
                    <td>{{ lease.get('mac-address', '-') }}</td>
                    <td>{{ lease.get('host-name', '-') }}</td>
                    <td>{{ lease.get('lease-time', '-') }}</td>
                    <td>
                        {% if lease.get('status') == 'bound' %}
                            <span style="background: #d4edda; color: #155724; padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">Aktif</span>
                        {% else %}
                            <span style="background: #f8d7da; color: #721c24; padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">{{ lease.get('status', 'Bilinmiyor') }}</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-title">
        <i class="fas fa-list"></i>
        ARP Tablosu
    </div>
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th><i class="fas fa-globe"></i> IP Adresi</th>
                    <th><i class="fas fa-ethernet"></i> MAC Adresi</th>
                    <th><i class="fas fa-network-wired"></i> Interface</th>
                    <th><i class="fas fa-info-circle"></i> Durum</th>
                </tr>
            </thead>
            <tbody>
                {% for arp in arp_table %}
                <tr>
                    <td><strong>{{ arp.get('address', '-') }}</strong></td>
                    <td>{{ arp.get('mac-address', '-') }}</td>
                    <td>{{ arp.get('interface', '-') }}</td>
                    <td>
                        {% if arp.get('complete') == 'true' %}
                            <span style="background: #d4edda; color: #155724; padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">Aktif</span>
                        {% else %}
                            <span style="background: #f8d7da; color: #721c24; padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">Pasif</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<div class="card">
    <div class="card-title">
        <i class="fas fa-chart-pie"></i>
        Kullanılan IP Adresleri
    </div>
    {% if used_ips %}
    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 10px; margin-top: 20px;">
        {% for ip in used_ips %}
        <div style="background: #f8f9fa; padding: 10px; border-radius: 8px; text-align: center; border-left: 4px solid #e74c3c;">
            <strong style="font-family: 'Courier New', monospace;">{{ ip }}</strong>
        </div>
        {% endfor %}
    </div>
    <div style="margin-top: 20px; text-align: center; color: #666;">
        <strong>Toplam {{ used_ips|length }} IP adresi kullanımda</strong>
    </div>
    {% else %}
    <div style="text-align: center; padding: 40px; color: #666;">
        <i class="fas fa-network-wired" style="font-size: 4rem; color: #ddd; margin-bottom: 20px; display: block;"></i>
        <h3>Kullanılan IP adresi bulunamadı</h3>
        <p>DHCP lease veya ARP kayıtları mevcut değil.</p>
    </div>
    {% endif %}
</div>
{% endblock %}
EOF

    # Profil sayfası
    cat > $TEMP_DIR/templates/profile.html << 'EOF'
{% extends "base.html" %}

{% block title %}Profil - MikroTik{% endblock %}
{% block page_title %}Kullanıcı Profili{% endblock %}
{% block page_subtitle %}MikroTik sistem bilgilerinizi görüntüleyin{% endblock %}

{% block content %}
<!-- Bağlantı Durumu -->
<div style="background: linear-gradient(135deg, #28a745, #20c997); color: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; text-align: center;">
    <div style="font-size: 1.2rem; margin-bottom: 10px;">
        <i class="fas fa-check-circle"></i> MikroTik'e Başarıyla Bağlı
    </div>
    <div style="font-size: 0.9rem; opacity: 0.9;">
        {{ session.mikrotik_host }} - {{ session.user_name }}@{{ system_info.identity or 'MikroTik' }}
    </div>
</div>

<!-- Profil Kartı -->
<div style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; border-radius: 15px; padding: 30px; margin-bottom: 30px; text-align: center;">
    <div style="width: 100px; height: 100px; background: rgba(255, 255, 255, 0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px; font-size: 3rem;">
        <i class="fas fa-user-cog"></i>
    </div>
    <div style="font-size: 1.8rem; margin-bottom: 10px;">{{ session.user_name }}</div>
    <div style="background: rgba(255, 255, 255, 0.2); padding: 5px 15px; border-radius: 20px; display: inline-block; font-size: 0.9rem;">
        <i class="fas fa-network-wired"></i> MikroTik Kullanıcısı
    </div>
</div>

<!-- Sistem Bilgileri -->
<div class="card">
    <div class="card-title">
        <i class="fas fa-server"></i>
        MikroTik Sistem Bilgileri
    </div>
    
    <div style="background: #f8f9fa; border-radius: 10px; padding: 25px; margin-bottom: 20px;">
        <div style="color: #333; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; font-size: 1.2rem;">
            <i class="fas fa-info-circle" style="color: #667eea;"></i>
            Cihaz Bilgileri
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px;">
            <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                <div style="font-weight: 600; color: #666; font-size: 0.9rem; margin-bottom: 5px;">Sistem Adı</div>
                <div style="font-size: 1.1rem; color: #333; font-family: 'Courier New', monospace;">{{ system_info.identity or 'Bilinmiyor' }}</div>
            </div>
            
            <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                <div style="font-weight: 600; color: #666; font-size: 0.9rem; margin-bottom: 5px;">Board</div>
                <div style="font-size: 1.1rem; color: #333; font-family: 'Courier New', monospace;">{{ system_info.board_name or 'Bilinmiyor' }}</div>
            </div>
            
            <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                <div style="font-weight: 600; color: #666; font-size: 0.9rem; margin-bottom: 5px;">RouterOS Sürümü</div>
                <div style="font-size: 1.1rem; color: #333; font-family: 'Courier New', monospace;">{{ system_info.version or 'Bilinmiyor' }}</div>
            </div>
            
            <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                <div style="font-weight: 600; color: #666; font-size: 0.9rem; margin-bottom: 5px;">CPU</div>
                <div style="font-size: 1.1rem; color: #333; font-family: 'Courier New', monospace;">{{ system_info.cpu or 'Bilinmiyor' }}</div>
            </div>
            
            <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                <div style="font-weight: 600; color: #666; font-size: 0.9rem; margin-bottom: 5px;">Toplam RAM</div>
                <div style="font-size: 1.1rem; color: #333; font-family: 'Courier New', monospace;">
                    {% if system_info.memory %}
                        {{ (system_info.memory|int / (1024*1024))|round|int }} MB
                    {% else %}
                        Bilinmiyor
                    {% endif %}
                </div>
            </div>
            
            <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                <div style="font-weight: 600; color: #666; font-size: 0.9rem; margin-bottom: 5px;">Uptime</div>
                <div style="font-size: 1.1rem; color: #333; font-family: 'Courier New', monospace;">{{ system_info.uptime or 'Bilinmiyor' }}</div>
            </div>
        </div>
    </div>
</div>

<!-- Bağlantı Bilgileri -->
<div class="card">
    <div class="card-title">
        <i class="fas fa-info-circle"></i>
        Bağlantı Bilgileri
    </div>
    
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
        <div style="background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
            <div style="font-size: 2rem; color: #667eea; margin-bottom: 15px;">
                <i class="fas fa-server"></i>
            </div>
            <div style="font-size: 1.5rem; font-weight: bold; color: #333; margin-bottom: 5px;">{{ session.mikrotik_host }}</div>
            <div style="color: #666; font-size: 0.9rem;">Kullanıcı Adı</div>
        </div>
        
        <div style="background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
            <div style="font-size: 2rem; color: #667eea; margin-bottom: 15px;">
                <i class="fas fa-shield-check"></i>
            </div>
            <div style="font-size: 1.5rem; font-weight: bold; color: #333; margin-bottom: 5px;">
                <span style="background: #d4edda; color: #155724; padding: 6px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">Aktif</span>
            </div>
            <div style="color: #666; font-size: 0.9rem;">Bağlantı Durumu</div>
        </div>
    </div>
</div>

<!-- Güvenlik İpuçları -->
<div class="card">
    <div class="card-title">
        <i class="fas fa-lightbulb"></i>
        MikroTik Güvenlik İpuçları
    </div>
    
    <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 20px; border-radius: 5px;">
        <h4 style="color: #1976d2; margin-bottom: 15px;">Güvenlik Önerileri</h4>
        <ul style="color: #555; margin-left: 20px; line-height: 1.6;">
            <li>Default admin kullanıcısının şifresini değiştirin</li>
            <li>Gereksiz servisleri kapatın</li>
            <li>Firewall kurallarını düzenli kontrol edin</li>
            <li>RouterOS'u güncel tutun</li>
            <li>API erişimini kısıtlayın</li>
            <li>Strong encryption kullanın</li>
        </ul>
    </div>
</div>
{% endblock %}
EOF

    echo "   ✅ Tüm template dosyalar oluşturuldu"
    
    # README.md dosyası
    cat > $TEMP_DIR/README.md << 'EOF'
# 🚀 MikroTik Panel

Modern, güvenli ve kullanıcı dostu MikroTik yönetim web arayüzü.

## ✨ Özellikler

### 🔐 **Güvenlik**
- MikroTik native authentication
- Session tabanlı kimlik doğrulama
- Direct MikroTik API bağlantısı
- Protected routes
- Güvenli çıkış sistemi

### 🌐 **NAT Yönetimi**
- Port yönlendirme kuralları ekleme/silme
- Görsel tablo arayüzü
- Gerçek zamanlı MikroTik entegrasyonu

### 📊 **IP Monitoring**
- DHCP lease takibi
- ARP tablosu görüntüleme
- IP kullanım durumu
- Canlı arama ve filtreleme

### 🎨 **Modern Arayüz**
- Responsive tasarım
- Gradient arka planlar
- Smooth animasyonlar
- Font Awesome ikonları

## 🚀 Hızlı Kurulum

```bash
# Otomatik kurulum (Önerilen)
curl -sSL https://raw.githubusercontent.com/KULLANICI/mikrotik-panel/main/install.sh | sudo bash

# Veya wget ile
wget -O - https://raw.githubusercontent.com/KULLANICI/mikrotik-panel/main/install.sh | sudo bash
```

## 📋 Manuel Kurulum

### 1. **Gereksinimleri Kurun**
```bash
# AlmaLinux/RHEL/CentOS
sudo dnf install -y python3 python3-pip python3-venv git

# Ubuntu/Debian
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git
```

### 2. **Projeyi Klonlayın**
```bash
git clone https://github.com/KULLANICI/mikrotik-panel.git
cd mikrotik-panel
```

### 3. **Virtual Environment Oluşturun**
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate     # Windows
```

### 4. **Bağımlılıkları Kurun**
```bash
pip install -r requirements.txt
```

### 5. **MikroTik API'yi Etkinleştirin**
MikroTik cihazınızda:
```bash
/ip service enable api
/ip service set api port=8728
```

### 6. **Uygulamayı Çalıştırın**
```bash
python app.py
```

### 7. **Tarayıcıda Açın**
```
http://localhost:5050
```

## 🔧 Yapılandırma

### MikroTik Bağlantı Ayarları
`app.py` dosyasındaki bağlantı bilgilerini düzenleyin:
```python
MIKROTIK_HOST = '192.168.1.1'  # MikroTik IP adresi
MIKROTIK_PORT = 8728           # API portu
```

### Güvenlik Ayarları
Production ortamında:
```python
app.secret_key = 'super-gizli-production-key'
```

## 🐛 Sorun Giderme

### MikroTik'e Bağlanamıyorum
- IP adresi doğru mu?
- API portu açık mı? (8728)
- Kullanıcı adı/şifre doğru mu?
- Firewall API'yi engelliyor mu?

### Uygulama Başlamıyor
- Python 3.7+ kurulu mu?
- Virtual environment aktif mi?
- Bağımlılıklar yüklü mü?
- Port 5050 kullanımda mı?

## 📊 Özellikler

- ✅ Responsive design (mobil uyumlu)
- ✅ Modern UI/UX
- ✅ Real-time data
- ✅ Error handling
- ✅ Flash messages
- ✅ Session management
- ✅ MikroTik native authentication

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

Sorunlar için GitHub Issues kullanın.

---

**🎉 MikroTik Panel v1.0 - Professional Network Management** 🎉
EOF

    # .gitignore dosyası
    cat > $TEMP_DIR/.gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs
*.log
logs/

# OS
.DS_Store
Thumbs.db

# Configuration
.env
config.py
instance/

# Database
*.db
*.sqlite

# Temporary files
*.tmp
*.bak
EOF

    echo "   ✅ Kaynak dosyalar başarıyla oluşturuldu"
    log_message "Tüm kaynak dosyalar oluşturuldu"
}; font-size: 0.9rem;">MikroTik IP</div>
        </div>
        
        <div style="background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
            <div style="font-size: 2rem; color: #667eea; margin-bottom: 15px;">
                <i class="fas fa-user"></i>
            </div>
            <div style="font-size: 1.5rem; font-weight: bold; color: #333; margin-bottom: 5px;">{{ session.user_name }}</div>
            <div style="color: #666