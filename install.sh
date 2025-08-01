#!/bin/bash

# MikroTik Panel Otomatik Kurulum Script'i - İyileştirilmiş Versiyon
# AlmaLinux 9.4 için hazırlanmıştır
# Kullanım: curl -sSL https://raw.githubusercontent.com/KULLANICI/mikrotik-panel/main/install.sh | bash

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

# MikroTik ayarları (kullanıcıdan alınacak)
MIKROTIK_IP=""
MIKROTIK_PORT="8728"

# Logo ve başlık
print_logo() {
    clear
    echo -e "${BLUE}"
    echo "
███╗   ███╗██╗██╗  ██╗██████╗  ██████╗ ████████╗██╗██╗  ██╗
████╗ ████║██║██║ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝██║██║ ██╔╝
██╔████╔██║██║█████╔╝ ██████╔╝██║   ██║   ██║   ██║█████╔╝ 
██║╚██╔╝██║██║██╔═██╗ ██╔══██╗██║   ██║   ██║   ██║██╔═██╗ 
██║ ╚═╝ ██║██║██║  ██╗██║  ██║╚██████╔╝   ██║   ██║██║  ██╗
╚═╝     ╚═╝╚═╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚═╝  ╚═╝
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

# MikroTik bağlantı bilgilerini kullanıcıdan al
get_mikrotik_config() {
    echo -e "${BLUE}🔧 MikroTik Bağlantı Ayarları${NC}"
    echo "=" * 60
    echo ""
    
    # IP adresi sor
    while true; do
        echo -e "${YELLOW}📡 MikroTik Router IP Adresi:${NC}"
        echo "   Örnekler: 192.168.1.1, 10.0.0.1, 172.16.0.1, 192.168.254.142"
        echo -e "${CYAN}   Not: MikroTik cihazınızın IP adresini girin${NC}"
        echo ""
        read -p "   MikroTik IP: " MIKROTIK_IP
        
        if [[ -z "$MIKROTIK_IP" ]]; then
            echo -e "${RED}   ❌ IP adresi boş olamaz!${NC}"
            continue
        fi
        
        # IP formatını kontrol et
        if [[ $MIKROTIK_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            # IP aralığı kontrolü
            IFS='.' read -r -a ip_parts <<< "$MIKROTIK_IP"
            valid_ip=true
            for part in "${ip_parts[@]}"; do
                if (( part > 255 )); then
                    valid_ip=false
                    break
                fi
            done
            
            if [[ $valid_ip == true ]]; then
                # Ping testi yap
                echo -e "${BLUE}   🔍 MikroTik bağlantısı test ediliyor...${NC}"
                if timeout 5 ping -c 1 $MIKROTIK_IP &> /dev/null; then
                    echo -e "${GREEN}   ✅ MikroTik $MIKROTIK_IP adresine erişilebilir${NC}"
                    break
                else
                    echo -e "${YELLOW}   ⚠️  $MIKROTIK_IP adresine ping atılamıyor${NC}"
                    echo -e "${CYAN}   💡 MikroTik kapalı olabilir veya ping'e cevap vermiyor olabilir${NC}"
                    echo ""
                    read -p "   Yine de bu IP ile devam etmek istiyor musunuz? [y/N]: " -n 1 -r
                    echo
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        echo -e "${YELLOW}   ⚠️  Ping başarısız olsa da devam ediliyor...${NC}"
                        break
                    fi
                fi
            else
                echo -e "${RED}   ❌ IP adresi aralığı geçersiz (0-255)!${NC}"
            fi
        else
            echo -e "${RED}   ❌ Geçersiz IP adresi formatı! (örn: 192.168.1.1)${NC}"
        fi
        echo ""
    done
    
    echo ""
    
    # API Port sor
    echo -e "${YELLOW}🚪 MikroTik API Portu:${NC}"
    echo "   Varsayılan MikroTik API portu 8728'dir"
    echo "   Değiştirmediyseniz Enter'a basın"
    echo ""
    read -p "   API Port (varsayılan 8728): " MIKROTIK_PORT_INPUT
    MIKROTIK_PORT=${MIKROTIK_PORT_INPUT:-8728}
    
    # Port kontrolü
    if ! [[ "$MIKROTIK_PORT" =~ ^[0-9]+$ ]] || [ "$MIKROTIK_PORT" -lt 1 ] || [ "$MIKROTIK_PORT" -gt 65535 ]; then
        echo -e "${YELLOW}   ⚠️  Geçersiz port numarası! Varsayılan 8728 kullanılacak${NC}"
        MIKROTIK_PORT=8728
    fi
    
    echo ""
    
    # Web port sor
    echo -e "${YELLOW}🌐 Web Panel Portu:${NC}"
    echo "   Web paneline erişim portu (önerilen: 5050)"
    echo "   Panel bu portta çalışacak"
    echo ""
    read -p "   Web Port (varsayılan 5050): " WEB_PORT_INPUT
    WEB_PORT_INPUT=${WEB_PORT_INPUT:-5050}
    
    # Port kontrolü ve çakışma kontrolü
    if [[ "$WEB_PORT_INPUT" =~ ^[0-9]+$ ]] && [ "$WEB_PORT_INPUT" -ge 1024 ] && [ "$WEB_PORT_INPUT" -le 65535 ]; then
        if ! ss -tlnp 2>/dev/null | grep -q ":$WEB_PORT_INPUT "; then
            WEB_PORT=$WEB_PORT_INPUT
            echo -e "${GREEN}   ✅ Port $WEB_PORT kullanılabilir${NC}"
        else
            echo -e "${YELLOW}   ⚠️  Port $WEB_PORT_INPUT kullanımda! Varsayılan 5050 kullanılacak${NC}"
            WEB_PORT=5050
        fi
    else
        echo -e "${YELLOW}   ⚠️  Geçersiz port! Port 1024-65535 arasında olmalı. Varsayılan 5050 kullanılacak${NC}"
        WEB_PORT=5050
    fi
    
    # API Bağlantı testi sor
    echo ""
    echo -e "${YELLOW}🔐 MikroTik API Bağlantı Testi (Opsiyonel):${NC}"
    echo "   MikroTik API bağlantısını şimdi test edebiliriz"
    echo "   Bu test sadece doğrulama amaçlıdır, zorunlu değildir"
    echo ""
    read -p "   API bağlantısını test etmek istiyor musunuz? [y/N]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${CYAN}🔧 MikroTik Kimlik Bilgileri:${NC}"
        read -p "   Kullanıcı Adı: " TEST_USER
        read -s -p "   Şifre: " TEST_PASS
        echo
        echo ""
        
        if [[ -n "$TEST_USER" && -n "$TEST_PASS" ]]; then
            echo -e "${BLUE}   🔍 MikroTik API bağlantısı test ediliyor...${NC}"
            
            # Basit socket testi
            if timeout 5 bash -c "</dev/tcp/$MIKROTIK_IP/$MIKROTIK_PORT" 2>/dev/null; then
                echo -e "${GREEN}   ✅ MikroTik API portu ($MIKROTIK_PORT) erişilebilir${NC}"
                echo -e "${CYAN}   💡 Gerçek kimlik doğrulama kurulum sonrası web panelinde yapılacak${NC}"
            else
                echo -e "${RED}   ❌ MikroTik API portu ($MIKROTIK_PORT) erişilemiyor!${NC}"
                echo ""
                echo -e "${YELLOW}   🔧 Olası çözümler:${NC}"
                echo "      • MikroTik'te API servisi etkin mi? -> /ip service enable api"
                echo "      • Firewall API portunu engelliyor mu?"
                echo "      • IP adresi doğru mu?"
                echo ""
                read -p "   Yine de kuruluma devam etmek istiyor musunuz? [y/N]: " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    echo -e "${RED}❌ Kurulum iptal edildi.${NC}"
                    exit 1
                fi
            fi
        fi
    fi
    
    # Ayarları özetle
    echo ""
    echo -e "${BLUE}📋 MikroTik Yapılandırma Özeti:${NC}"
    echo "=" * 50
    echo -e "   🏠 MikroTik IP Adresi : ${GREEN}$MIKROTIK_IP${NC}"
    echo -e "   🚪 MikroTik API Port  : ${GREEN}$MIKROTIK_PORT${NC}"
    echo -e "   🌐 Web Panel Portu    : ${GREEN}$WEB_PORT${NC}"
    echo -e "   🔗 Panel Erişim URL   : ${GREEN}http://$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1{print $7}' || echo 'SERVER_IP'):$WEB_PORT${NC}"
    echo "=" * 50
    echo ""
    
    read -p "$(echo -e "${GREEN}Bu ayarlarla kuruluma devam etmek istiyor musunuz? [Y/n]: ${NC}")" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}🔄 MikroTik ayarlarını yeniden yapılandırıyorum...${NC}"
        echo ""
        get_mikrotik_config
    fi
    
    log_message "MikroTik ayarları: IP=$MIKROTIK_IP, API_PORT=$MIKROTIK_PORT, WEB_PORT=$WEB_PORT"
}

# Sistem uyumluluğu kontrolü
check_system_compatibility() {
    echo -e "${BLUE}🔍 Sistem uyumluluğu kontrol ediliyor...${NC}"
    
    # OS kontrolü
    if [[ -f /etc/redhat-release ]]; then
        OS_VERSION=$(cat /etc/redhat-release)
        echo "   ✅ Desteklenen OS: $OS_VERSION"
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
    
    if ss -tlnp 2>/dev/null | grep -q ":$WEB_PORT "; then
        echo -e "${YELLOW}⚠️  Port $WEB_PORT kullanımda. Çakışan servis durduruluyor...${NC}"
        # Port kullanan servisi bul ve durdur
        PID=$(ss -tlnp 2>/dev/null | grep ":$WEB_PORT " | awk '{print $6}' | cut -d',' -f2 | cut -d'=' -f2 | head -1)
        if [[ -n $PID ]]; then
            kill -9 $PID 2>/dev/null || true
            sleep 2
        fi
    fi
    
    if ! ss -tlnp 2>/dev/null | grep -q ":$WEB_PORT "; then
        echo "   ✅ Port $WEB_PORT kullanılabilir"
    else
        error_exit "Port $WEB_PORT hala kullanımda. Manuel müdahale gerekli."
    fi
}

# Kaynak dosyaları oluştur fonksiyonu
create_source_files() {
    echo -e "${BLUE}📝 Kaynak dosyalar oluşturuluyor...${NC}"
    
    # GitHub'dan indirmeyi dene
    if command -v git &> /dev/null; then
        echo "   🔄 GitHub'dan kaynak kodları indiriliyor..."
        if git clone https://github.com/KULLANICI/mikrotik-panel.git $TEMP_DIR &>> $LOG_FILE; then
            echo "   ✅ GitHub'dan başarıyla indirildi"
            
            # MikroTik ayarlarını app.py'ye uygula
            sed -i "s/MIKROTIK_HOST = '.*'/MIKROTIK_HOST = '$MIKROTIK_IP'/" $TEMP_DIR/app.py
            sed -i "s/MIKROTIK_PORT = .*/MIKROTIK_PORT = $MIKROTIK_PORT/" $TEMP_DIR/app.py
            
            return 0
        else
            echo "   ⚠️  GitHub indirme başarısız, yerel dosyalar oluşturuluyor..."
        fi
    fi
    
    # Yerel dosyalar oluştur
    create_local_files
}

create_local_files() {
    # Dizin yapısını oluştur
    mkdir -p $TEMP_DIR/{templates,static/{css,js}}
    
    # requirements.txt
    cat > $TEMP_DIR/requirements.txt << 'EOF'
Flask==3.0.0
librouteros==3.2.1
gunicorn==21.2.0
Werkzeug==3.0.0
EOF

    # Ana Flask uygulaması - Dinamik ayarlarla
    cat > $TEMP_DIR/app.py << EOF
from flask import Flask, render_template, request, redirect, url_for, session, flash
from librouteros import connect
from functools import wraps
import secrets
import os

app = Flask(__name__)

# Güvenlik yapılandırması
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 saat

# MikroTik bağlantı bilgileri - Kurulum sırasında ayarlandı
MIKROTIK_HOST = '$MIKROTIK_IP'
MIKROTIK_PORT = $MIKROTIK_PORT

def mikrotik_login(username=None, password=None, host=None):
    """MikroTik'e bağlanır. Eğer kullanıcı bilgileri verilmezse session'dan alır."""
    try:
        if username and password:
            return connect(
                host=host or MIKROTIK_HOST,
                username=username,
                password=password,
                port=MIKROTIK_PORT,
                encoding='utf-8'
            )
        else:
            return connect(
                host=session.get('mikrotik_host', MIKROTIK_HOST),
                username=session['mikrotik_user'],
                password=session['mikrotik_pass'],
                port=MIKROTIK_PORT,
                encoding='utf-8'
            )
    except Exception as e:
        raise Exception(f"MikroTik bağlantı hatası: {str(e)}")

@app.context_processor
def inject_request():
    return dict(request=request)

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
            return render_template('login.html', default_host=MIKROTIK_HOST)
        
        try:
            api = mikrotik_login(username, password, mikrotik_host)
            system_resource = list(api.path('system', 'resource'))[0]
            system_identity = list(api.path('system', 'identity'))[0]
            
            session['mikrotik_user'] = username
            session['mikrotik_pass'] = password
            session['mikrotik_host'] = mikrotik_host
            session['user_name'] = username
            session['system_name'] = system_identity.get('name', 'MikroTik')
            session['board_name'] = system_resource.get('board-name', 'Unknown')
            
            if remember_me:
                session.permanent = True
            
            flash(f'Hoş geldiniz, {username}! {system_identity.get("name", "MikroTik")} sistemine bağlandınız.', 'success')
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f'MikroTik bağlantı hatası: {str(e)}', 'error')
    
    return render_template('login.html', default_host=MIKROTIK_HOST)

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

@app.route('/health')
def health():
    return {
        'status': 'healthy',
        'version': '1.0.0',
        'mikrotik_host': MIKROTIK_HOST,
        'mikrotik_port': MIKROTIK_PORT,
        'web_port': $WEB_PORT
    }, 200

if __name__ == '__main__':
    print("🚀 MikroTik Panel başlatılıyor...")
    print(f"📡 MikroTik Host: {MIKROTIK_HOST}:{MIKROTIK_PORT}")
    print(f"🌐 Web Server: http://0.0.0.0:$WEB_PORT")
    print("🔧 Production Mode: Aktif")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=$WEB_PORT, debug=False)
EOF

    # Login template - İyileştirilmiş
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
            padding: 20px;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
            padding: 50px;
            width: 100%;
            max-width: 450px;
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
        }
        .login-logo i { font-size: 2.5rem; color: white; }
        .login-title { font-size: 2rem; color: #333; margin-bottom: 10px; }
        .form-group { margin-bottom: 25px; position: relative; }
        .form-label { display: block; margin-bottom: 8px; color: #555; font-weight: 600; }
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
        }
        .form-icon {
            position: absolute;
            left: 18px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            font-size: 1.1rem;
        }
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
        }
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }
        .alert {
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        .alert-info { background: #d1ecf1; color: #0c5460; }
        .connection-info {
            background: linear-gradient(135deg, #e3f2fd, #bbdefb);
            border: 1px solid #2196f3;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: center;
            color: #1976d2;
        }
        .connection-info i { font-size: 1.5rem; margin-bottom: 10px; display: block; }
        .connection-info strong { font-size: 1.1rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="login-logo">
                <i class="fas fa-shield-alt"></i>
            </div>
            <h1 class="login-title">MikroTik Panel</h1>
            <p>Ağınızı kolayca yönetin</p>
        </div>

        <div class="connection-info">
            <i class="fas fa-server"></i>
            <div><strong>Hedef MikroTik:</strong></div>
            <div style="font-family: 'Courier New', monospace; font-size: 1.2rem; margin-top: 5px;">{{ default_host }}</div>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        {% if category == 'success' %}
                            <i class="fas fa-check-circle"></i>
                        {% elif category == 'error' %}
                            <i class="fas fa-exclamation-circle"></i>
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
                           value="{{ default_host }}"
                           placeholder="192.168.1.1"
                           required>
                    <i class="fas fa-user form-icon"></i>
                </div>
            </div>

            <div class="form-group">
                <label for="password" class="form-label">
                    <i class="fas fa-lock"></i> Şifre
                </label>
                <div style="position: relative;">
                    <input type="password" 
                           id="password" 
                           name="password" 
                           class="form-input" 
                           placeholder="MikroTik şifrenizi girin"
                           required>
                    <i class="fas fa-lock form-icon"></i>
                </div>
            </div>

            <div style="margin-bottom: 25px;">
                <label style="display: flex; align-items: center; gap: 8px; color: #666;">
                    <input type="checkbox" name="remember_me">
                    Beni Hatırla
                </label>
            </div>

            <button type="submit" class="login-btn">
                <i class="fas fa-sign-in-alt"></i>
                Giriş Yap
            </button>
        </form>

        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e1e5e9; color: #666; font-size: 0.9rem;">
            <strong>MikroTik Panel v1.0</strong><br>
            <i class="fas fa-heart" style="color: #e74c3c;"></i> Murat Sağ
        </div>
    </div>
</body>
</html>
EOF

    # Basit index template
    cat > $TEMP_DIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MikroTik Panel</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; color: white; margin-bottom: 40px; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .card { background: white; border-radius: 15px; padding: 30px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .alert { padding: 15px; border-radius: 10px; margin-bottom: 20px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        .user-info { background: rgba(255,255,255,0.2); color: white; padding: 15px; border-radius: 10px; margin-bottom: 30px; text-align: center; }
        .btn { padding: 12px 25px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 8px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { transform: translateY(-2px); }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 15px; }
        td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        input[type="text"], input[type="number"] { width: 100%; padding: 10px; border: 2px solid #ddd; border-radius: 5px; margin-bottom: 10px; }
        .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> MikroTik Panel</h1>
            <p>NAT Kuralları Yönetimi</p>
        </div>

        {% if session.mikrotik_user %}
        <div class="user-info">
            <i class="fas fa-user-cog"></i> {{ session.user_name }}@{{ session.system_name }}
            <span style="margin-left: 20px;">({{ session.mikrotik_host }})</span>
            <a href="/logout" style="color: white; margin-left: 20px;"><i class="fas fa-sign-out-alt"></i> Çıkış</a>
        </div>
        {% endif %}

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">
                        <i class="fas fa-info-circle"></i> {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="card">
            <h2><i class="fas fa-plus"></i> Yeni NAT Kuralı Ekle</h2>
            <form action="/add_rule" method="post">
                <div class="form-row">
                    <div>
                        <label>Kural Adı:</label>
                        <input type="text" name="name" required placeholder="Web Server">
                    </div>
                    <div>
                        <label>Dış Port:</label>
                        <input type="number" name="external_port" required placeholder="80">
                    </div>
                    <div>
                        <label>Hedef IP:</label>
                        <input type="text" name="internal_ip" required placeholder="192.168.1.10">
                    </div>
                    <div>
                        <label>Hedef Port:</label>
                        <input type="number" name="internal_port" required placeholder="8080">
                    </div>
                </div>
                <button type="submit" class="btn"><i class="fas fa-plus"></i> Kural Ekle</button>
            </form>
        </div>

        <div class="card">
            <h2><i class="fas fa-list"></i> Mevcut NAT Kuralları</h2>
            {% if rules %}
            <table>
                <thead>
                    <tr>
                        <th>Chain</th>
                        <th>Protokol</th>
                        <th>Hedef Port</th>
                        <th>Aksiyon</th>
                        <th>Yorum</th>
                        <th>İşlemler</th>
                    </tr>
                </thead>
                <tbody>
                    {% for rule in rules %}
                    <tr>
                        <td>{{ rule.get('chain', '-') }}</td>
                        <td>{{ rule.get('protocol', '-') }}</td>
                        <td>{{ rule.get('dst-port', '-') }}</td>
                        <td>{{ rule.get('action', '-') }}</td>
                        <td>{{ rule.get('comment', '-') }}</td>
                        <td>
                            <form action="/delete_rule" method="post" style="display:inline;" 
                                  onsubmit="return confirm('Silmek istediğinizden emin misiniz?')">
                                <input type="hidden" name="rule_id" value="{{ rule['.id'] }}">
                                <button type="submit" style="background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer;">
                                    <i class="fas fa-trash"></i> Sil
                                </button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div style="text-align: center; padding: 40px; color: #666;">
                <i class="fas fa-inbox" style="font-size: 3rem; margin-bottom: 20px; display: block;"></i>
                <h3>Henüz NAT kuralı yok</h3>
                <p>Yukarıdaki formu kullanarak yeni kural ekleyebilirsiniz.</p>
            </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
EOF

    echo "   ✅ Yerel kaynak dosyalar oluşturuldu"
    log_message "Kaynak dosylar oluşturuldu - MikroTik IP: $MIKROTIK_IP"
}

# Sistem paketlerini kur
install_system_packages() {
    echo -e "${BLUE}📦 Sistem paketleri kuruluyor...${NC}"
    
    if command -v dnf &> /dev/null; then
        dnf update -y &>> $LOG_FILE
        dnf install -y epel-release &>> $LOG_FILE
        dnf install -y python3 python3-pip python3-venv git curl wget \
                       firewalld systemd nginx &>> $LOG_FILE
    elif command -v yum &> /dev/null; then
        yum update -y &>> $LOG_FILE
        yum install -y epel-release &>> $LOG_FILE
        yum install -y python3 python3-pip python3-venv git curl wget \
                       firewalld systemd nginx &>> $LOG_FILE
    else
        error_exit "Desteklenen paket yöneticisi bulunamadı (dnf/yum)"
    fi
    
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
    
    usermod -a -G systemd-journal $SERVICE_USER
    log_message "Servis kullanıcısı hazırlandı: $SERVICE_USER"
}

# Uygulama dosyalarını kur
install_application_files() {
    echo -e "${BLUE}📁 Uygulama dosyları kuruluyor...${NC}"
    
    if [[ -d $INSTALL_DIR ]]; then
        echo "   🧹 Eski kurulum temizleniyor..."
        systemctl stop $SERVICE_NAME 2>/dev/null || true
        rm -rf $INSTALL_DIR
    fi
    
    mkdir -p $INSTALL_DIR
    cp -r $TEMP_DIR/* $INSTALL_DIR/
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    chmod -R 755 $INSTALL_DIR
    chmod 644 $INSTALL_DIR/app.py
    
    echo "   ✅ Uygulama dosyları kuruldu: $INSTALL_DIR"
    log_message "Uygulama dosyları kuruldu: $INSTALL_DIR"
}

# Python Virtual Environment kur
setup_python_environment() {
    echo -e "${BLUE}🐍 Python Virtual Environment kuruluyor...${NC}"
    
    sudo -u $SERVICE_USER python3 -m venv $INSTALL_DIR/venv
    sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install --upgrade pip &>> $LOG_FILE
    
    if [[ -f $INSTALL_DIR/requirements.txt ]]; then
        sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install -r $INSTALL_DIR/requirements.txt &>> $LOG_FILE
        echo "   ✅ Python paketleri kuruldu"
    else
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
Description=MikroTik Panel Web Application (MikroTik: $MIKROTIK_IP)
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
    
    systemctl enable firewalld &>> $LOG_FILE
    systemctl start firewalld &>> $LOG_FILE
    
    firewall-cmd --permanent --add-port=$WEB_PORT/tcp &>> $LOG_FILE
    firewall-cmd --permanent --add-service=http &>> $LOG_FILE
    firewall-cmd --reload &>> $LOG_FILE
    
    if firewall-cmd --list-ports | grep -q "$WEB_PORT/tcp"; then
        echo "   ✅ Firewall port $WEB_PORT açıldı"
    else
        echo "   ⚠️  Firewall port açılımı doğrulanamadı"
    fi
    
    log_message "Firewall yapılandırıldı - Port: $WEB_PORT"
}

# Service'i başlat
start_services() {
    echo -e "${BLUE}🚀 Servisler başlatılıyor...${NC}"
    
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME &>> $LOG_FILE
    systemctl start $SERVICE_NAME
    
    echo "   ⏳ Servis başlatılması bekleniyor..."
    sleep 10
    
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
    echo -e "   📅 Kurulum Zamanı    : ${YELLOW}$install_time${NC}"
    echo -e "   🖥️  Sunucu IP         : ${YELLOW}$server_ip${NC}"
    echo -e "   🏠 MikroTik IP       : ${YELLOW}$MIKROTIK_IP${NC}"
    echo -e "   🚪 MikroTik API Port : ${YELLOW}$MIKROTIK_PORT${NC}"
    echo -e "   🌐 Web Panel URL     : ${YELLOW}http://$server_ip:$WEB_PORT${NC}"
    echo -e "   ⚙️  Service Durumu    : $SERVICE_STATUS"
    echo -e "   🔌 Port Durumu       : $PORT_STATUS"
    echo -e "   🌍 Web Erişimi       : $WEB_STATUS"
    echo -e "   📁 Kurulum Yeri      : ${YELLOW}$INSTALL_DIR${NC}"
    echo -e "   👤 Service User      : ${YELLOW}$SERVICE_USER${NC}"
    echo -e "   🔄 Otomatik Başlatma : ${GREEN}✅ Aktif${NC}"
    echo "=" * 70
    
    echo -e "${GREEN}🚀 MikroTik Panel başarılı şekilde kuruldu ve çalışıyor!${NC}"
    echo ""
    
    echo -e "${BLUE}📱 ERİŞİM BİLGİLERİ:${NC}"
    echo -e "   • Ana Panel URL     : ${YELLOW}http://$server_ip:$WEB_PORT${NC}"
    echo -e "   • Yerel erişim      : ${YELLOW}http://localhost:$WEB_PORT${NC}"
    echo -e "   • Hedef MikroTik    : ${YELLOW}$MIKROTIK_IP:$MIKROTIK_PORT${NC}"
    echo ""
    
    echo -e "${PURPLE}🔧 YÖNETİM KOMUTLARI:${NC}"
    echo -e "   • Durumu kontrol et : ${YELLOW}systemctl status $SERVICE_NAME${NC}"
    echo -e "   • Logları görüntüle : ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
    echo -e "   • Yeniden başlat    : ${YELLOW}systemctl restart $SERVICE_NAME${NC}"
    echo -e "   • Durdur           : ${YELLOW}systemctl stop $SERVICE_NAME${NC}"
    echo ""
    
    echo -e "${YELLOW}🔒 ÖNEMLİ GÜVENLİK HATIRLATMALARI:${NC}"
    echo -e "   • MikroTik'te güçlü şifre kullanın"
    echo -e "   • API erişimini kısıtlayın: /ip service set api address=192.168.1.0/24"
    echo -e "   • Firewall kurallarını kontrol edin"
    echo -e "   • RouterOS'u güncel tutun"
    echo -e "   • Web paneline sadece güvenilir IP'lerden erişim sağlayın"
    echo ""
    
    echo -e "${CYAN}📞 DESTEK:${NC}"
    echo -e "   • GitHub: https://github.com/KULLANICI/mikrotik-panel"
    echo -e "   • Log Dosyası: $LOG_FILE"
    echo ""
    
    # Kurulum raporunu dosyaya kaydet
    cat > $INSTALL_DIR/installation-report.txt << EOF
========================================
MikroTik Panel Kurulum Raporu
========================================
Kurulum Zamanı: $install_time
Sunucu IP: $server_ip
MikroTik IP: $MIKROTIK_IP
MikroTik API Port: $MIKROTIK_PORT
Web Panel URL: http://$server_ip:$WEB_PORT
Kurulum Dizini: $INSTALL_DIR
Service: $SERVICE_NAME

Erişim Bilgileri:
- Ana Panel: http://$server_ip:$WEB_PORT
- Hedef MikroTik: $MIKROTIK_IP:$MIKROTIK_PORT

Yönetim Komutları:
- systemctl status $SERVICE_NAME
- systemctl restart $SERVICE_NAME
- journalctl -u $SERVICE_NAME -f

Bu rapor otomatik olarak oluşturulmuştur.
EOF
    
    chown $SERVICE_USER:$SERVICE_USER $INSTALL_DIR/installation-report.txt
    
    log_message "=== KURULUM BAŞARIYLA TAMAMLANDI ==="
    log_message "MikroTik IP: $MIKROTIK_IP:$MIKROTIK_PORT"
    log_message "Web Panel: http://$server_ip:$WEB_PORT"
}

# Ana kurulum fonksiyonu
main() {
    print_logo
    
    echo -e "${GREEN}🚀 MikroTik Panel İnteraktif Kurulum Script'i${NC}"
    echo -e "${CYAN}📅 Versiyon: 2.0 - $(date +'%Y-%m-%d')${NC}"
    echo -e "${YELLOW}🔧 AlmaLinux 9.4 için optimize edilmiştir${NC}"
    echo "=" * 75
    
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
    echo ""
    
    # MikroTik yapılandırmasını al
    get_mikrotik_config
    
    # Kurulum onayı
    echo -e "${YELLOW}⚠️  Kurulum işlemleri:${NC}"
    echo "   • Sistem paketlerini güncelleyecek ve kuracak"
    echo "   • Python3 Virtual Environment oluşturacak"
    echo "   • MikroTik Panel uygulamasını kuracak"
    echo "   • Systemd servisini yapılandıracak"
    echo "   • Firewall ayarlarını yapacak (port $WEB_PORT)"
    echo "   • Otomatik başlatmayı etkinleştirecek"
    echo ""
    
    read -p "$(echo -e "${GREEN}Kuruluma başlamak için Enter'a basın, iptal için Ctrl+C: ${NC}")"
    
    # Kurulum başlangıcı
    echo ""
    echo -e "${GREEN}🎯 MikroTik Panel kurulumu başlatılıyor...${NC}"
    echo "📋 Detaylı loglar: $LOG_FILE"
    sleep 2
    
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
    
    echo -e "\n${CYAN}========== ADIM 7: SERVİS BAŞLATMA =========${NC}"
    start_services
    
    echo -e "\n${CYAN}========== ADIM 8: DOĞRULAMA ===============${NC}"
    if verify_installation; then
        echo -e "\n${CYAN}========== ADIM 9: RAPOR ==================${NC}"
        generate_installation_report
        
        echo -e "${GREEN}✅ MikroTik Panel başarıyla kuruldu ve çalışıyor!${NC}"
        echo -e "${GREEN}🎯 Tarayıcınızda http://$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1{print $7}' || echo '127.0.0.1'):$WEB_PORT adresini ziyaret edin.${NC}"
        exit 0
    else
        echo -e "${RED}❌ Kurulum tamamlandı ancak doğrulama başarısız!${NC}"
        echo -e "${YELLOW}🔧 Lütfen logları kontrol edin:${NC}"
        echo -e "   • systemctl status $SERVICE_NAME"
        echo -e "   • journalctl -u $SERVICE_NAME"
        echo -e "   • cat $LOG_FILE"
        exit 1
    fi
}

# Script'i çalıştır
main "$@"
                    <i class="fas fa-server form-icon"></i>
                </div>
            </div>

            <div class="form-group">
                <label for="username" class="form-label">
                    <i class="fas fa-user"></i> Kullanıcı Adı
                </label>
                <div style="position: relative;">
                    <input type="text" 
                           id="username" 
                           name="username" 
                           class="form-input" 
                           placeholder="admin"#!/bin/bash

# MikroTik Panel Otomatik Kurulum Script'i - İyileştirilmiş Versiyon
# AlmaLinux 9.4 için hazırlanmıştır
# Kullanım: curl -sSL https://raw.githubusercontent.com/KULLANICI/mikrotik-panel/main/install.sh | bash

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

# MikroTik ayarları (kullanıcıdan alınacak)
MIKROTIK_IP=""
MIKROTIK_PORT="8728"

# Logo ve başlık
print_logo() {
    clear
    echo -e "${BLUE}"
    echo "
███╗   ███╗██╗██╗  ██╗██████╗  ██████╗ ████████╗██╗██╗  ██╗
████╗ ████║██║██║ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝██║██║ ██╔╝
██╔████╔██║██║█████╔╝ ██████╔╝██║   ██║   ██║   ██║█████╔╝ 
██║╚██╔╝██║██║██╔═██╗ ██╔══██╗██║   ██║   ██║   ██║██╔═██╗ 
██║ ╚═╝ ██║██║██║  ██╗██║  ██║╚██████╔╝   ██║   ██║██║  ██╗
╚═╝     ╚═╝