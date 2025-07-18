from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from librouteros import connect
from functools import wraps
import secrets
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import time

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

# IP ping kontrolü için yardımcı fonksiyon
def ping_ip(ip, timeout=1):
    """IP adresinin erişilebilir olup olmadığını kontrol eder"""
    try:
        # İlk olarak yaygın portları dene
        common_ports = [80, 443, 22, 23, 21, 53, 8080, 8443]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return True
        
        return False
    except Exception:
        return False

def get_network_scan(network_prefix, max_workers=50):
    """Ağdaki tüm IP'leri paralel olarak tarar"""
    active_ips = []
    
    def check_ip(i):
        ip = f"{network_prefix}{i}"
        if ping_ip(ip, 0.8):  # 800ms timeout
            return ip
        return None
    
    print(f"Ağ taraması başlatılıyor: {network_prefix}1-254")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 1-254 aralığını paralel tara
        futures = [executor.submit(check_ip, i) for i in range(1, 255)]
        
        for i, future in enumerate(futures):
            try:
                result = future.result(timeout=2)  # 2 saniye timeout
                if result:
                    active_ips.append(result)
                    print(f"Aktif IP bulundu: {result}")
            except Exception as e:
                # Timeout veya diğer hatalar için sessizce geç
                pass
        
        # Sonuçları sırala
        active_ips.sort(key=lambda x: int(x.split('.')[-1]))
    
    print(f"Tarama tamamlandı. {len(active_ips)} aktif IP bulundu.")
    return active_ips

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

@app.route('/edit_rule', methods=['GET'])
@login_required
def edit_rule():
    rule_id = request.args.get('rule_id')
    if not rule_id:
        flash('Kural ID eksik!', 'error')
        return redirect(url_for('index'))

    try:
        api = mikrotik_login()
        rules = list(api.path('ip', 'firewall', 'nat').select('.id', 'chain', 'src-address', 'dst-address', 'protocol', 'dst-port', 'action', 'comment').where('.id', rule_id))
        rule = rules[0] if rules else None

        if not rule:
            flash('Kural bulunamadı!', 'error')
            return redirect(url_for('index'))

        return render_template('edit_rule.html', rule=rule)
    except Exception as e:
        flash(f'Kural yüklenirken hata oluştu: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/edit_rule', methods=['POST'])
@login_required
def edit_rule_post():
    rule_id = request.form.get('rule_id')
    if not rule_id:
        flash('Kural ID eksik!', 'error')
        return redirect(url_for('index'))

    try:
        chain = request.form.get('chain')
        src_address = request.form.get('src_address')
        dst_address = request.form.get('dst_address')
        protocol = request.form.get('protocol')
        dst_port = request.form.get('dst_port')
        action = request.form.get('action')
        comment = request.form.get('comment')

        api = mikrotik_login()

        # Boş değerleri None olarak ayarla
        update_data = {'.id': rule_id}
        
        if chain:
            update_data['chain'] = chain
        if src_address:
            update_data['src-address'] = src_address
        if dst_address:
            update_data['dst-address'] = dst_address
        if protocol:
            update_data['protocol'] = protocol
        if dst_port:
            update_data['dst-port'] = dst_port
        if action:
            update_data['action'] = action
        if comment:
            update_data['comment'] = comment

        api.path('ip', 'firewall', 'nat').set(**update_data)
        flash('Kural başarıyla güncellendi!', 'success')
    except Exception as e:
        flash(f'Kural güncellenirken hata oluştu: {str(e)}', 'error')

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
        
        # Her ağ için ayrı analiz
        network_analysis = {}
        
        for range_prefix in target_ranges:
            network_name = range_prefix + 'x'
            
            # Bu ağdaki kullanılan IP'ler
            used_in_network = []
            available_in_network = []
            
            for i in range(1, 255):
                ip = f"{range_prefix}{i}"
                if ip in used_ips:
                    # Kullanılan IP için detay bilgi topla
                    ip_details = {'ip': ip, 'type': 'unknown', 'hostname': '', 'mac': '', 'status': ''}
                    
                    # DHCP lease'den bilgi al
                    for lease in filtered_leases:
                        if lease.get('address') == ip:
                            ip_details.update({
                                'type': 'DHCP',
                                'hostname': lease.get('host-name', ''),
                                'mac': lease.get('mac-address', ''),
                                'status': lease.get('status', '')
                            })
                            break
                    
                    # ARP tablosundan bilgi al (eğer DHCP'de yoksa)
                    if ip_details['type'] == 'unknown':
                        for arp_entry in filtered_arp:
                            if arp_entry.get('address') == ip:
                                ip_details.update({
                                    'type': 'ARP',
                                    'mac': arp_entry.get('mac-address', ''),
                                    'status': 'complete' if arp_entry.get('complete') == 'true' else 'incomplete'
                                })
                                break
                    
                    used_in_network.append(ip_details)
                else:
                    available_in_network.append(ip)
            
            # Kullanım yüzdesini hesapla
            total_count = 254
            used_count = len(used_in_network)
            available_count = len(available_in_network)
            usage_percentage = round((used_count / total_count) * 100) if total_count > 0 else 0
            
            network_analysis[network_name] = {
                'used_ips': used_in_network,
                'available_ips': available_in_network,
                'used_count': used_count,
                'available_count': available_count,
                'total_count': total_count,
                'usage_percentage': usage_percentage
            }
        
        return render_template('ip_monitor.html', 
                             dhcp_leases=filtered_leases, 
                             arp_table=filtered_arp,
                             used_ips=sorted(used_ips),
                             network_analysis=network_analysis,
                             addresses=addresses)
    except Exception as e:
        flash(f'IP veriler yüklenirken hata oluştu: {str(e)}', 'error')
        return render_template('ip_monitor.html', 
                             dhcp_leases=[], 
                             arp_table=[],
                             used_ips=[],
                             network_analysis={},
                             addresses=[])

# JSON API endpoint'i - AJAX için
@app.route('/api/ip_monitor_data')
@login_required
def ip_monitor_data():
    """IP monitor verileri için JSON API"""
    try:
        print("API: IP monitor data istendi")
        api = mikrotik_login()
        
        # DHCP lease'leri al
        dhcp_leases = list(api.path('ip', 'dhcp-server', 'lease'))
        print(f"API: {len(dhcp_leases)} DHCP lease bulundu")
        
        # ARP tablosunu al
        arp_table = list(api.path('ip', 'arp'))
        print(f"API: {len(arp_table)} ARP girişi bulundu")
        
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
        
        print(f"API: DHCP/ARP'den {len(used_ips)} kullanılan IP bulundu")
        
        # Her ağ için ayrı analiz
        network_analysis = {}
        
        for range_prefix in target_ranges:
            network_name = range_prefix + 'x'
            
            # Sadece 192.168.254.x ağı için ek tarama yap
            if range_prefix == '192.168.254.':
                print("API: 192.168.254.x ağı için ek tarama başlatılıyor...")
                try:
                    # Hızlı tarama yap
                    active_ips_scan = get_network_scan(range_prefix, max_workers=30)
                    print(f"API: Tarama ile {len(active_ips_scan)} aktif IP bulundu")
                    
                    for ip in active_ips_scan:
                        if ip not in used_ips:
                            used_ips.add(ip)
                            # Tarama ile bulunan IP'ler için ARP tablosuna ekle
                            filtered_arp.append({
                                'address': ip,
                                'mac-address': 'Tarama ile bulundu',
                                'interface': 'Scan',
                                'complete': 'true',
                                'comment': 'Ağ tarama sonucu'
                            })
                except Exception as scan_error:
                    print(f"API: Ağ tarama hatası: {scan_error}")
            
            # Bu ağdaki kullanılan IP'ler
            used_in_network = []
            available_in_network = []
            
            for i in range(1, 255):
                ip = f"{range_prefix}{i}"
                if ip in used_ips:
                    # Kullanılan IP için detay bilgi topla
                    ip_details = {'ip': ip, 'type': 'unknown', 'hostname': '', 'mac': '', 'status': ''}
                    
                    # DHCP lease'den bilgi al
                    for lease in filtered_leases:
                        if lease.get('address') == ip:
                            ip_details.update({
                                'type': 'DHCP',
                                'hostname': lease.get('host-name', ''),
                                'mac': lease.get('mac-address', ''),
                                'status': lease.get('status', '')
                            })
                            break
                    
                    # ARP tablosundan bilgi al (eğer DHCP'de yoksa)
                    if ip_details['type'] == 'unknown':
                        for arp_entry in filtered_arp:
                            if arp_entry.get('address') == ip:
                                ip_details.update({
                                    'type': 'ARP',
                                    'mac': arp_entry.get('mac-address', ''),
                                    'status': 'complete' if arp_entry.get('complete') == 'true' else 'incomplete'
                                })
                                break
                    
                    used_in_network.append(ip_details)
                else:
                    available_in_network.append(ip)
            
            # Kullanım yüzdesini hesapla
            total_count = 254
            used_count = len(used_in_network)
            available_count = len(available_in_network)
            usage_percentage = round((used_count / total_count) * 100) if total_count > 0 else 0
            
            network_analysis[network_name] = {
                'used_ips': used_in_network,
                'available_ips': available_in_network,
                'used_count': used_count,
                'available_count': available_count,
                'total_count': total_count,
                'usage_percentage': usage_percentage
            }
            
            print(f"API: {network_name} - {used_count} kullanılan, {available_count} boş")
        
        print(f"API: Toplam {len(used_ips)} IP kullanımda")
        
        # JSON formatında döndür
        response_data = {
            'success': True,
            'dhcp_leases': filtered_leases,
            'arp_table': filtered_arp,
            'used_ips': sorted(list(used_ips)),
            'network_analysis': network_analysis,
            'addresses': addresses,
            'timestamp': int(time.time())
        }
        
        print("API: Veriler başarıyla hazırlandı")
        return jsonify(response_data)
        
    except Exception as e:
        print(f"API: Hata oluştu: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': int(time.time())
        }), 500

# Hızlı ping kontrolü için endpoint
@app.route('/api/ping_network/<network>')
@login_required
def ping_network(network):
    """Belirli bir ağı hızlı tarar"""
    try:
        print(f"API: Ağ tarama istendi: {network}")
        
        # Güvenlik kontrolü
        allowed_networks = ['10.10.10', '20.20.20', '192.168.254']
        if network not in allowed_networks:
            return jsonify({'success': False, 'error': 'Geçersiz ağ adresi'}), 400
        
        network_prefix = f"{network}."
        print(f"API: {network_prefix}x ağı taranıyor...")
        
        # Network scan başlat
        active_ips = get_network_scan(network_prefix, max_workers=40)
        
        print(f"API: Tarama tamamlandı. {len(active_ips)} aktif IP bulundu")
        
        return jsonify({
            'success': True,
            'network': network,
            'active_ips': active_ips,
            'count': len(active_ips),
            'timestamp': int(time.time())
        })
        
    except Exception as e:
        print(f"API: Ping network hatası: {str(e)}")
        return jsonify({
            'success': False, 
            'error': str(e),
            'timestamp': int(time.time())
        }), 500

# Kullanıcı profil sayfası
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

# Sağlık kontrolü endpoint'i
@app.route('/api/health')
def health_check():
    """Uygulama sağlık durumu kontrolü"""
    try:
        # MikroTik bağlantısını test et (eğer session varsa)
        mikrotik_status = 'disconnected'
        if 'mikrotik_user' in session:
            try:
                api = mikrotik_login()
                # Basit bir komut çalıştır
                list(api.path('system', 'identity'))
                mikrotik_status = 'connected'
            except:
                mikrotik_status = 'error'
        
        return jsonify({
            'status': 'healthy',
            'timestamp': int(time.time()),
            'mikrotik_connection': mikrotik_status,
            'session_active': 'mikrotik_user' in session
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': int(time.time())
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Uygulama başlatma
if __name__ == '__main__':
    print("🚀 MikroTik Panel başlatılıyor...")
    print(f"📡 MikroTik Host: {MIKROTIK_HOST}:{MIKROTIK_PORT}")
    print(f"🌐 Web Server: http://0.0.0.0:5050")
    print("🔧 Debug Mode: Aktif")
    print("⚡ AJAX API: /api/ip_monitor_data")
    print("🔍 Network Scan: /api/ping_network/<network>")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5050, debug=True)