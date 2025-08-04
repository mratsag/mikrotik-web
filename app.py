from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from librouteros import connect
from functools import wraps
import secrets
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import ipaddress
import re

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

# IP ping kontrolü için yardımcı fonksiyon
def ping_ip(ip, timeout=1):
    """IP adresinin erişilebilir olup olmadığını kontrol eder"""
    try:
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
        if ping_ip(ip, 0.8):
            return ip
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_ip, i) for i in range(1, 255)]
        for i, future in enumerate(futures):
            try:
                result = future.result(timeout=2)
                if result:
                    active_ips.append(result)
            except Exception:
                pass
        active_ips.sort(key=lambda x: int(x.split('.')[-1]))
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

# ===============================
# DHCP SERVER MANAGEMENT
# ===============================

@app.route('/dhcp_management')
@login_required
def dhcp_management():
    """DHCP Server yönetim sayfası"""
    try:
        api = mikrotik_login()
        
        # DHCP Server'ları al
        dhcp_servers = list(api.path('ip', 'dhcp-server'))
        
        # IP Pool'ları al
        ip_pools = list(api.path('ip', 'pool'))
        
        # Interface'leri al
        interfaces = list(api.path('interface'))
        
        # DHCP Network'leri al
        dhcp_networks = list(api.path('ip', 'dhcp-server', 'network'))
        
        return render_template('dhcp_management.html', 
                             dhcp_servers=dhcp_servers,
                             ip_pools=ip_pools,
                             interfaces=interfaces,
                             dhcp_networks=dhcp_networks)
    except Exception as e:
        flash(f'DHCP veriler yüklenirken hata oluştu: {str(e)}', 'error')
        return render_template('dhcp_management.html', 
                             dhcp_servers=[], ip_pools=[], interfaces=[], dhcp_networks=[])

@app.route('/add_dhcp_server', methods=['POST'])
@login_required
def add_dhcp_server():
    """Yeni DHCP Server ekle"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        server_name = request.form['server_name']
        interface = request.form['interface']
        address_pool = request.form['address_pool']
        lease_time = request.form.get('lease_time', '1d')
        
        # DHCP Server oluştur
        api.path('ip', 'dhcp-server').add(
            name=server_name,
            interface=interface,
            **{'address-pool': address_pool},
            **{'lease-time': lease_time},
            disabled='false'
        )
        
        flash(f'DHCP Server "{server_name}" başarıyla oluşturuldu!', 'success')
    except Exception as e:
        flash(f'DHCP Server oluşturulurken hata: {str(e)}', 'error')
    
    return redirect(url_for('dhcp_management'))

@app.route('/add_ip_pool', methods=['POST'])
@login_required
def add_ip_pool():
    """Yeni IP Pool ekle"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        pool_name = request.form['pool_name']
        ranges = request.form['ranges']  # Format: 192.168.1.100-192.168.1.200
        
        # IP Pool oluştur
        api.path('ip', 'pool').add(
            name=pool_name,
            ranges=ranges
        )
        
        flash(f'IP Pool "{pool_name}" başarıyla oluşturuldu!', 'success')
    except Exception as e:
        flash(f'IP Pool oluşturulurken hata: {str(e)}', 'error')
    
    return redirect(url_for('dhcp_management'))

@app.route('/add_dhcp_network', methods=['POST'])
@login_required
def add_dhcp_network():
    """DHCP Network ekle"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        address = request.form['network_address']  # 192.168.1.0/24
        gateway = request.form['gateway']
        dns_servers = request.form.get('dns_servers', '8.8.8.8,8.8.4.4')
        domain = request.form.get('domain', '')
        
        # DHCP Network oluştur
        network_data = {
            'address': address,
            'gateway': gateway,
            'dns-server': dns_servers
        }
        
        if domain:
            network_data['domain'] = domain
            
        api.path('ip', 'dhcp-server', 'network').add(**network_data)
        
        flash(f'DHCP Network "{address}" başarıyla oluşturuldu!', 'success')
    except Exception as e:
        flash(f'DHCP Network oluşturulurken hata: {str(e)}', 'error')
    
    return redirect(url_for('dhcp_management'))

# ===============================
# INTERFACE & VLAN MANAGEMENT
# ===============================

@app.route('/interface_management')
@login_required
def interface_management():
    """Interface ve VLAN yönetim sayfası"""
    try:
        api = mikrotik_login()
        
        # Tüm interface'leri al
        interfaces = list(api.path('interface'))
        
        # VLAN interface'leri al
        vlan_interfaces = list(api.path('interface', 'vlan'))
        
        # Bridge'leri al
        bridges = list(api.path('interface', 'bridge'))
        
        # Bridge port'larını al
        bridge_ports = list(api.path('interface', 'bridge', 'port'))
        
        # IP adresleri al
        ip_addresses = list(api.path('ip', 'address'))
        
        return render_template('interface_management.html',
                             interfaces=interfaces,
                             vlan_interfaces=vlan_interfaces,
                             bridges=bridges,
                             bridge_ports=bridge_ports,
                             ip_addresses=ip_addresses)
    except Exception as e:
        flash(f'Interface veriler yüklenirken hata oluştu: {str(e)}', 'error')
        return render_template('interface_management.html',
                             interfaces=[], vlan_interfaces=[], bridges=[], bridge_ports=[], ip_addresses=[])

@app.route('/create_vlan', methods=['POST'])
@login_required
def create_vlan():
    """Yeni VLAN oluştur"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        vlan_name = request.form['vlan_name']  # pglan10
        vlan_id = request.form['vlan_id']      # 10
        interface = request.form['interface']   # ether2
        
        # VLAN interface oluştur
        api.path('interface', 'vlan').add(
            name=vlan_name,
            **{'vlan-id': vlan_id},
            interface=interface
        )
        
        flash(f'VLAN "{vlan_name}" (ID: {vlan_id}) başarıyla oluşturuldu!', 'success')
    except Exception as e:
        flash(f'VLAN oluşturulurken hata: {str(e)}', 'error')
    
    return redirect(url_for('interface_management'))

@app.route('/create_bridge', methods=['POST'])
@login_required
def create_bridge():
    """Yeni Bridge oluştur"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        bridge_name = request.form['bridge_name']
        
        # Bridge oluştur
        api.path('interface', 'bridge').add(name=bridge_name)
        
        flash(f'Bridge "{bridge_name}" başarıyla oluşturuldu!', 'success')
    except Exception as e:
        flash(f'Bridge oluşturulurken hata: {str(e)}', 'error')
    
    return redirect(url_for('interface_management'))

@app.route('/add_bridge_port', methods=['POST'])
@login_required
def add_bridge_port():
    """Bridge'e port ekle"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        bridge = request.form['bridge']
        interface = request.form['port_interface']
        
        # Bridge port ekle
        api.path('interface', 'bridge', 'port').add(
            bridge=bridge,
            interface=interface
        )
        
        flash(f'Interface "{interface}" bridge "{bridge}" üzerine eklendi!', 'success')
    except Exception as e:
        flash(f'Bridge port eklenirken hata: {str(e)}', 'error')
    
    return redirect(url_for('interface_management'))

@app.route('/assign_ip', methods=['POST'])
@login_required
def assign_ip():
    """Interface'e IP adresi ata"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        interface = request.form['ip_interface']
        address = request.form['ip_address']    # 192.168.10.1/24
        
        # IP adresi ata
        api.path('ip', 'address').add(
            interface=interface,
            address=address
        )
        
        flash(f'IP adresi "{address}" interface "{interface}" üzerine atandı!', 'success')
    except Exception as e:
        flash(f'IP adresi atanırken hata: {str(e)}', 'error')
    
    return redirect(url_for('interface_management'))

# ===============================
# VM NETWORK WIZARD
# ===============================

@app.route('/vm_network_wizard')
@login_required
def vm_network_wizard():
    """VM Network kurulum sihirbazı"""
    try:
        api = mikrotik_login()
        
        # Mevcut interface'leri al
        interfaces = list(api.path('interface'))
        
        # Mevcut VLAN'ları al
        vlan_interfaces = list(api.path('interface', 'vlan'))
        
        # Mevcut DHCP Server'ları al
        dhcp_servers = list(api.path('ip', 'dhcp-server'))
        
        # Bridge'leri al
        bridges = list(api.path('interface', 'bridge'))
        
        return render_template('vm_network_wizard.html',
                             interfaces=interfaces,
                             vlan_interfaces=vlan_interfaces,
                             dhcp_servers=dhcp_servers,
                             bridges=bridges)
    except Exception as e:
        flash(f'Sihirbaz yüklenirken hata oluştu: {str(e)}', 'error')
        return render_template('vm_network_wizard.html',
                             interfaces=[], vlan_interfaces=[], dhcp_servers=[], bridges=[])

@app.route('/create_vm_network', methods=['POST'])
@login_required
def create_vm_network():
    """VM için tam network kurulumu yap"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        vm_name = request.form['vm_name']
        base_interface = request.form['base_interface']
        vlan_id = request.form['vlan_id']
        network_address = request.form['network_address']  # 192.168.10.0/24
        gateway_ip = request.form['gateway_ip']            # 192.168.10.1
        dhcp_start = request.form['dhcp_start']            # 192.168.10.100
        dhcp_end = request.form['dhcp_end']                # 192.168.10.200
        dns_servers = request.form.get('dns_servers', '8.8.8.8,8.8.4.4')
        
        # İsim formatları
        vlan_name = f"{vm_name}-vlan{vlan_id}"
        pool_name = f"{vm_name}-pool"
        dhcp_server_name = f"{vm_name}-dhcp"
        bridge_name = f"{vm_name}-bridge"
        
        results = []
        
        # 1. VLAN Interface oluştur
        try:
            api.path('interface', 'vlan').add(
                name=vlan_name,
                **{'vlan-id': vlan_id},
                interface=base_interface
            )
            results.append(f"✅ VLAN interface '{vlan_name}' oluşturuldu")
        except Exception as e:
            results.append(f"❌ VLAN oluşturma hatası: {str(e)}")
        
        # 2. Bridge oluştur
        try:
            api.path('interface', 'bridge').add(name=bridge_name)
            results.append(f"✅ Bridge '{bridge_name}' oluşturuldu")
        except Exception as e:
            results.append(f"❌ Bridge oluşturma hatası: {str(e)}")
        
        # 3. VLAN'ı Bridge'e ekle
        try:
            api.path('interface', 'bridge', 'port').add(
                bridge=bridge_name,
                interface=vlan_name
            )
            results.append(f"✅ VLAN bridge'e eklendi")
        except Exception as e:
            results.append(f"❌ Bridge port ekleme hatası: {str(e)}")
        
        # 4. Bridge'e IP adresi ata
        try:
            api.path('ip', 'address').add(
                interface=bridge_name,
                address=f"{gateway_ip}/{network_address.split('/')[1]}"
            )
            results.append(f"✅ IP adresi '{gateway_ip}' atandı")
        except Exception as e:
            results.append(f"❌ IP atama hatası: {str(e)}")
        
        # 5. IP Pool oluştur
        try:
            api.path('ip', 'pool').add(
                name=pool_name,
                ranges=f"{dhcp_start}-{dhcp_end}"
            )
            results.append(f"✅ IP Pool '{pool_name}' oluşturuldu")
        except Exception as e:
            results.append(f"❌ IP Pool oluşturma hatası: {str(e)}")
        
        # 6. DHCP Server oluştur
        try:
            api.path('ip', 'dhcp-server').add(
                name=dhcp_server_name,
                interface=bridge_name,
                **{'address-pool': pool_name},
                **{'lease-time': '1d'},
                disabled='false'
            )
            results.append(f"✅ DHCP Server '{dhcp_server_name}' oluşturuldu")
        except Exception as e:
            results.append(f"❌ DHCP Server oluşturma hatası: {str(e)}")
        
        # 7. DHCP Network ekle
        try:
            api.path('ip', 'dhcp-server', 'network').add(
                address=network_address,
                gateway=gateway_ip,
                **{'dns-server': dns_servers},
                domain=f"{vm_name}.local"
            )
            results.append(f"✅ DHCP Network oluşturuldu")
        except Exception as e:
            results.append(f"❌ DHCP Network oluşturma hatası: {str(e)}")
        
        # 8. Firewall kuralı ekle (VM'den internete çıkış)
        try:
            api.path('ip', 'firewall', 'nat').add(
                chain='srcnat',
                **{'src-address': network_address},
                **{'out-interface-list': 'WAN'},
                action='masquerade',
                comment=f"{vm_name} NAT Rule"
            )
            results.append(f"✅ NAT kuralı eklendi")
        except Exception as e:
            results.append(f"❌ NAT kuralı ekleme hatası: {str(e)}")
        
        # Sonuçları session'a kaydet
        session['vm_setup_results'] = {
            'vm_name': vm_name,
            'vlan_name': vlan_name,
            'bridge_name': bridge_name,
            'network_address': network_address,
            'gateway_ip': gateway_ip,
            'dhcp_range': f"{dhcp_start}-{dhcp_end}",
            'results': results
        }
        
        flash(f'VM "{vm_name}" için network kurulumu tamamlandı!', 'success')
        return redirect(url_for('vm_setup_results'))
        
    except Exception as e:
        flash(f'VM network kurulumu hatası: {str(e)}', 'error')
        return redirect(url_for('vm_network_wizard'))

@app.route('/vm_setup_results')
@login_required
def vm_setup_results():
    """VM kurulum sonuçlarını göster"""
    if 'vm_setup_results' not in session:
        flash('Kurulum sonuçları bulunamadı!', 'warning')
        return redirect(url_for('vm_network_wizard'))
    
    results = session.pop('vm_setup_results')
    return render_template('vm_setup_results.html', results=results)

# ===============================
# ADVANCED NAT MANAGEMENT
# ===============================

@app.route('/advanced_nat')
@login_required
def advanced_nat():
    """Gelişmiş NAT yönetimi"""
    try:
        api = mikrotik_login()
        
        # NAT kurallarını al
        nat_rules = list(api.path('ip', 'firewall', 'nat'))
        
        # Interface'leri al
        interfaces = list(api.path('interface'))
        
        # Address list'leri al
        address_lists = list(api.path('ip', 'firewall', 'address-list'))
        
        return render_template('advanced_nat.html',
                             nat_rules=nat_rules,
                             interfaces=interfaces,
                             address_lists=address_lists)
    except Exception as e:
        flash(f'NAT veriler yüklenirken hata oluştu: {str(e)}', 'error')
        return render_template('advanced_nat.html',
                             nat_rules=[], interfaces=[], address_lists=[])

@app.route('/add_advanced_nat', methods=['POST'])
@login_required
def add_advanced_nat():
    """Gelişmiş NAT kuralı ekle"""
    try:
        api = mikrotik_login()
        
        # Form verilerini al
        rule_name = request.form['rule_name']
        chain = request.form['chain']
        protocol = request.form.get('protocol', 'tcp')
        src_address = request.form.get('src_address', '')
        dst_address = request.form.get('dst_address', '')
        dst_port = request.form.get('dst_port', '')
        to_addresses = request.form.get('to_addresses', '')
        to_ports = request.form.get('to_ports', '')
        out_interface = request.form.get('out_interface', '')
        action = request.form['action']
        
        # NAT kuralı verilerini hazırla
        nat_data = {
            'chain': chain,
            'action': action,
            'comment': rule_name
        }
        
        if protocol:
            nat_data['protocol'] = protocol
        if src_address:
            nat_data['src-address'] = src_address
        if dst_address:
            nat_data['dst-address'] = dst_address
        if dst_port:
            nat_data['dst-port'] = dst_port
        if to_addresses:
            nat_data['to-addresses'] = to_addresses
        if to_ports:
            nat_data['to-ports'] = to_ports
        if out_interface:
            nat_data['out-interface'] = out_interface
        
        # NAT kuralını ekle
        api.path('ip', 'firewall', 'nat').add(**nat_data)
        
        flash(f'NAT kuralı "{rule_name}" başarıyla eklendi!', 'success')
    except Exception as e:
        flash(f'NAT kuralı eklenirken hata: {str(e)}', 'error')
    
    return redirect(url_for('advanced_nat'))

# ===============================
# EXISTING ROUTES (NAT, IP MONITOR, ETC.)
# ===============================

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
        
        dhcp_leases = list(api.path('ip', 'dhcp-server', 'lease'))
        arp_table = list(api.path('ip', 'arp'))
        addresses = list(api.path('ip', 'address'))
        
        target_ranges = ['10.10.10.', '20.20.20.', '192.168.254.']
        
        filtered_leases = []
        for lease in dhcp_leases:
            ip = lease.get('address', '')
            if any(ip.startswith(range_prefix) for range_prefix in target_ranges):
                filtered_leases.append(lease)
        
        filtered_arp = []
        for arp in arp_table:
            ip = arp.get('address', '')
            if any(ip.startswith(range_prefix) for range_prefix in target_ranges):
                filtered_arp.append(arp)
        
        used_ips = set()
        for lease in filtered_leases:
            if lease.get('address'):
                used_ips.add(lease.get('address'))
        
        for arp in filtered_arp:
            if arp.get('address'):
                used_ips.add(arp.get('address'))
        
        network_analysis = {}
        
        for range_prefix in target_ranges:
            network_name = range_prefix + 'x'
            
            if range_prefix == '192.168.254.':
                try:
                    active_ips_scan = get_network_scan(range_prefix, max_workers=30)
                    for ip in active_ips_scan:
                        if ip not in used_ips:
                            used_ips.add(ip)
                            filtered_arp.append({
                                'address': ip,
                                'mac-address': 'Tarama ile bulundu',
                                'interface': 'Scan',
                                'complete': 'true',
                                'comment': 'Ağ tarama sonucu'
                            })
                except Exception as scan_error:
                    print(f"Ağ tarama hatası: {scan_error}")
            
            used_in_network = []
            available_in_network = []
            
            for i in range(1, 255):
                ip = f"{range_prefix}{i}"
                if ip in used_ips:
                    ip_details = {'ip': ip, 'type': 'unknown', 'hostname': '', 'mac': '', 'status': ''}
                    
                    for lease in filtered_leases:
                        if lease.get('address') == ip:
                            ip_details.update({
                                'type': 'DHCP',
                                'hostname': lease.get('host-name', ''),
                                'mac': lease.get('mac-address', ''),
                                'status': lease.get('status', '')
                            })
                            break
                    
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
        api = mikrotik_login()
        
        dhcp_leases = list(api.path('ip', 'dhcp-server', 'lease'))
        arp_table = list(api.path('ip', 'arp'))
        addresses = list(api.path('ip', 'address'))
        
        target_ranges = ['10.10.10.', '20.20.20.', '192.168.254.']
        
        filtered_leases = []
        for lease in dhcp_leases:
            ip = lease.get('address', '')
            if any(ip.startswith(range_prefix) for range_prefix in target_ranges):
                filtered_leases.append(lease)
        
        filtered_arp = []
        for arp in arp_table:
            ip = arp.get('address', '')
            if any(ip.startswith(range_prefix) for range_prefix in target_ranges):
                filtered_arp.append(arp)
        
        used_ips = set()
        for lease in filtered_leases:
            if lease.get('address'):
                used_ips.add(lease.get('address'))
        
        for arp in filtered_arp:
            if arp.get('address'):
                used_ips.add(arp.get('address'))
        
        network_analysis = {}
        
        for range_prefix in target_ranges:
            network_name = range_prefix + 'x'
            
            if range_prefix == '192.168.254.':
                try:
                    active_ips_scan = get_network_scan(range_prefix, max_workers=30)
                    for ip in active_ips_scan:
                        if ip not in used_ips:
                            used_ips.add(ip)
                            filtered_arp.append({
                                'address': ip,
                                'mac-address': 'Tarama ile bulundu',
                                'interface': 'Scan',
                                'complete': 'true',
                                'comment': 'Ağ tarama sonucu'
                            })
                except Exception as scan_error:
                    print(f"Ağ tarama hatası: {scan_error}")
            
            used_in_network = []
            available_in_network = []
            
            for i in range(1, 255):
                ip = f"{range_prefix}{i}"
                if ip in used_ips:
                    ip_details = {'ip': ip, 'type': 'unknown', 'hostname': '', 'mac': '', 'status': ''}
                    
                    for lease in filtered_leases:
                        if lease.get('address') == ip:
                            ip_details.update({
                                'type': 'DHCP',
                                'hostname': lease.get('host-name', ''),
                                'mac': lease.get('mac-address', ''),
                                'status': lease.get('status', '')
                            })
                            break
                    
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
        
        return jsonify({
            'success': True,
            'dhcp_leases': filtered_leases,
            'arp_table': filtered_arp,
            'used_ips': sorted(list(used_ips)),
            'network_analysis': network_analysis,
            'addresses': addresses,
            'timestamp': int(time.time())
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': int(time.time())
        }), 500

@app.route('/api/ping_network/<network>')
@login_required
def ping_network(network):
    """Belirli bir ağı hızlı tarar"""
    try:
        allowed_networks = ['10.10.10', '20.20.20', '192.168.254']
        if network not in allowed_networks:
            return jsonify({'success': False, 'error': 'Geçersiz ağ adresi'}), 400
        
        network_prefix = f"{network}."
        active_ips = get_network_scan(network_prefix, max_workers=40)
        
        return jsonify({
            'success': True,
            'network': network,
            'active_ips': active_ips,
            'count': len(active_ips),
            'timestamp': int(time.time())
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': str(e),
            'timestamp': int(time.time())
        }), 500

@app.route('/profile')
@login_required
def profile():
    try:
        api = mikrotik_login()
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

@app.route('/api/health')
def health_check():
    """Uygulama sağlık durumu kontrolü"""
    try:
        mikrotik_status = 'disconnected'
        if 'mikrotik_user' in session:
            try:
                api = mikrotik_login()
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

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    print("🚀 MikroTik Panel başlatılıyor...")
    print(f"📡 MikroTik Host: {MIKROTIK_HOST}:{MIKROTIK_PORT}")
    print(f"🌐 Web Server: http://0.0.0.0:5050")
    print("🔧 Production Mode: Aktif")
    print("⚡ AJAX API: /api/ip_monitor_data")
    print("🔍 Network Scan: /api/ping_network/<network>")
    print("🆕 DHCP Management: /dhcp_management")
    print("🆕 Interface Management: /interface_management")
    print("🆕 VM Network Wizard: /vm_network_wizard")
    print("🆕 Advanced NAT: /advanced_nat")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5050, debug=False)