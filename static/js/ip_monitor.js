// IP Monitor Page JavaScript - AJAX ile dinamik güncelleme
document.addEventListener('DOMContentLoaded', function() {
    
    let refreshInterval;
    let isSearching = false;
    let lastUpdateTime = 0;
    
    // Search functionality for tables
    function setupTableSearch(searchInputId, tableId) {
        const input = document.getElementById(searchInputId);
        const table = document.getElementById(tableId);
        
        if (!input || !table) return;
        
        input.addEventListener('input', function() {
            const filter = this.value.toLowerCase();
            const rows = table.querySelectorAll('tbody tr');
            let visibleCount = 0;
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(filter)) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            updateSearchResultCount(tableId, visibleCount, rows.length);
        });
        
        // Clear search on Escape
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                this.value = '';
                this.dispatchEvent(new Event('input'));
            }
        });
        
        // Pause refresh when searching
        input.addEventListener('focus', () => {
            isSearching = true;
            clearInterval(refreshInterval);
            console.log('Search active - pausing auto refresh');
        });
        
        input.addEventListener('blur', () => {
            isSearching = false;
            startAutoRefresh();
            console.log('Search inactive - resuming auto refresh');
        });
    }
    
    // Update search result count
    function updateSearchResultCount(tableId, visible, total) {
        let countElement = document.getElementById(tableId + '_count');
        if (!countElement) {
            countElement = document.createElement('div');
            countElement.id = tableId + '_count';
            countElement.style.cssText = `
                font-size: 0.85rem;
                color: #666;
                margin-top: 10px;
                text-align: right;
                font-style: italic;
            `;
            const table = document.getElementById(tableId);
            if (table && table.parentElement) {
                table.parentElement.appendChild(countElement);
            }
        }
        
        if (visible < total) {
            countElement.innerHTML = `<i class="fas fa-filter"></i> ${visible} / ${total} kayıt gösteriliyor`;
        } else {
            countElement.innerHTML = `<i class="fas fa-list"></i> ${total} kayıt`;
        }
    }

    // AJAX ile veri çekme fonksiyonu
    async function fetchIPMonitorData() {
        try {
            showLoadingIndicator();
            console.log('Fetching IP monitor data...');
            
            const response = await fetch('/api/ip_monitor_data', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
                cache: 'no-cache'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.success) {
                updateIPMonitorUI(data);
                lastUpdateTime = data.timestamp;
                showSuccessIndicator();
                console.log('Data updated successfully');
            } else {
                throw new Error(data.error || 'Bilinmeyen hata');
            }
            
        } catch (error) {
            console.error('Veri çekme hatası:', error);
            showErrorIndicator(error.message);
        } finally {
            hideLoadingIndicator();
        }
    }
    
    // UI güncelleme fonksiyonu
    function updateIPMonitorUI(data) {
        console.log('Updating UI with new data...');
        
        // İstatistikleri güncelle
        updateStatistics(data);
        
        // DHCP tablosunu güncelle
        updateDHCPTable(data.dhcp_leases);
        
        // ARP tablosunu güncelle
        updateARPTable(data.arp_table);
        
        // Ağ analizini güncelle
        updateNetworkAnalysis(data.network_analysis);
        
        // Son güncelleme zamanını göster
        updateLastRefreshTime();
        
        console.log('UI update completed');
    }
    
    // İstatistikleri güncelle
    function updateStatistics(data) {
        const statNumbers = document.querySelectorAll('.stat-number');
        
        if (statNumbers.length >= 4) {
            // Toplam kullanılan IP
            animateCounter(statNumbers[0], data.used_ips.length);
            
            // Toplam kullanılabilir IP
            let totalAvailable = 0;
            for (const network in data.network_analysis) {
                totalAvailable += data.network_analysis[network].available_count;
            }
            animateCounter(statNumbers[1], totalAvailable);
            
            // DHCP lease sayısı
            animateCounter(statNumbers[2], data.dhcp_leases.length);
            
            // ARP giriş sayısı
            animateCounter(statNumbers[3], data.arp_table.length);
        }
    }
    
    // Sayı animasyonu
    function animateCounter(element, targetValue) {
        const currentValue = parseInt(element.textContent) || 0;
        const difference = Math.abs(targetValue - currentValue);
        
        // Büyük değişikliklerde animasyon, küçüklerde direkt güncelleme
        if (difference <= 1) {
            element.textContent = targetValue;
            return;
        }
        
        const increment = (targetValue - currentValue) / 20;
        let current = currentValue;
        
        const timer = setInterval(() => {
            current += increment;
            if ((increment > 0 && current >= targetValue) || (increment < 0 && current <= targetValue)) {
                element.textContent = targetValue;
                clearInterval(timer);
            } else {
                element.textContent = Math.round(current);
            }
        }, 50);
    }
    
    // DHCP tablosunu güncelle
    function updateDHCPTable(dhcpLeases) {
        const tableBody = document.querySelector('#dhcpTable tbody');
        if (!tableBody) return;
        
        // Mevcut search değerini sakla
        const searchInput = document.getElementById('dhcpSearch');
        const currentSearch = searchInput ? searchInput.value : '';
        
        tableBody.innerHTML = '';
        
        dhcpLeases.forEach((lease, index) => {
            const row = document.createElement('tr');
            row.style.opacity = '0';
            row.style.transform = 'translateY(10px)';
            
            row.innerHTML = `
                <td><strong class="ip-address" title="Kopyalamak için tıklayın">${lease.address || '-'}</strong></td>
                <td style="font-family: monospace;">${lease['mac-address'] || '-'}</td>
                <td>${lease['host-name'] || '-'}</td>
                <td>${lease['lease-time'] || '-'}</td>
                <td>
                    ${lease.status === 'bound' 
                        ? '<span class="status-badge status-bound"><i class="fas fa-check-circle"></i> Aktif</span>'
                        : `<span class="status-badge status-inactive"><i class="fas fa-times-circle"></i> ${lease.status || 'Bilinmiyor'}</span>`
                    }
                </td>
                <td>${lease['last-seen'] || '-'}</td>
            `;
            
            tableBody.appendChild(row);
            
            // Animasyonlu ekleme
            setTimeout(() => {
                row.style.transition = 'all 0.3s ease';
                row.style.opacity = '1';
                row.style.transform = 'translateY(0)';
            }, index * 50);
        });
        
        // Search functionality'yi yeniden aktifleştir
        if (searchInput && currentSearch) {
            searchInput.value = currentSearch;
            searchInput.dispatchEvent(new Event('input'));
        }
        
        // IP kopyalama özelliğini aktifleştir
        setupIPClickEvents();
    }
    
    // ARP tablosunu güncelle
    function updateARPTable(arpTable) {
        const tableBody = document.querySelector('#arpTable tbody');
        if (!tableBody) return;
        
        // Mevcut search değerini sakla
        const searchInput = document.getElementById('arpSearch');
        const currentSearch = searchInput ? searchInput.value : '';
        
        tableBody.innerHTML = '';
        
        arpTable.forEach((arp, index) => {
            const row = document.createElement('tr');
            row.style.opacity = '0';
            row.style.transform = 'translateY(10px)';
            
            row.innerHTML = `
                <td><strong class="ip-address" title="Kopyalamak için tıklayın">${arp.address || '-'}</strong></td>
                <td style="font-family: monospace;">${arp['mac-address'] || '-'}</td>
                <td>${arp.interface || '-'}</td>
                <td>
                    ${arp.complete === 'true' 
                        ? '<span class="status-badge status-active"><i class="fas fa-wifi"></i> Aktif</span>'
                        : '<span class="status-badge status-inactive"><i class="fas fa-wifi-slash"></i> Pasif</span>'
                    }
                </td>
                <td>${arp.comment || '-'}</td>
            `;
            
            tableBody.appendChild(row);
            
            // Animasyonlu ekleme
            setTimeout(() => {
                row.style.transition = 'all 0.3s ease';
                row.style.opacity = '1';
                row.style.transform = 'translateY(0)';
            }, index * 30);
        });
        
        // Search functionality'yi yeniden aktifleştir
        if (searchInput && currentSearch) {
            searchInput.value = currentSearch;
            searchInput.dispatchEvent(new Event('input'));
        }
        
        // IP kopyalama özelliğini aktifleştir
        setupIPClickEvents();
    }
    
    // Ağ analizini güncelle
    function updateNetworkAnalysis(networkAnalysis) {
        const networkGrid = document.querySelector('.network-grid');
        if (!networkGrid) return;
        
        // Mevcut kartları yumuşak çıkış animasyonu ile kaldır
        const existingCards = networkGrid.querySelectorAll('.network-card');
        existingCards.forEach((card, index) => {
            setTimeout(() => {
                card.style.transition = 'all 0.3s ease';
                card.style.opacity = '0';
                card.style.transform = 'translateY(-20px)';
            }, index * 50);
        });
        
        setTimeout(() => {
            networkGrid.innerHTML = '';
            
            // Yeni kartları ekle
            Object.entries(networkAnalysis).forEach(([networkName, analysis], index) => {
                setTimeout(() => {
                    const networkCard = createNetworkCard(networkName, analysis);
                    networkGrid.appendChild(networkCard);
                }, index * 100);
            });
            
            // Event'leri yeniden aktifleştir
            setTimeout(() => {
                setupIPClickEvents();
                setupNetworkCardEvents();
            }, 500);
        }, 300);
    }
    
    // Ağ kartı oluştur
    function createNetworkCard(networkName, analysis) {
        const card = document.createElement('div');
        card.className = 'network-card';
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        
        let usedIPsHTML = '';
        if (analysis.used_ips && analysis.used_ips.length > 0) {
            const usedIPsList = analysis.used_ips.map(ipInfo => `
                <div class="used-ip-item" title="Detaylar için tıklayın">
                    <div class="ip-address">
                        ${ipInfo.ip}
                        <i class="fas fa-copy" style="font-size: 0.8rem; color: #999; cursor: pointer; opacity: 0.6;" title="Kopyala"></i>
                    </div>
                    <div class="ip-details">
                        <div class="ip-detail">
                            <div class="detail-label">Tip</div>
                            <div class="detail-value">
                                <span class="type-badge type-${ipInfo.type.toLowerCase()}">
                                    ${ipInfo.type === 'DHCP' ? '<i class="fas fa-server"></i>' : ipInfo.type === 'ARP' ? '<i class="fas fa-list"></i>' : '<i class="fas fa-question"></i>'} ${ipInfo.type}
                                </span>
                            </div>
                        </div>
                        <div class="ip-detail">
                            <div class="detail-label">Hostname</div>
                            <div class="detail-value ${!ipInfo.hostname ? 'empty' : ''}">
                                ${ipInfo.hostname || '-'}
                            </div>
                        </div>
                        <div class="ip-detail">
                            <div class="detail-label">MAC Adres</div>
                            <div class="detail-value ${!ipInfo.mac ? 'empty' : ''}" style="font-family: monospace;">
                                ${ipInfo.mac || '-'}
                            </div>
                        </div>
                        <div class="ip-detail">
                            <div class="detail-label">Durum</div>
                            <div class="detail-value ${!ipInfo.status ? 'empty' : ''}">
                                ${ipInfo.status || '-'}
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
            
            usedIPsHTML = `
                <div class="used-ips-section">
                    <div class="used-ips-title">
                        <i class="fas fa-wifi"></i>
                        Kullanılan IP Adresleri (${analysis.used_count})
                    </div>
                    <div class="used-ip-list">
                        ${usedIPsList}
                    </div>
                </div>
            `;
        }
        
        let availableSummaryHTML = '';
        if (analysis.available_count > 0) {
            let statusClass = '';
            let statusIcon = '';
            let statusText = '';
            
            if (analysis.available_count > 50) {
                statusClass = 'text-success';
                statusIcon = 'fas fa-check-circle';
                statusText = 'Bol miktarda IP mevcut';
            } else if (analysis.available_count < 10) {
                statusClass = 'text-warning';
                statusIcon = 'fas fa-exclamation-triangle';
                statusText = 'IP adresleri azalıyor';
            } else {
                statusClass = 'text-info';
                statusIcon = 'fas fa-info-circle';
                statusText = 'Normal kullanım seviyesi';
            }
            
            availableSummaryHTML = `
                <div class="available-summary">
                    <div class="available-count">${analysis.available_count}</div>
                    <div class="available-text">kullanılabilir IP adresi mevcut</div>
                    <div style="font-size: 0.8rem; margin-top: 8px; opacity: 0.9;" class="${statusClass}">
                        <i class="${statusIcon}"></i> ${statusText}
                    </div>
                </div>
            `;
        }
        
        // Kullanım seviyesine göre renk
        let progressColor = '#27ae60';
        if (analysis.usage_percentage > 80) {
            progressColor = '#e74c3c';
        } else if (analysis.usage_percentage > 60) {
            progressColor = '#f39c12';
        }
        
        card.innerHTML = `
            <div class="network-header">
                <div class="network-title">
                    <i class="fas fa-sitemap"></i>
                    ${networkName} Alt Ağı
                </div>
                <div class="network-summary">
                    <div class="summary-item used">
                        <i class="fas fa-circle"></i>
                        ${analysis.used_count} kullanılan
                    </div>
                    <div class="summary-item available">
                        <i class="fas fa-circle"></i>
                        ${analysis.available_count} boş
                    </div>
                </div>
            </div>
            
            <div class="network-progress">
                <div class="progress-bar" style="
                    width: 0%; 
                    background: linear-gradient(90deg, ${progressColor}, ${progressColor}aa);
                    transition: width 1.5s ease-in-out;
                " data-width="${analysis.usage_percentage}%"></div>
            </div>
            <div style="text-align: center; font-size: 0.9rem; color: #666; margin-bottom: 20px;">
                <strong>%${analysis.usage_percentage}</strong> kullanım oranı 
                <span style="font-size: 0.8rem; color: #999;">
                    (${analysis.used_count}/${analysis.total_count})
                </span>
            </div>
            
            ${usedIPsHTML}
            ${availableSummaryHTML}
            
            ${analysis.used_count === 0 && analysis.available_count === 0 ? `
                <div class="empty-network">
                    <i class="fas fa-network-wired"></i>
                    <h4>Bu ağda IP kullanımı bulunamadı</h4>
                    <p>Ağ yapılandırması kontrol edilebilir.</p>
                    <button onclick="scanNetwork('${networkName.replace('.x', '').replace('.', '.')}')" class="btn btn-secondary" style="margin-top: 15px;">
                        <i class="fas fa-search"></i> Ağı Tara
                    </button>
                </div>
            ` : ''}
        `;
        
        // Kartı görünür yapma animasyonu
        setTimeout(() => {
            card.style.transition = 'all 0.6s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
            
            // Progress bar animasyonu
            const progressBar = card.querySelector('.progress-bar');
            if (progressBar) {
                setTimeout(() => {
                    progressBar.style.width = progressBar.dataset.width;
                }, 300);
            }
        }, 100);
        
        return card;
    }
    
    // IP click olaylarını kurulum
    function setupIPClickEvents() {
        // Used IP items için modal
        document.querySelectorAll('.used-ip-item').forEach(item => {
            item.addEventListener('click', function(e) {
                // Copy butonuna tıklandıysa modal açma
                if (e.target.classList.contains('fa-copy')) {
                    return;
                }
                
                const ipAddress = this.querySelector('.ip-address').textContent.trim().split(' ')[0];
                const details = this.querySelector('.ip-details');
                showIPDetailModal(ipAddress, details);
            });
            
            // Hover effects
            item.addEventListener('mouseenter', function() {
                this.style.transform = 'scale(1.02)';
                this.style.boxShadow = '0 8px 25px rgba(0,0,0,0.15)';
                const copyIcon = this.querySelector('.fa-copy');
                if (copyIcon) {
                    copyIcon.style.opacity = '1';
                }
            });
            
            item.addEventListener('mouseleave', function() {
                this.style.transform = 'scale(1)';
                this.style.boxShadow = 'none';
                const copyIcon = this.querySelector('.fa-copy');
                if (copyIcon) {
                    copyIcon.style.opacity = '0.6';
                }
            });
        });
        
        // Tüm IP adreslerine tıklama olayı
        document.querySelectorAll('.ip-address').forEach(ipElement => {
            ipElement.style.cursor = 'pointer';
            
            ipElement.addEventListener('click', function(e) {
                e.stopPropagation();
                
                const ip = this.textContent.trim().split(' ')[0]; // Icon'u kaldır
                navigator.clipboard.writeText(ip).then(() => {
                    showTooltip(this, 'Kopyalandı!');
                    
                    // Kısa süre için yeşil yap
                    const originalColor = this.style.color;
                    this.style.color = '#27ae60';
                    this.style.fontWeight = 'bold';
                    
                    setTimeout(() => {
                        this.style.color = originalColor;
                        this.style.fontWeight = '';
                    }, 1000);
                }).catch(() => {
                    showTooltip(this, 'Kopyalama başarısız!');
                });
            });
        });
    }
    
    // Network card olaylarını kurulum
    function setupNetworkCardEvents() {
        document.querySelectorAll('.network-header').forEach(header => {
            header.style.cursor = 'pointer';
            header.title = 'Daraltmak/genişletmek için tıklayın';
            
            header.addEventListener('click', function() {
                const card = this.closest('.network-card');
                const content = card.querySelector('.used-ips-section');
                
                if (content) {
                    const isHidden = content.style.display === 'none';
                    content.style.display = isHidden ? 'block' : 'none';
                    this.style.opacity = isHidden ? '1' : '0.7';
                    
                    // Icon değiştir
                    const icon = this.querySelector('.network-title i');
                    if (icon) {
                        icon.className = isHidden ? 'fas fa-sitemap' : 'fas fa-eye-slash';
                    }
                }
            });
        });
    }
    
    // Loading gösterge fonksiyonları
    function showLoadingIndicator() {
        let indicator = document.getElementById('loading-indicator');
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.id = 'loading-indicator';
            indicator.className = 'update-indicator loading';
            indicator.innerHTML = '<i class="fas fa-sync fa-spin"></i> Güncelleniyor...';
            document.body.appendChild(indicator);
        }
        indicator.style.display = 'flex';
    }
    
    function hideLoadingIndicator() {
        const indicator = document.getElementById('loading-indicator');
        if (indicator) {
            indicator.style.display = 'none';
        }
    }
    
    function showSuccessIndicator() {
        showStatusIndicator('<i class="fas fa-check"></i> Başarıyla güncellendi', 'success');
    }
    
    function showErrorIndicator(message) {
        showStatusIndicator(`<i class="fas fa-exclamation-triangle"></i> Hata: ${message}`, 'error');
    }
    
    function showStatusIndicator(message, type) {
        let indicator = document.getElementById('status-indicator');
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.id = 'status-indicator';
            indicator.className = 'update-indicator';
            document.body.appendChild(indicator);
        }
        
        indicator.innerHTML = message;
        indicator.className = `update-indicator ${type}`;
        indicator.style.display = 'flex';
        
        setTimeout(() => {
            indicator.style.display = 'none';
        }, 3000);
    }
    
    // Tooltip göster
    function showTooltip(element, message) {
        // Varolan tooltip'i kaldır
        const existingTooltip = element.querySelector('.tooltip');
        if (existingTooltip) {
            existingTooltip.remove();
        }
        
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = message;
        tooltip.style.cssText = `
            position: absolute;
            background: #2c3e50;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            z-index: 1000;
            pointer-events: none;
            top: -40px;
            left: 50%;
            transform: translateX(-50%);
            white-space: nowrap;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            opacity: 0;
            transition: opacity 0.3s ease;
        `;
        
        // Tooltip konumunu ayarla
        element.style.position = 'relative';
        element.appendChild(tooltip);
        
        // Animasyon
        setTimeout(() => {
            tooltip.style.opacity = '1';
        }, 10);
        
        setTimeout(() => {
            if (tooltip.parentNode) {
                tooltip.style.opacity = '0';
                setTimeout(() => {
                    tooltip.remove();
                }, 300);
            }
        }, 2000);
    }
    
    // Son güncelleme zamanını göster
    function updateLastRefreshTime() {
        let timeElement = document.getElementById('last-refresh-time');
        if (!timeElement) {
            timeElement = document.createElement('div');
            timeElement.id = 'last-refresh-time';
            timeElement.style.cssText = `
                position: fixed;
                bottom: 25px;
                right: 25px;
                background: rgba(44, 62, 80, 0.9);
                color: white;
                padding: 8px 15px;
                border-radius: 20px;
                font-size: 0.8rem;
                z-index: 1000;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                backdrop-filter: blur(10px);
            `;
            document.body.appendChild(timeElement);
        }
        
        const now = new Date();
        timeElement.innerHTML = `<i class="fas fa-clock"></i> Son güncelleme: ${now.toLocaleTimeString()}`;
        
        setTimeout(() => {
            if (timeElement.parentNode) {
                timeElement.style.opacity = '0';
                setTimeout(() => {
                    timeElement.remove();
                }, 300);
            }
        }, 5000);
    }
    
    // Otomatik yenileme başlat
    function startAutoRefresh() {
        if (refreshInterval) {
            clearInterval(refreshInterval);
        }
        
        refreshInterval = setInterval(() => {
            if (!isSearching && document.hidden === false) {
                fetchIPMonitorData();
            }
        }, 15000); // 15 saniyede bir güncelle
        
        console.log('Auto refresh started - every 15 seconds');
    }
    
    // IP Detail Modal
    function showIPDetailModal(ip, detailsElement) {
        // Varolan modal'ı kaldır
        const existingModal = document.querySelector('.ip-detail-modal');
        if (existingModal) {
            existingModal.remove();
        }
        
        const modal = document.createElement('div');
        modal.className = 'ip-detail-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.6);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            backdrop-filter: blur(8px);
            opacity: 0;
            transition: opacity 0.3s ease;
        `;
        
        const content = document.createElement('div');
        content.style.cssText = `
            background: white;
            padding: 35px;
            border-radius: 20px;
            max-width: 550px;
            width: 90%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            transform: scale(0.8);
            transition: transform 0.3s ease;
            max-height: 80vh;
            overflow-y: auto;
        `;
        
        const ipDetails = detailsElement.querySelectorAll('.ip-detail');
        let detailsHTML = '';
        
        ipDetails.forEach(detail => {
            const label = detail.querySelector('.detail-label').textContent;
            const valueElement = detail.querySelector('.detail-value');
            const value = valueElement.textContent;
            
            detailsHTML += `
                <div style="margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 10px; border-left: 4px solid #667eea;">
                    <div style="font-weight: 600; color: #495057; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; font-size: 0.85rem;">
                        ${label}
                    </div>
                    <div style="font-family: 'Consolas', 'Monaco', 'Courier New', monospace; color: #2c3e50; font-size: 1.1rem; font-weight: 500;">
                        ${value === '-' ? '<em style="color: #6c757d;">Bilgi yok</em>' : value}
                    </div>
                </div>
            `;
        });
        
        content.innerHTML = `
            <div style="text-align: center; margin-bottom: 30px;">
                <div style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 15px; border-radius: 15px; margin-bottom: 15px;">
                    <h2 style="margin: 0; font-size: 1.8rem; font-weight: 700;">${ip}</h2>
                    <div style="font-size: 0.9rem; opacity: 0.9; margin-top: 5px;">IP Adres Detayları</div>
                </div>
            </div>
            <div style="margin-bottom: 30px;">
                ${detailsHTML}
            </div>
            <div style="text-align: center; display: flex; gap: 15px; justify-content: center;">
                <button onclick="navigator.clipboard.writeText('${ip}').then(() => alert('IP adresi kopyalandı!'))" style="
                    background: #28a745;
                    color: white;
                    border: none;
                    padding: 12px 20px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-size: 1rem;
                    font-weight: 600;
                    transition: all 0.3s ease;
                " onmouseover="this.style.background='#218838'" onmouseout="this.style.background='#28a745'">
                    <i class="fas fa-copy"></i> IP'yi Kopyala
                </button>
                <button onclick="this.closest('.ip-detail-modal').remove()" style="
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 12px 20px;
                    border-radius: 10px;
                    cursor: pointer;
                    font-size: 1rem;
                    font-weight: 600;
                    transition: all 0.3s ease;
                " onmouseover="this.style.background='#5a67d8'" onmouseout="this.style.background='#667eea'">
                    <i class="fas fa-times"></i> Kapat
                </button>
            </div>
        `;
        
        modal.appendChild(content);
        document.body.appendChild(modal);
        
        // Animasyonlar
        setTimeout(() => {
            modal.style.opacity = '1';
            content.style.transform = 'scale(1)';
        }, 10);
        
        // Close events
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                modal.remove();
            }
        });
        
        // ESC ile kapatma
        const escHandler = function(e) {
            if (e.key === 'Escape') {
                modal.remove();
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    }
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // F5 veya Ctrl+R for manual refresh
        if (e.key === 'F5' || (e.ctrlKey && e.key === 'r')) {
            e.preventDefault();
            fetchIPMonitorData();
        }
        
        // Ctrl+F for search focus
        if (e.ctrlKey && e.key === 'f') {
            e.preventDefault();
            const searchInput = document.querySelector('input[type="text"]');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
    });
    
    // Global fonksiyon tanımlamaları
    window.fetchIPMonitorData = fetchIPMonitorData;
    
    // Manual refresh event listener
    document.addEventListener('manualRefresh', fetchIPMonitorData);
    
    // Sayfa görünürlük kontrolü
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            clearInterval(refreshInterval);
            console.log('Page hidden - stopping auto refresh');
        } else {
            startAutoRefresh();
            console.log('Page visible - starting auto refresh');
            // Sayfa geri geldiğinde hemen güncelle
            setTimeout(fetchIPMonitorData, 1000);
        }
    });
    
    // Connection monitoring
    window.addEventListener('online', () => {
        showStatusIndicator('<i class="fas fa-wifi"></i> İnternet bağlantısı geri geldi', 'success');
        setTimeout(fetchIPMonitorData, 2000);
    });
    
    window.addEventListener('offline', () => {
        showStatusIndicator('<i class="fas fa-wifi-slash"></i> İnternet bağlantısı kesildi', 'error');
        clearInterval(refreshInterval);
    });
    
    // Initialize
    console.log('Initializing IP Monitor...');
    
    setupTableSearch('dhcpSearch', 'dhcpTable');
    setupTableSearch('arpSearch', 'arpTable');
    setupIPClickEvents();
    setupNetworkCardEvents();
    
    // İlk veri yüklemesi
    fetchIPMonitorData();
    
    // Otomatik yenileme başlat
    startAutoRefresh();
    
    console.log('IP Monitor initialized successfully - AJAX updates every 15 seconds');
});

// Global network scan function
async function scanNetwork(network) {
    const statusElement = document.getElementById('scan-status');
    const resultsElement = document.getElementById('scan-results');
    const resultsContent = document.getElementById('scan-results-content');
    
    if (!statusElement) {
        console.error('Scan status element not found');
        return;
    }
    
    statusElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ağ taranıyor... Bu işlem 30-60 saniye sürebilir.';
    
    try {
        const response = await fetch(`/api/ping_network/${network}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            statusElement.innerHTML = `<i class="fas fa-check" style="color: #28a745;"></i> ${network}.x ağında <strong>${data.count} aktif IP</strong> bulundu`;
            
            if (resultsContent && data.active_ips.length > 0) {
                resultsContent.innerHTML = `
                    <div style="background: linear-gradient(135deg, #e8f5e8, #d4edda); padding: 20px; border-radius: 15px; border-left: 5px solid #27ae60;">
                        <div style="display: flex; align-items: center; margin-bottom: 15px;">
                            <i class="fas fa-search" style="color: #27ae60; margin-right: 10px; font-size: 1.2rem;"></i>
                            <strong style="color: #2c3e50;">Bulunan Aktif IP'ler (${data.count} adet):</strong>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px;">
                            ${data.active_ips.map(ip => `
                                <span style="
                                    font-family: 'Consolas', monospace; 
                                    background: white; 
                                    padding: 8px 12px; 
                                    border-radius: 8px; 
                                    display: inline-block;
                                    border: 1px solid #dee2e6;
                                    cursor: pointer;
                                    transition: all 0.2s ease;
                                    font-weight: 600;
                                    color: #2c3e50;
                                    text-align: center;
                                " onclick="navigator.clipboard.writeText('${ip}').then(() => {
                                    this.style.background='#28a745';
                                    this.style.color='white';
                                    this.innerHTML='✓ Kopyalandı';
                                    setTimeout(() => {
                                        this.style.background='white';
                                        this.style.color='#2c3e50';
                                        this.innerHTML='${ip}';
                                    }, 1500);
                                })" 
                                onmouseover="this.style.background='#f8f9fa'; this.style.borderColor='#667eea';"
                                onmouseout="this.style.background='white'; this.style.borderColor='#dee2e6';"
                                title="Kopyalamak için tıklayın">
                                    ${ip}
                                </span>
                            `).join('')}
                        </div>
                        <div style="margin-top: 15px; font-size: 0.9rem; color: #6c757d; text-align: center;">
                            <i class="fas fa-info-circle"></i> IP adreslerini kopyalamak için tıklayın
                        </div>
                    </div>
                `;
                
                if (resultsElement) {
                    resultsElement.style.display = 'block';
                    resultsElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
            } else if (resultsContent) {
                resultsContent.innerHTML = `
                    <div style="background: #fff3cd; padding: 20px; border-radius: 15px; border-left: 5px solid #ffc107; text-align: center;">
                        <i class="fas fa-exclamation-triangle" style="color: #856404; font-size: 2rem; margin-bottom: 10px;"></i>
                        <div style="color: #856404; font-weight: 600;">Bu ağda aktif IP bulunamadı</div>
                        <div style="color: #6c757d; font-size: 0.9rem; margin-top: 5px;">Ağ yapılandırması kontrol edilebilir</div>
                    </div>
                `;
                if (resultsElement) {
                    resultsElement.style.display = 'block';
                }
            }
            
            // 20 saniye sonra sonuçları gizle
            setTimeout(() => {
                if (resultsElement) {
                    resultsElement.style.display = 'none';
                }
            }, 20000);
            
        } else {
            statusElement.innerHTML = `<i class="fas fa-times" style="color: #dc3545;"></i> Tarama hatası: ${data.error}`;
        }
    } catch (error) {
        statusElement.innerHTML = `<i class="fas fa-times" style="color: #dc3545;"></i> Ağ tarama hatası: ${error.message}`;
        console.error('Network scan error:', error);
    }
    
    // 10 saniye sonra status'u sıfırla
    setTimeout(() => {
        statusElement.innerHTML = '<i class="fas fa-info-circle"></i> Tarama bekleniyor...';
    }, 10000);
}


