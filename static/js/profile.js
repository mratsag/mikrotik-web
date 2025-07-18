// Profile Page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    
    // Session time counter
    let sessionStart = new Date();
    
    function updateSessionTime() {
        const sessionTimeElement = document.getElementById('sessionTime');
        if (sessionTimeElement) {
            const now = new Date();
            const diff = Math.floor((now - sessionStart) / 1000);
            const hours = Math.floor(diff / 3600);
            const minutes = Math.floor((diff % 3600) / 60);
            const seconds = diff % 60;
            
            sessionTimeElement.textContent = 
                `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
    }
    
    // Update session time every second
    setInterval(updateSessionTime, 1000);
    updateSessionTime();
    
    // Auto-refresh system info every 30 seconds
    setInterval(() => {
        // Only reload if user is not actively interacting
        if (document.hidden === false) {
            location.reload();
        }
    }, 30000);
    
    // Animate statistics cards on load
    const activityCards = document.querySelectorAll('.activity-card');
    activityCards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
    
    // Info items animation
    const infoItems = document.querySelectorAll('.info-item');
    infoItems.forEach((item, index) => {
        item.style.opacity = '0';
        item.style.transform = 'translateX(-20px)';
        
        setTimeout(() => {
            item.style.transition = 'all 0.4s ease';
            item.style.opacity = '1';
            item.style.transform = 'translateX(0)';
        }, index * 50);
    });
    
    // Connection status ping test (optional)
    function pingMikroTik() {
        const connectionStatus = document.querySelector('.connection-info');
        if (connectionStatus) {
            // Visual ping indicator
            connectionStatus.style.animation = 'pulse 1s ease-in-out';
            
            setTimeout(() => {
                connectionStatus.style.animation = '';
            }, 1000);
        }
    }
    
    // Ping every 10 seconds
    setInterval(pingMikroTik, 10000);
    
    // Format memory values
    const memoryElements = document.querySelectorAll('.info-value');
    memoryElements.forEach(element => {
        const text = element.textContent.trim();
        if (text.includes('MB') && !isNaN(text.replace(' MB', ''))) {
            const mb = parseInt(text.replace(' MB', ''));
            if (mb > 1024) {
                element.textContent = `${(mb / 1024).toFixed(1)} GB`;
            }
        }
    });
    
    // Copy to clipboard functionality
    document.querySelectorAll('.info-value').forEach(element => {
        element.addEventListener('click', function() {
            const text = this.textContent.trim();
            if (text && text !== 'Bilinmiyor') {
                navigator.clipboard.writeText(text).then(() => {
                    // Show tooltip
                    const tooltip = document.createElement('div');
                    tooltip.textContent = 'Kopyalandı!';
                    tooltip.style.cssText = `
                        position: absolute;
                        background: #333;
                        color: white;
                        padding: 5px 10px;
                        border-radius: 4px;
                        font-size: 0.8rem;
                        z-index: 1000;
                        pointer-events: none;
                    `;
                    
                    this.style.position = 'relative';
                    this.appendChild(tooltip);
                    
                    setTimeout(() => {
                        tooltip.remove();
                    }, 2000);
                });
            }
        });
        
        // Add cursor pointer for clickable elements
        element.style.cursor = 'pointer';
        element.title = 'Kopyalamak için tıklayın';
    });
});