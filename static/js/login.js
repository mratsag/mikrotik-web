// Login Page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    
    // Form submit animation
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function() {
            const button = document.getElementById('loginButton');
            const normalText = button.querySelector('.normal-text');
            const loadingText = button.querySelector('.loading');
            
            if (normalText && loadingText) {
                normalText.style.display = 'none';
                loadingText.style.display = 'inline-flex';
                button.disabled = true;
            }
        });
    }

    // Input focus animations
    document.querySelectorAll('.form-input').forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.style.transform = 'scale(1.02)';
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.style.transform = 'scale(1)';
        });
    });

    // Enter key to submit form
    document.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const form = document.getElementById('loginForm');
            if (form) {
                form.submit();
            }
        }
    });

    // IP address format validation
    const mikrotikHostInput = document.getElementById('mikrotik_host');
    if (mikrotikHostInput) {
        mikrotikHostInput.addEventListener('input', function() {
            const value = this.value;
            const isValidIP = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(value);
            
            if (value && !isValidIP) {
                this.style.borderColor = '#ff6b6b';
                this.style.backgroundColor = '#ffe6e6';
                
                // Show error message
                let errorMsg = this.parentElement.querySelector('.error-message');
                if (!errorMsg) {
                    errorMsg = document.createElement('div');
                    errorMsg.className = 'error-message';
                    errorMsg.style.cssText = `
                        color: #ff6b6b;
                        font-size: 0.8rem;
                        margin-top: 5px;
                        display: flex;
                        align-items: center;
                        gap: 5px;
                    `;
                    errorMsg.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Geçerli bir IP adresi girin';
                    this.parentElement.appendChild(errorMsg);
                }
            } else {
                this.style.borderColor = value ? '#28a745' : '#e1e5e9';
                this.style.backgroundColor = value ? '#e8f5e8' : '#f8f9fa';
                
                // Remove error message
                const errorMsg = this.parentElement.querySelector('.error-message');
                if (errorMsg) {
                    errorMsg.remove();
                }
            }
        });
    }
    
    // Auto-fill demo credentials (for testing)
    const demoCredentials = document.querySelector('.demo-credentials');
    if (demoCredentials) {
        demoCredentials.addEventListener('click', function() {
            const usernameInput = document.getElementById('username');
            const hostInput = document.getElementById('mikrotik_host');
            
            if (usernameInput && !usernameInput.value) {
                usernameInput.value = 'admin';
                usernameInput.dispatchEvent(new Event('input'));
            }
            
            if (hostInput && !hostInput.value) {
                hostInput.value = '192.168.254.142';
                hostInput.dispatchEvent(new Event('input'));
            }
        });
    }
    
    // Password visibility toggle
    function addPasswordToggle() {
        const passwordInput = document.getElementById('password');
        if (!passwordInput) return;
        
        const toggleButton = document.createElement('button');
        toggleButton.type = 'button';
        toggleButton.innerHTML = '<i class="fas fa-eye"></i>';
        toggleButton.style.cssText = `
            position: absolute;
            right: 50px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #999;
            cursor: pointer;
            padding: 5px;
            z-index: 1;
        `;
        
        toggleButton.addEventListener('click', function() {
            const icon = this.querySelector('i');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                passwordInput.type = 'password';
                icon.className = 'fas fa-eye';
            }
        });
        
        passwordInput.parentElement.style.position = 'relative';
        passwordInput.parentElement.appendChild(toggleButton);
    }
    
    addPasswordToggle();
    
    // Remember last successful IP
    const hostInput = document.getElementById('mikrotik_host');
    if (hostInput) {
        // Load saved IP
        const savedIP = localStorage.getItem('lastMikrotikIP');
        if (savedIP && !hostInput.value) {
            hostInput.value = savedIP;
        }
        
        // Save IP on change
        hostInput.addEventListener('change', function() {
            if (this.value && /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(this.value)) {
                localStorage.setItem('lastMikrotikIP', this.value);
            }
        });
    }
    
    // Connection test button (optional)
    function addTestConnectionButton() {
        const hostInput = document.getElementById('mikrotik_host');
        if (!hostInput) return;
        
        const testButton = document.createElement('button');
        testButton.type = 'button';
        testButton.innerHTML = '<i class="fas fa-network-wired"></i>';
        testButton.title = 'Bağlantıyı test et';
        testButton.style.cssText = `
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: #667eea;
            color: white;
            border: none;
            padding: 8px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
        `;
        
        testButton.addEventListener('click', function() {
            const ip = hostInput.value;
            if (!ip) {
                alert('Lütfen IP adresi girin');
                return;
            }
            
            // Simple ping test (this is just visual feedback)
            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
            this.disabled = true;
            
            setTimeout(() => {
                this.innerHTML = '<i class="fas fa-check"></i>';
                this.style.background = '#28a745';
                
                setTimeout(() => {
                    this.innerHTML = '<i class="fas fa-network-wired"></i>';
                    this.style.background = '#667eea';
                    this.disabled = false;
                }, 2000);
            }, 1500);
        });
        
        hostInput.parentElement.style.position = 'relative';
        hostInput.parentElement.appendChild(testButton);
    }
    
    // addTestConnectionButton(); // Uncomment to enable
    
    // Particle animation enhancement
    function enhanceParticles() {
        const particles = document.querySelectorAll('.particle');
        particles.forEach(particle => {
            // Random size and opacity
            const size = Math.random() * 4 + 2;
            particle.style.width = size + 'px';
            particle.style.height = size + 'px';
            particle.style.opacity = Math.random() * 0.5 + 0.1;
            
            // Random horizontal position
            particle.style.left = Math.random() * 100 + '%';
        });
    }
    
    enhanceParticles();
    
    // Focus first empty input
    const inputs = document.querySelectorAll('.form-input');
    for (let input of inputs) {
        if (!input.value) {
            input.focus();
            break;
        }
    }
});