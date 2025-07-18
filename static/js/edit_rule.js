// Edit Rule Page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    
    // Form submit loading animation
    const editForm = document.getElementById('editForm');
    if (editForm) {
        editForm.addEventListener('submit', function() {
            const loadingElement = document.getElementById('loading');
            const formActions = document.querySelector('.form-actions');
            
            if (loadingElement) {
                loadingElement.style.display = 'block';
            }
            if (formActions) {
                formActions.style.display = 'none';
            }
        });
    }

    // Form validation - input border color change
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('input', function() {
            if (this.value.trim() !== '') {
                this.style.borderColor = '#28a745';
            } else {
                this.style.borderColor = '#e1e5e9';
            }
        });
    });

    // Input focus animations
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('focus', function() {
            this.style.transform = 'translateY(-1px)';
        });
        
        input.addEventListener('blur', function() {
            this.style.transform = 'translateY(0)';
        });
    });

    // Auto-save form data to localStorage (optional)
    function saveFormData() {
        const formData = {};
        document.querySelectorAll('input').forEach(input => {
            if (input.name && input.type !== 'hidden') {
                formData[input.name] = input.value;
            }
        });
        localStorage.setItem('editRuleFormData', JSON.stringify(formData));
    }

    // Load saved form data (optional)
    function loadFormData() {
        const savedData = localStorage.getItem('editRuleFormData');
        if (savedData) {
            const formData = JSON.parse(savedData);
            Object.keys(formData).forEach(key => {
                const input = document.querySelector(`input[name="${key}"]`);
                if (input && input.value === '') {
                    input.value = formData[key];
                }
            });
        }
    }

    // Save form data on input change
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('input', saveFormData);
    });

    // Clear saved data on successful submit
    if (editForm) {
        editForm.addEventListener('submit', function() {
            setTimeout(() => {
                localStorage.removeItem('editRuleFormData');
            }, 1000);
        });
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl+S to save
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            if (editForm) {
                editForm.submit();
            }
        }
        
        // Escape to cancel
        if (e.key === 'Escape') {
            const cancelButton = document.querySelector('a[href="/"]');
            if (cancelButton) {
                window.location.href = cancelButton.href;
            }
        }
    });

    // Confirmation before leaving with unsaved changes
    let formChanged = false;
    document.querySelectorAll('input').forEach(input => {
        const originalValue = input.value;
        input.addEventListener('input', function() {
            formChanged = (this.value !== originalValue);
        });
    });

    window.addEventListener('beforeunload', function(e) {
        if (formChanged) {
            e.preventDefault();
            e.returnValue = 'Kaydedilmemiş değişiklikleriniz var. Sayfadan çıkmak istediğinizden emin misiniz?';
        }
    });

    // Reset form changed flag on submit
    if (editForm) {
        editForm.addEventListener('submit', function() {
            formChanged = false;
        });
    }
});