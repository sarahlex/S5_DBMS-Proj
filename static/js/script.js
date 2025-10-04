// Basic functionality without complex features
document.addEventListener('DOMContentLoaded', function() {
    console.log('Eventify loaded successfully');
    
    // Auto-hide flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert && alert.classList.contains('alert')) {
                alert.style.display = 'none';
            }
        }, 5000);
    });

    // Basic form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Processing...';
            }
        });
    });

    // Prevent past dates in event creation
    const eventDateInput = document.getElementById('event_date');
    if (eventDateInput) {
        const today = new Date().toISOString().split('T')[0];
        eventDateInput.min = today;
    }
});