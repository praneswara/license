// Auto-refresh dashboard every 30 seconds
if (window.location.pathname === '/') {
    setInterval(() => {
        // Only refresh if user is on dashboard
        if (document.hasFocus()) {
            location.reload();
        }
    }, 30000);
}

// Add loading states to buttons
document.addEventListener('DOMContentLoaded', function() {
    const refreshButtons = document.querySelectorAll('.btn-refresh');
    refreshButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            this.textContent = '⏳ Refreshing...';
            this.disabled = true;
        });
    });
});

