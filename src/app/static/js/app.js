// Disable transitions initially to prevent flash
document.documentElement.classList.add('no-transitions');

function showPage() {
    const $app = $('.app');
    const $loading = $('#loading-overlay');
    
    // First, mark the app as loaded to make it visible and styled
    $app.addClass('loaded');
    
    // Slight delay before hiding the loading overlay to ensure smooth transition
    setTimeout(() => {
        $loading.addClass('hidden');
        // Remove the overlay after transition completes
        setTimeout(() => $loading.remove(), 500);
        
        // Re-enable transitions after a delay
        setTimeout(() => {
            document.documentElement.classList.remove('no-transitions');
        }, 50);
    }, 200);
    
    const preloadTheme = document.documentElement.getAttribute('data-theme-preload');
    if (preloadTheme === 'dark') {
        $('body').attr('data-theme', 'dark');
        document.documentElement.removeAttribute('data-theme-preload');
    }
}

function initSideNav() {
    const $sidenav = $('#sidenav');
    const $navIcon = $('.nav-icon');
    let isAnimating = false;

    $navIcon.on('click', function (e) {
        e.preventDefault();
        if (isAnimating) return;
        
        isAnimating = true;
        $sidenav.toggleClass('sidenav-open sidenav-hidden');
        
        setTimeout(() => {
            isAnimating = false;
        }, 300);
        
        return false;
    });

    $('#menu-overlay').on('click', function () {
        if (isAnimating) return;
        isAnimating = true;
        
        $sidenav.removeClass('sidenav-open').addClass('sidenav-hidden');
        
        setTimeout(() => {
            isAnimating = false;
        }, 300);
    });

    $(document).on('click', function (e) {
        if (window.innerWidth <= 768 && 
            !$(e.target).closest('#sidenav .wrapper').length && 
            !$(e.target).closest('.nav-icon').length && 
            $sidenav.hasClass('sidenav-open')) {
            $sidenav.removeClass('sidenav-open').addClass('sidenav-hidden');
        }
    });

    let resizeTimer;
    $(window).on('resize', function() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            if (window.innerWidth > 768) {
                $sidenav.removeClass('sidenav-open sidenav-hidden');
            }
        }, 250);
    });

    $('#sidenav .menu > ul > li > a').on('click', function (e) {
        const submenu = $(this).next('ul');
        if (submenu.length && window.innerWidth <= 768) {
            e.preventDefault();
            $(this).parent().toggleClass('active');
            return false;
        }
    });
}

// Initialize app when document is ready
$(document).ready(function () {
    // Update loading text when DOM is ready
    document.querySelector('.loading-text').textContent = 'Loading resources...';
    
    // Load settings and initialize theme
    loadUISettings();
    const themeUpdated = localStorage.getItem('theme_updated');
    if (themeUpdated) {
        localStorage.removeItem('theme_updated');
        setTimeout(loadUISettings, 100);
    }
    
    const savedTheme = localStorage.getItem('theme');
    setTheme(savedTheme || getSystemThemePreference());
    
    // Theme toggle handler
    $('#theme-switch').on('click', function () {
        const currentTheme = $('body').attr('data-theme') === 'dark' ? 'dark' : 'light';
        setTheme(currentTheme === 'dark' ? 'light' : 'dark');
        return false;
    });
    
    // Initialize sidenav
    initSideNav();
    
    // Theme system change listener
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
            if (!localStorage.getItem('theme')) {
                setTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
    
    // When everything is loaded
    $(window).on('load', function() {
        try {
            $('.menu').niceScroll({
                cursorcolor: 'var(--light-text)',
                cursorwidth: '6px',
                cursorborder: 'none',
                background: 'rgba(0,0,0,0.1)',
                zindex: 1000,
                touchbehavior: true
            });
        } catch (e) {
            console.warn("NiceScroll initialization failed:", e);
        }
        
        // Only show page after everything is loaded
        showPage();
    });
    
    // Fallback in case window.load doesn't fire properly or takes too long
    setTimeout(() => {
        if ($('#loading-overlay').length && !$('#loading-overlay').hasClass('hidden')) {
            console.log("Fallback page show triggered after timeout");
            showPage();
        }
    }, 5000);
});
