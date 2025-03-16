function getSystemThemePreference() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function setTheme(theme) {
    const body = $('body');
    const themeSwitch = $('#theme-switch');
    if (theme === 'dark') {
        body.attr('data-theme', 'dark');
        themeSwitch.html('<i class="fas fa-sun"></i> Toggle Theme');
    } else {
        body.removeAttr('data-theme');
        themeSwitch.html('<i class="fas fa-moon"></i> Toggle Theme');
    }
    localStorage.setItem('theme', theme);
    setTimeout(applyThemeVariables, 100);
}

function applyThemeVariables() {
    fetch('/settings/api/ui-settings')
        .then(response => response.json())
        .then(settings => {
            const isDark = document.body.getAttribute('data-theme') === 'dark';
            const theme = isDark ? settings.dark : settings.light;
            const root = document.documentElement;
            for (const [key, value] of Object.entries(theme)) {
                root.style.setProperty(`--${key}`, value);
            }
        })
        .catch(error => console.error('Failed to apply theme variables:', error));
}

function loadUISettings() {
    const cacheBuster = new Date().getTime();
    fetch(`/settings/api/ui-settings?_=${cacheBuster}`)
        .then(response => response.json())
        .then(settings => {
            let cssRules = ":root {\n";
            for (const [key, value] of Object.entries(settings.light)) {
                cssRules += `  --${key}: ${value} !important;\n`;
            }
            cssRules += "}\n\n[data-theme=\"dark\"], [data-theme-preload=\"dark\"] {\n";
            for (const [key, value] of Object.entries(settings.dark)) {
                cssRules += `  --${key}: ${value} !important;\n`;
            }
            cssRules += "}\n";
            document.getElementById('dynamic-theme-styles').innerHTML = cssRules;
            
            if (settings.general) {
                if (settings.general['app-name']) {
                    $('#app-name').text(settings.general['app-name']);
                    document.title = document.title.replace(/^.*? - /, settings.general['app-name'] + ' - ');
                }
                if (settings.general['app-favicon-url'] && settings.general['app-favicon-url'].trim()) {
                    $('#dynamic-favicon').attr('href', settings.general['app-favicon-url']);
                }
                if (settings.general['app-logo-url'] && settings.general['app-logo-url'].trim()) {
                    const logoContainer = $('#sidenav .logo a#app-name');
                    let logoImg = logoContainer.find('img');
                    if (!logoImg.length) {
                        const originalText = logoContainer.text();
                        logoContainer.html(`<img alt="${originalText}" class="app-logo">`);
                        logoImg = logoContainer.find('img');
                        const style = document.createElement('style');
                        style.textContent = `#sidenav .logo a img.app-logo { height: 24px; max-width: 160px; object-fit: contain; }`;
                        document.head.appendChild(style);
                    }
                    logoImg.attr('src', settings.general['app-logo-url']);
                } else {
                    const logoContainer = $('#sidenav .logo a#app-name');
                    if (logoContainer.find('img').length) {
                        logoContainer.text(settings.general['app-name'] || 'Dashboard');
                    }
                }
            }
            applyThemeVariables();
        })
        .catch(error => console.error("Failed to load UI settings:", error));
}

// Setup theme switcher on DOM load
document.addEventListener('DOMContentLoaded', function() {
    // Pre-load theme detection
    (function() {
        function getSystemTheme() {
            return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }
        const savedTheme = localStorage.getItem('theme');
        const theme = savedTheme || getSystemTheme();
        if (theme === 'dark') {
            document.documentElement.setAttribute('data-theme-preload', 'dark');
        }
    })();
});
