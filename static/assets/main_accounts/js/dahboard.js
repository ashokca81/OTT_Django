
    document.addEventListener('DOMContentLoaded', function() {
        // Dark Mode Toggle
        const darkModeToggle = document.getElementById('darkModeToggle');
        const body = document.body;
        
        // Check for saved dark mode preference
        if (localStorage.getItem('darkMode') === 'enabled') {
            body.classList.add('dark');
            darkModeToggle.querySelector('i').classList.replace('fa-moon', 'fa-sun');
        }
        
        // Toggle dark mode
        darkModeToggle.addEventListener('click', () => {
            body.classList.toggle('dark');
            const icon = darkModeToggle.querySelector('i');
            
            if (body.classList.contains('dark')) {
                icon.classList.replace('fa-moon', 'fa-sun');
                localStorage.setItem('darkMode', 'enabled');
            } else {
                icon.classList.replace('fa-sun', 'fa-moon');
                localStorage.setItem('darkMode', 'disabled');
            }
        });

        // Full Screen Toggle
        const fullscreenToggle = document.getElementById('fullscreenToggle');
        const fullscreenIcon = fullscreenToggle.querySelector('i');

        fullscreenToggle.addEventListener('click', () => {
            if (!document.fullscreenElement) {
                document.documentElement.requestFullscreen().catch(err => {
                    console.log(`Error attempting to enable full-screen mode: ${err.message}`);
                });
                fullscreenIcon.classList.replace('fa-expand', 'fa-compress');
            } else {
                if (document.exitFullscreen) {
                    document.exitFullscreen();
                    fullscreenIcon.classList.replace('fa-compress', 'fa-expand');
                }
            }
        });

        // Listen for fullscreen change
        document.addEventListener('fullscreenchange', () => {
            if (!document.fullscreenElement) {
                fullscreenIcon.classList.replace('fa-compress', 'fa-expand');
            }
        });

        // Sidebar Toggle
        const toggleSidebarBtn = document.getElementById('toggleSidebarBtn');
        const closeSidebarBtn = document.getElementById('closeSidebarBtn');
        const sidebar = document.querySelector('.sidebar');
        const sidebarOverlay = document.getElementById('sidebarOverlay');
        const mainContent = document.querySelector('.main-content');
        const menuIcon = toggleSidebarBtn.querySelector('i');

        function toggleSidebar() {
            if (window.innerWidth <= 768) {
                // Mobile behavior
                sidebar.classList.add('active');
                sidebarOverlay.classList.add('active');
                document.body.style.overflow = 'hidden';
            } else {
                // Desktop behavior
                sidebar.classList.toggle('desktop-collapsed');
                mainContent.classList.toggle('expanded');
                menuIcon.classList.toggle('fa-bars');
                menuIcon.classList.toggle('fa-chevron-right');
            }
        }

        function closeSidebar() {
            if (window.innerWidth <= 768) {
                // Mobile behavior
                sidebar.classList.remove('active');
                sidebarOverlay.classList.remove('active');
                document.body.style.overflow = '';
            }
        }

        // Toggle sidebar on menu button click
        toggleSidebarBtn.addEventListener('click', toggleSidebar);

        // Close sidebar when clicking close button (mobile only)
        closeSidebarBtn.addEventListener('click', closeSidebar);

        // Close sidebar when clicking overlay (mobile only)
        sidebarOverlay.addEventListener('click', closeSidebar);

        // Close sidebar on escape key (mobile only)
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && window.innerWidth <= 768 && sidebar.classList.contains('active')) {
                closeSidebar();
            }
        });

        // Handle resize events
        let lastWidth = window.innerWidth;
        window.addEventListener('resize', () => {
            const currentWidth = window.innerWidth;
            const breakpoint = 768;

            // Check if we're crossing the breakpoint
            if ((lastWidth <= breakpoint && currentWidth > breakpoint) || 
                (lastWidth > breakpoint && currentWidth <= breakpoint)) {
                // Reset all states
                sidebar.classList.remove('active', 'desktop-collapsed');
                mainContent.classList.remove('expanded');
                sidebarOverlay.classList.remove('active');
                document.body.style.overflow = '';
                menuIcon.classList.remove('fa-chevron-right');
                menuIcon.classList.add('fa-bars');
            }

            lastWidth = currentWidth;
        });
    });

