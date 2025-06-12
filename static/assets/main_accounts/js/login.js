// Wait for the page to load
document.addEventListener('DOMContentLoaded', function() {
    // Get all elements we need
    const passwordField = document.getElementById('password');
    const eyeIcon = document.getElementById('togglePassword');
    const loginForm = document.getElementById('loginForm');
    const emailField = document.getElementById('email');
    const emailError = document.getElementById('emailError');
    const passwordError = document.getElementById('passwordError');

    // Password show/hide function
    eyeIcon.onclick = function() {
        if(passwordField.type === 'password') {
            passwordField.type = 'text';
            eyeIcon.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            passwordField.type = 'password';
            eyeIcon.innerHTML = '<i class="fas fa-eye"></i>';
        }
    }

    // Show error message function
    function showError(element, message) {
        element.querySelector('span').textContent = message;
        element.style.display = 'flex';
    }

    // Hide error message function
    function hideError(element) {
        element.querySelector('span').textContent = '';
        element.style.display = 'none';
    }

    // Check if email is valid
    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    // Check if password is valid (at least 6 characters)
    function isValidPassword(password) {
        return password.length >= 6;
    }

    // When typing in email field
    emailField.addEventListener('input', function() {
        if(!isValidEmail(this.value)) {
            showError(emailError, 'Please enter a valid email');
        } else {
            hideError(emailError);
        }
    });

    // When typing in password field
    passwordField.addEventListener('input', function() {
        if(!isValidPassword(this.value)) {
            showError(passwordError, 'Password must be at least 6 characters');
        } else {
            hideError(passwordError);
        }
    });

    // When submitting the form
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Check both email and password
        let isValid = true;

        if(!isValidEmail(emailField.value)) {
            showError(emailError, 'Please enter a valid email');
            isValid = false;
        }

        if(!isValidPassword(passwordField.value)) {
            showError(passwordError, 'Password must be at least 6 characters');
            isValid = false;
        }

        // If both are valid, submit the form
        if(isValid) {
            try {
                const formData = new FormData(this);
                const response = await fetch(this.action, {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRFToken': formData.get('csrfmiddlewaretoken')
                    }
                });

                const data = await response.json();

                if(response.ok) {
                    window.location.href = '/dashboard/';
                } else {
                    showError(emailError, data.message || 'Login failed');
                }
            } catch(error) {
                showError(emailError, 'Something went wrong. Please try again.');
            }
        }
    });
});

// Support Modal Functionality
document.addEventListener('DOMContentLoaded', function() {
    const supportLink = document.getElementById('supportLink');
    const supportModal = document.getElementById('supportModal');
    const closeModal = document.getElementById('closeModal');

    // Open modal
    supportLink.addEventListener('click', function(e) {
        e.preventDefault();
        supportModal.classList.add('active');
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
    });

    // Close modal when clicking the close button
    closeModal.addEventListener('click', function() {
        supportModal.classList.remove('active');
        document.body.style.overflow = '';
    });

    // Close modal when clicking outside
    supportModal.addEventListener('click', function(e) {
        if (e.target === supportModal) {
            supportModal.classList.remove('active');
            document.body.style.overflow = '';
        }
    });

    // Prevent modal close when clicking inside modal content
    const modalContent = supportModal.querySelector('.modal-content');
    modalContent.addEventListener('click', function(e) {
        e.stopPropagation();
    });

    // Close modal with Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && supportModal.classList.contains('active')) {
            supportModal.classList.remove('active');
            document.body.style.overflow = '';
        }
    });

    // Handle support category clicks
    const supportCategories = document.querySelectorAll('.support-category');
    supportCategories.forEach(category => {
        category.addEventListener('click', function(e) {
            e.preventDefault();
            // You can add specific handling for each category here
            const categoryType = this.classList[1]; // Get the category type from class
            handleSupportCategory(categoryType);
        });
    });
});

// Handle different support categories
function handleSupportCategory(category) {
    const supportMessages = {
        technical: "Our technical team will assist you with system-related issues.",
        account: "Our security team will help you with account-related concerns."
    };

    // You can customize this function to handle different categories differently
    alert(supportMessages[category] + "\nRedirecting to specialized support...");
} 