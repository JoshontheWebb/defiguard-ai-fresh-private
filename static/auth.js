/ Polling for DOM readiness
function waitForDOM(selectors, callback, maxAttempts = 10, interval = 100) {
    let attempts = 0;
    const elements = {};
    const check = () => {
        let allFound = true;
        for (const [key, selector] of Object.entries(selectors)) {
            elements[key] = document.querySelector(selector);
            if (!elements[key]) allFound = false;
        }
        if (allFound) {
            callback(elements);
        } else if (attempts < maxAttempts) {
            attempts++;
            console.log(`[DEBUG] Waiting for DOM elements, attempt ${attempts}/${maxAttempts}, time=${new Date().toISOString()}`);
            setTimeout(check, interval);
        } else {
            console.error('[ERROR] DOM elements not found:', Object.keys(selectors).filter(k => !elements[k]));
        }
    };
    check();
}

document.addEventListener('DOMContentLoaded', () => {
    // Fetch CSRF token with retry
    const fetchCsrfToken = async (attempt = 1, maxAttempts = 3) => {
        try {
            const response = await fetch(`/csrf-token?_=${Date.now()}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Cache-Control': 'no-cache'
                },
                credentials: 'include'
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(`Failed to fetch CSRF token: ${response.status} ${errorData.detail || response.statusText}`);
            }
            const data = await response.json();
            console.log(`[DEBUG] CSRF response data: ${JSON.stringify(data)}, type=${typeof data.csrf_token}`);
            if (typeof data.csrf_token !== 'string' || !data.csrf_token || data.csrf_token === 'undefined') {
                throw new Error('Invalid CSRF token received');
            }
            localStorage.setItem('csrfToken', data.csrf_token);
            console.log(`[DEBUG] CSRF token fetched and stored: ${data.csrf_token}, time=${new Date().toISOString()}`);
            return data.csrf_token;
        } catch (error) {
            console.error(`CSRF token fetch error (attempt ${attempt}/${maxAttempts}): ${error.message}`);
            if (attempt < maxAttempts) {
                console.log(`Retrying CSRF token fetch in 1s...`);
                await new Promise(resolve => setTimeout(resolve, 1000));
                return fetchCsrfToken(attempt + 1, maxAttempts);
            }
            console.error('Max CSRF fetch attempts reached.');
            throw error;
        }
    };

    // Wrapper to ensure fresh CSRF token for POST requests
    const withCsrfToken = async (fetchFn) => {
        await new Promise(resolve => setTimeout(resolve, 100)); // Add delay to ensure token is stored
        const token = await fetchCsrfToken();
        console.log(`[DEBUG] Using CSRF token for POST: ${token}, type=${typeof token}, time=${new Date().toISOString()}`);
        return fetchFn(token);
    };

    // Initialize CSRF token on load
    fetchCsrfToken().catch(error => {
        const messageDiv = document.querySelector('.auth-message');
        if (messageDiv) {
            messageDiv.classList.remove('is-hidden', 'is-success');
            messageDiv.classList.add('is-danger');
            messageDiv.textContent = `Error setting up secure connection: ${error.message}`;
        }
    });

    waitForDOM({
        authToggle: '#auth-toggle',
        authForms: '#auth-forms',
        messageDiv: '.auth-message',
        logoutSection: '#logout-section',
        logoutButton: '#logout-button',
        tabs: '.tabs',
        signinForm: '#signin-form',
        signupForm: '#signup-form'
    }, ({ authToggle, authForms, messageDiv, logoutSection, logoutButton, tabs, signinForm, signupForm }) => {
        // Toggle auth forms
        authToggle.addEventListener('click', () => {
            const isVisible = authForms.style.visibility === 'visible';
            authForms.style.visibility = isVisible ? 'hidden' : 'visible';
            authForms.style.opacity = isVisible ? 0 : 1;
            authToggle.textContent = isVisible ? 'Sign In or Create Account' : 'Hide Forms';
            console.log(`[DEBUG] Toggled auth forms: visibility=${authForms.style.visibility}, time=${new Date().toISOString()}`);
        });

        // Tab switching
        tabs.addEventListener('click', (e) => {
            const tab = e.target.closest('li[data-tab]');
            if (!tab) return;
            document.querySelectorAll('.tabs li').forEach(t => t.classList.remove('is-active'));
            tab.classList.add('is-active');
            document.querySelectorAll('.tab-content').forEach(content => {
                if (content.id === tab.dataset.tab) {
                    content.classList.add('active');
                    content.style.opacity = 0;
                    setTimeout(() => { content.style.opacity = 1; }, 50);
                } else {
                    content.classList.remove('active');
                }
            });
            console.log(`[DEBUG] Switching to tab: ${tab.dataset.tab}, time=${new Date().toISOString()}`);
            const debugDiv = document.getElementById('tab-debug');
            if (debugDiv) {
                debugDiv.style.display = 'block';
                debugDiv.textContent = `Current tab: ${tab.dataset.tab}`;
            }
        });

        // Password toggle
        const togglePassword = (inputId, toggleId) => {
            const input = document.getElementById(inputId);
            const toggle = document.getElementById(toggleId);
            if (!input || !toggle) {
                console.error('[ERROR] Password toggle elements not found:', { inputId, toggleId });
                return;
            }
            toggle.addEventListener('click', () => {
                const type = input.type === 'password' ? 'text' : 'password';
                input.type = type;
                toggle.querySelector('i').classList.toggle('fa-eye');
                toggle.querySelector('i').classList.toggle('fa-eye-slash');
            });
        };

        togglePassword('signin-password', 'toggle-signin-password');
        togglePassword('signup-password', 'toggle-signup-password');
        togglePassword('signup-confirm-password', 'toggle-confirm-password');

        // Sign-in form
        signinForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('signin-username')?.value.trim();
            const password = document.getElementById('signin-password')?.value;

            if (!username || !password) {
                console.log('Sign-in attempt: Missing fields', { username, password });
                messageDiv.classList.remove('is-hidden', 'is-success');
                messageDiv.classList.add('is-danger');
                messageDiv.textContent = 'Please fill in all fields.';
                return;
            }

            console.log('Sign-in attempt:', { username });
            await withCsrfToken(async (token) => {
                try {
                    const response = await fetch(`/signin/${encodeURIComponent(username)}`, {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': token
                        },
                        body: JSON.stringify({ password }),
                        credentials: 'include'
                    });
                    const data = await response.json();

                    if (response.ok) {
                        console.log('Sign-in success:', { username, message: data.message });
                        localStorage.setItem('username', username);
                        const tierResponse = await fetch(`/tier?username=${encodeURIComponent(username)}`, {
                            headers: { 'Accept': 'application/json' },
                            credentials: 'include'
                        });
                        if (!tierResponse.ok) {
                            console.error('Failed to fetch tier:', tierResponse.status);
                            throw new Error('Failed to fetch tier information');
                        }
                        const tierData = await tierResponse.json();
                        localStorage.setItem('tier', tierData.tier);
                        localStorage.setItem('size_limit', tierData.size_limit);
                        localStorage.setItem('diamond_feature', JSON.stringify(tierData.feature_flags.diamond));
                        console.log(`[DEBUG] Setting localStorage: username=${username}, tier=${tierData.tier}, time=${new Date().toISOString()}`);
                        window.dispatchEvent(new Event('authUpdate'));
                        messageDiv.classList.remove('is-hidden', 'is-danger');
                        messageDiv.classList.add('is-success');
                        messageDiv.textContent = data.message;
                        logoutSection.style.display = 'block';
                        document.getElementById('signin').style.display = 'none';
                        document.getElementById('signup').style.display = 'none';
                        authToggle.style.display = 'none';
                        setTimeout(() => window.location.href = '/ui', 1000);
                    } else {
                        console.log('Sign-in failed:', { error: data.detail });
                        localStorage.removeItem('username');
                        localStorage.removeItem('tier');
                        localStorage.removeItem('size_limit');
                        localStorage.removeItem('diamond_feature');
                        throw new Error(data.detail || 'Sign in failed');
                    }
                } catch (error) {
                    console.error('Sign-in error:', error.message);
                    messageDiv.classList.remove('is-hidden', 'is-success');
                    messageDiv.classList.add('is-danger');
                    messageDiv.textContent = error.message;
                }
            });
        });

        // Signup form
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('signup-email')?.value.trim();
            const username = document.getElementById('signup-username')?.value.trim();
            const password = document.getElementById('signup-password')?.value;
            const confirmPassword = document.getElementById('signup-confirm-password')?.value;
            const emailError = document.getElementById('email-error');
            const passwordError = document.getElementById('password-error');
            const confirmError = document.getElementById('confirm-error');

            if (!emailError || !passwordError || !confirmError) {
                console.error('[ERROR] Signup error elements not found');
                return;
            }

            emailError.style.display = 'none';
            passwordError.style.display = 'none';
            confirmError.style.display = 'none';

            let valid = true;

            if (!/\S+@\S+\.\S+/.test(email)) {
                emailError.textContent = 'Invalid email format.';
                emailError.style.display = 'block';
                valid = false;
            }

            if (password !== confirmPassword) {
                confirmError.textContent = 'Passwords do not match.';
                confirmError.style.display = 'block';
                valid = false;
            }

            if (password.length < 8) {
                passwordError.textContent = 'Password must be at least 8 characters long.';
                passwordError.style.display = 'block';
                valid = false;
            }

            if (!valid || !username) {
                console.log('Signup attempt: Validation failed', { email, username, valid });
                messageDiv.classList.remove('is-hidden', 'is-success');
                messageDiv.classList.add('is-danger');
                messageDiv.textContent = 'Please correct the errors.';
                return;
            }

            console.log('Signup attempt:', { email, username });
            await withCsrfToken(async (token) => {
                try {
                    const response = await fetch(`/signup/${encodeURIComponent(username)}`, {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': token
                        },
                        body: JSON.stringify({ email, password }),
                        credentials: 'include'
                    });
                    const data = await response.json();

                    if (response.ok) {
                        console.log('Signup success:', { username, message: data.message });
                        localStorage.setItem('username', username);
                        localStorage.setItem('tier', 'free');
                        localStorage.setItem('size_limit', '1MB');
                        localStorage.setItem('diamond_feature', JSON.stringify(false));
                        console.log(`[DEBUG] Setting localStorage: username=${username}, tier=free, time=${new Date().toISOString()}`);
                        window.dispatchEvent(new Event('authUpdate'));
                        messageDiv.classList.remove('is-hidden', 'is-danger');
                        messageDiv.classList.add('is-success');
                        messageDiv.textContent = data.message;
                        logoutSection.style.display = 'block';
                        document.getElementById('signin').style.display = 'none';
                        document.getElementById('signup').style.display = 'none';
                        authToggle.style.display = 'none';
                        setTimeout(() => window.location.href = '/ui', 1000);
                    } else {
                        console.log('Signup failed:', { error: data.detail });
                        localStorage.removeItem('username');
                        localStorage.removeItem('tier');
                        localStorage.removeItem('size_limit');
                        localStorage.removeItem('diamond_feature');
                        throw new Error(data.detail || 'Account creation failed');
                    }
                } catch (error) {
                    console.error('Signup error:', error.message);
                    messageDiv.classList.remove('is-hidden', 'is-success');
                    messageDiv.classList.add('is-danger');
                    messageDiv.textContent = error.message;
                }
            });
        });

        // Logout handler
        const username = localStorage.getItem('username');
        if (username) {
            logoutSection.style.display = 'block';
            document.getElementById('signin').style.display = 'none';
            document.getElementById('signup').style.display = 'none';
            authForms.style.display = 'block';
            authToggle.style.display = 'none';
        } else {
            logoutSection.style.display = 'none';
            authToggle.style.display = 'block';
        }

        logoutButton.addEventListener('click', () => {
            console.log('Logout attempt:', { username: localStorage.getItem('username') });
            localStorage.removeItem('username');
            localStorage.removeItem('tier');
            localStorage.removeItem('size_limit');
            localStorage.removeItem('diamond_feature');
            localStorage.removeItem('csrfToken');
            console.log('Logout success');
            logoutSection.style.display = 'none';
            document.getElementById('signin').classList.add('active');
            document.getElementById('signup').classList.remove('active');
            authForms.style.display = 'none';
            authForms.style.visibility = 'hidden';
            authToggle.style.display = 'block';
            authToggle.textContent = 'Sign In or Create Account';
            window.location.href = '/ui';
        });
    });
});