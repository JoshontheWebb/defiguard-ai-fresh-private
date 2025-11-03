// Section1: DOM Handling
function waitForDOM(selectors, callback, maxAttempts = 20, interval = 300) {
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
            console.error('[ERROR] DOM elements not found after max attempts:', Object.keys(selectors).filter(k => !elements[k]));
        }
    };
    check();
}

document.addEventListener('DOMContentLoaded', () => {
    // Delegated hamburger toggle (works after reloads)
    document.addEventListener('click', (e) => {
        const hamburger = e.target.closest('#hamburger');
        if (!hamburger) return;
        e.preventDefault();
        const sidebar = document.querySelector('#sidebar');
        const mainContent = document.querySelector('.main-content');
        if (!sidebar || !mainContent) return;
        try {
            sidebar.classList.toggle('open');
            hamburger.classList.toggle('open');
            // Use CSS class for smooth animation + mobile support
            document.body.classList.toggle('sidebar-open');
            console.log(`[DEBUG] Hamburger menu toggled: open=${sidebar.classList.contains('open')}, time=${new Date().toISOString()}`);
        } catch (error) {
            console.error(`[ERROR] Hamburger toggle failed: ${error.message}, time=${new Date().toISOString()}`);
            const warning = document.querySelector('.usage-warning');
            if (warning) {
                warning.textContent = `Menu error: ${error.message}`;
                warning.classList.add('error');
            }
        }
    });

    // Accessibility: keyboard + touch
    const hamburger = document.querySelector('#hamburger');
    if (hamburger) {
        hamburger.setAttribute('tabindex', '0');
        hamburger.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                hamburger.click();
            }
        });
        hamburger.addEventListener('touchstart', (e) => {
            e.preventDefault();
            hamburger.click();
        }, { passive: true });
    }
    // Section2: CSRF Token Management
    const fetchCsrfToken = async (attempt = 1, maxAttempts = 3) => {
        try {
            const response = await fetch(`/csrf-token?_=${Date.now()}`, {
                method: 'GET',
                headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' },
                credentials: 'include'
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(`Failed to fetch CSRF token: ${response.status} ${errorData.detail || response.statusText}`);
            }
            const data = await response.json();
            console.log(`[DEBUG] CSRF response data: ${JSON.stringify(data)}, type=${typeof data.csrf_token}, time=${new Date().toISOString()}`);
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
            console.error('Max CSRF fetch attempts reached, proceeding with null token.');
            return null;
        }
    };

    const withCsrfToken = async (fetchFn) => {
        await new Promise(resolve => setTimeout(resolve, 100));
        let token = localStorage.getItem('csrfToken');
        if (!token) {
            console.error('[ERROR] No CSRF token in localStorage, fetching new');
            try {
                token = await fetchCsrfToken();
            } catch (error) {
                console.error(`[ERROR] Failed to fetch CSRF token: ${error.message}, proceeding with null`);
                return fetchFn(null);
            }
        }
        console.log(`[DEBUG] Using CSRF token for POST: ${token}, type=${typeof token}, time=${new Date().toISOString()}`);
        return fetchFn(token);
    };

    fetchCsrfToken().catch(error => {
        const messageDiv = document.querySelector('.usage-warning');
        if (messageDiv) {
            messageDiv.classList.remove('is-hidden', 'success');
            messageDiv.classList.add('error');
            messageDiv.textContent = `Error setting up secure connection: ${error.message}`;
        }
    });

    // Section3: DOM Initialization
    waitForDOM({
        auditForm: '.audit-section form',
        loading: '.loading',
        resultsDiv: '.results',
        riskScoreSpan: '#risk-score',
        issuesBody: '#issues-body',
        predictionsList: '#predictions-list',
        recommendationsList: '#recommendations-list',
        fuzzingList: '#fuzzing-list',
        remediationRoadmap: '#remediation-roadmap',
        usageWarning: '.usage-warning',
        tierInfo: '.tier-info span',
        tierDescription: '#tier-description',
        sizeLimit: '#size-limit',
        features: '#features',
        upgradeLink: '#upgrade-link',
        tierSelect: '#tier-select',
        tierSwitchButton: '#tier-switch',
        contractAddressInput: '#contract_address',
        facetWell: '#facet-preview',
        downloadReportButton: '#download-report',
        diamondAuditButton: '#diamond-audit',
        customReportInput: '#custom_report',
        apiKeySpan: '#api-key-value',
        logoutSidebar: '#logout-sidebar',
        authStatus: '#auth-status',
        pendingMessage: '#pending-message'
    }, ({ auditForm, loading, resultsDiv, riskScoreSpan, issuesBody, predictionsList, recommendationsList, fuzzingList, remediationRoadmap, usageWarning, tierInfo, tierDescription, sizeLimit, features, upgradeLink, tierSelect, tierSwitchButton, contractAddressInput, facetWell, downloadReportButton, diamondAuditButton, customReportInput, apiKeySpan, logoutSidebar, authStatus, pendingMessage }) => {
        let maxFileSize = null;
        let auditCount = 0;
        let auditLimit = 3;
        // Ensure .audit-section is position: relative for .loading overlay
        const auditSection = document.querySelector('.audit-section');
        if (auditSection && getComputedStyle(auditSection).position !== 'relative') {
            auditSection.style.position = 'relative';
            auditSection.style.overflow = 'hidden';
            console.log('[DEBUG] Applied position: relative to .audit-section for spinner overlay');
        }
        // Create spinner once after DOM is ready
        if (loading && !loading.querySelector('.spinner')) {
            const spinner = document.createElement('div');
            spinner.className = 'spinner';
            const loadingText = document.createElement('p');
            loadingText.textContent = 'Analyzing contract...';
            const progressBar = document.createElement('div');
            progressBar.className = 'progress-bar';
            progressBar.innerHTML = '<div class="progress-fill" style="width: 0%"></div><span class="progress-text">0%</span>';
            loading.appendChild(spinner);
            loading.appendChild(loadingText);
            loading.appendChild(progressBar);
            console.log('[DEBUG] Audit spinner + progress bar created once in DOM, time=' + new Date().toISOString());
        }
        // Section4: File and Pricing Logic
        const AUDIT_CONTRACT_BUTTON = document.querySelector('button[type="submit"]');
        const DIAMOND_AUDIT_BUTTON = document.getElementById('diamond-audit');
        const DIAMOND_PRICE = document.getElementById('diamond-price');
        const calculateDiamondOverage = (file) => {
            if (!file) {
                if (DIAMOND_PRICE) DIAMOND_PRICE.style.display = 'none';
                return 0;
            }
            const size = file.size;
            const overageMb = Math.max(0, (size - 1024 * 1024) / (1024 * 1024));
            let overageCost = 0;
            if (overageMb > 0) {
                if (overageMb <= 10) {
                    overageCost = overageMb * 0.50;
                } else {
                    overageCost += 10 * 0.50;
                    const remainingMb = overageMb - 10;
                    if (remainingMb <= 40) {
                        overageCost += remainingMb * 1.00;
                    } else {
                        overageCost += 40 * 1.00;
                        const remainingAfter50 = overageMb - 50;
                        if (remainingAfter50 <= 2) {
                            overageCost += remainingAfter50 * 2.00;
                        } else {
                            overageCost += 2 * 2.00;
                            overageCost += (remainingAfter50 - 2) * 5.00;
                        }
                    }
                }
            }
            if (DIAMOND_PRICE) {
                DIAMOND_PRICE.textContent = `Diamond Audit Overage: $${overageCost.toFixed(2)} for ${(size / 1024 / 1024).toFixed(2)}MB`;
                DIAMOND_PRICE.style.display = overageCost > 0 ? 'block' : 'none';
            }
            console.log(`[DEBUG] Diamond overage calculated: $${overageCost.toFixed(2)} for ${size} bytes, time=${new Date().toISOString()}`);
            return overageCost;
        };
        const fileInput = document.getElementById('file');
        if (fileInput) {
            fileInput.addEventListener('change', (event) => {
                const file = event.target.files[0];
                if (!file) {
                    AUDIT_CONTRACT_BUTTON.disabled = false;
                    AUDIT_CONTRACT_BUTTON.title = "";
                    if (DIAMOND_AUDIT_BUTTON) DIAMOND_AUDIT_BUTTON.style.display = 'none';
                    if (usageWarning) {
                        usageWarning.textContent = '';
                        usageWarning.classList.remove('warning', 'error');
                    }
                    return;
                }
                const fileSizeMB = file.size / (1024 * 1024);
                const isOver1MB = fileSizeMB > 1;
                const hasDiamond = localStorage.getItem('diamond_feature') === 'true';
                if (isOver1MB && !hasDiamond) {
                    // BLOCK "Audit Contract" for files >1MB without Diamond
                    AUDIT_CONTRACT_BUTTON.disabled = true;
                    AUDIT_CONTRACT_BUTTON.title = "Files >1MB require Diamond Audit with payment";
                    if (DIAMOND_AUDIT_BUTTON) DIAMOND_AUDIT_BUTTON.style.display = 'block';
                    calculateDiamondOverage(file);
                    if (usageWarning) {
                        usageWarning.textContent = `File >1MB. Use "Request Diamond Audit" to pay and process.`;
                        usageWarning.classList.add('warning');
                        usageWarning.classList.remove('error');
                    }
                } else {
                    // ALLOW "Audit Contract" for files ≤1MB or with Diamond
                    AUDIT_CONTRACT_BUTTON.disabled = false;
                    AUDIT_CONTRACT_BUTTON.title = "";
                    if (DIAMOND_AUDIT_BUTTON) DIAMOND_AUDIT_BUTTON.style.display = 'none';
                    if (usageWarning) {
                        usageWarning.textContent = '';
                        usageWarning.classList.remove('warning', 'error');
                    }
                    if (isOver1MB && hasDiamond) {
                        calculateDiamondOverage(file);
                        if (usageWarning) {
                            usageWarning.textContent = `Diamond overage will be charged post-audit.`;
                            usageWarning.classList.add('warning');
                        }
                    }
                }
            });
        }
        // Section6: Authentication
        const updateAuthStatus = () => {
            const username = localStorage.getItem('username');
            console.log(`[DEBUG] updateAuthStatus: username=${username}, localStorage=${JSON.stringify(localStorage)}, time=${new Date().toISOString()}`);
            if (authStatus) {
                authStatus.textContent = username ? `Signed in as ${username}` : 'Sign In / Create Account';
                if (username) {
                    authStatus.innerHTML = `Signed in as ${username}`;
                    sidebar.classList.add('logged-in');
                } else {
                    authStatus.innerHTML = '<a href="/auth">Sign In / Create Account</a>';
                    sidebar.classList.remove('logged-in');
                }
            } else {
                console.error('[ERROR] #auth-status not found in DOM');
            }
        };
        window.addEventListener('storage', () => {
            console.log('[DEBUG] Storage event detected, re-running updateAuthStatus');
            updateAuthStatus();
        });
        let authCheckAttempts = 0;
        const maxAuthCheckAttempts = 60;
        const authCheckInterval = setInterval(() => {
            console.log(`[DEBUG] Periodic auth check attempt ${authCheckAttempts + 1}/${maxAuthCheckAttempts}, username=${localStorage.getItem('username')}`);
            updateAuthStatus();
            authCheckAttempts++;
            if (authCheckAttempts >= maxAuthCheckAttempts) {
                clearInterval(authCheckInterval);
                console.log('[DEBUG] Stopped periodic auth check');
            }
        }, 500);
        window.addEventListener('authUpdate', () => {
            console.log('[DEBUG] Custom authUpdate event detected, re-running updateAuthStatus');
            updateAuthStatus();
        });
        setTimeout(() => {
            console.log(`[DEBUG] Extended auth check after load, username=${localStorage.getItem('username')}, time=${new Date().toISOString()}`);
            updateAuthStatus();
        }, 5000);
        setTimeout(() => {
            console.log(`[DEBUG] Persistent auth check, username=${localStorage.getItem('username')}, time=${new Date().toISOString()}`);
            updateAuthStatus();
        }, 10000);
        if (logoutSidebar) {
            logoutSidebar.addEventListener('click', (e) => {
                e.preventDefault();
                console.log(`[DEBUG] Logout initiated from sidebar, time=${new Date().toISOString()}`);
                localStorage.removeItem('username');
                console.log('[DEBUG] Local storage cleared (username only)');
                updateAuthStatus();
                window.location.href = '/auth';
            });
        } else {
            console.error('[ERROR] #logout-sidebar not found in DOM');
        }
        // Section9: Tier Management
        const fetchTierData = async () => {
            try {
                const username = localStorage.getItem('username') || '';
                const url = username ? `/tier?username=${encodeURIComponent(username)}` : '/tier';
                console.log(`[DEBUG] Fetching tier data from ${url}, time=${new Date().toISOString()}`);
                const response = await fetch(url, {
                    headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' },
                    credentials: 'include'
                });
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(`Failed to fetch tier data: ${response.status} ${errorData.detail || response.statusText}`);
                }
                const data = await response.json();
                const { tier, size_limit, feature_flags, api_key, audit_count, audit_limit, has_diamond } = data;
                auditCount = audit_count;
                auditLimit = audit_limit;
                localStorage.setItem('tier', tier);
                localStorage.setItem('diamond_feature', has_diamond.toString());
                localStorage.setItem('size_limit', size_limit);
                if (tierInfo) tierInfo.textContent = `Tier: ${tier.charAt(0).toUpperCase() + tier.slice(1)}${has_diamond ? ' + Diamond' : ''} (${size_limit === 'Unlimited' ? 'Unlimited audits' : `${auditCount}/${auditLimit} audits`})`;
                if (tierDescription) tierDescription.textContent = `${tier.charAt(0).toUpperCase() + tier.slice(1)}${has_diamond ? ' + Diamond' : ''} Tier: ${has_diamond ? 'Unlimited file size, full Diamond audits, fuzzing, priority support, NFT rewards' : tier === 'pro' ? 'Unlimited audits, Diamond add-on access ($50/mo), fuzzing, priority support' : tier === 'beginner' ? `Up to 10 audits, 1MB file size (${auditCount}/${auditLimit} remaining), priority support` : `Up to 3 audits, 1MB file size (${auditCount}/${auditLimit} remaining)`}`;
                if (sizeLimit) sizeLimit.textContent = `Max file size: ${size_limit}`;
                if (features) features.textContent = `Features: ${has_diamond ? 'Diamond audits, Diamond Pattern previews, priority support, NFT rewards' : tier === 'pro' ? 'Diamond add-on access, standard audits, Diamond Pattern previews, fuzzing, priority support' : 'Standard audit features'}${feature_flags.predictions ? ', AI predictions' : ''}${feature_flags.onchain ? ', on-chain analysis' : ''}${feature_flags.reports ? ', exportable reports' : ''}${feature_flags.fuzzing ? ', fuzzing analysis' : ''}${feature_flags.priority_support ? ', priority support' : ''}${feature_flags.nft_rewards ? ', NFT rewards' : ''}`;

                if (usageWarning) usageWarning.textContent = tier === 'free' || tier === 'beginner' ? `${tier.charAt(0).toUpperCase() + tier.slice(1)} tier: ${auditCount}/${auditLimit} audits remaining` : '';
                if (usageWarning) usageWarning.classList.remove('error');
                if (upgradeLink) upgradeLink.style.display = !has_diamond ? 'inline-block' : 'none';
                maxFileSize = size_limit === 'Unlimited' ? Infinity : parseFloat(size_limit.replace('MB', '')) * 1024 * 1024;
                if (document.querySelector('#file-help')) document.querySelector('#file-help').textContent = '';
                document.querySelectorAll('.pro-diamond-only').forEach(el => el.style.display = tier === 'pro' || has_diamond ? 'block' : 'none');
                if (customReportInput) customReportInput.style.display = tier === 'pro' || has_diamond ? 'block' : 'none';
                if (downloadReportButton) downloadReportButton.style.display = feature_flags.reports ? 'block' : 'none';
                document.querySelectorAll('.diamond-only').forEach(el => el.style.display = has_diamond ? 'block' : 'none');
                if (document.querySelector('.remediation-placeholder')) document.querySelector('.remediation-placeholder').style.display = has_diamond ? 'block' : 'none';
                if (document.querySelector('.fuzzing-placeholder')) document.querySelector('.fuzzing-placeholder').style.display = feature_flags.fuzzing ? 'block' : 'none';
                if (document.querySelector('.priority-support')) document.querySelector('.priority-support').style.display = feature_flags.priority_support ? 'block' : 'none';
                if (apiKeySpan) apiKeySpan.textContent = api_key || 'N/A';
                if (document.getElementById('api-key')) document.getElementById('api-key').style.display = api_key ? 'block' : 'none';
                // Update sidebar tier display
                const sidebarTierDisplay = document.querySelector('.sidebar .tier-display');
                if (sidebarTierDisplay) {
                    sidebarTierDisplay.textContent = `Tier: ${tier.charAt(0).toUpperCase() + tier.slice(1)}${has_diamond ? ' + Diamond' : ''}`;
                    console.log(`[DEBUG] Sidebar tier updated: ${sidebarTierDisplay.textContent}, time=${new Date().toISOString()}`);
                } else {
                    console.warn('[DEBUG] .sidebar .tier-display not found, scheduling recheck');
                    setTimeout(() => {
                        const retryDisplay = document.querySelector('.sidebar .tier-display');
                        if (retryDisplay) {
                            retryDisplay.textContent = `Tier: ${tier.charAt(0).toUpperCase() + tier.slice(1)}${has_diamond ? ' + Diamond' : ''}`;
                            console.log(`[DEBUG] Sidebar tier updated after recheck: ${retryDisplay.textContent}, time=${new Date().toISOString()}`);
                        }
                    }, 500);
                }
                console.log(`[DEBUG] Tier data fetched: tier=${tier}, has_diamond=${has_diamond}, auditCount=${auditCount}, auditLimit=${auditLimit}, time=${new Date().toISOString()}`);
            } catch (error) {
                console.error(`[ERROR] Tier fetch error: ${error.message}, time=${new Date().toISOString()}`);
                if (usageWarning) usageWarning.textContent = `Error fetching tier data: ${error.message}`;
                if (usageWarning) usageWarning.classList.add('error');
            }
        };
        tierSwitchButton.addEventListener('click', () => {
            withCsrfToken(async (token) => {
                if (!token) {
                    usageWarning.textContent = 'Unable to establish secure connection.';
                    usageWarning.classList.add('error');
                    console.error(`[ERROR] No CSRF token for tier switch, time=${new Date().toISOString()}`);
                    return;
                }
                const selectedTier = tierSelect.value;
                if (!tierSelect) {
                    console.error(`[ERROR] tierSelect element not found, time=${new Date().toISOString()}`);
                    usageWarning.textContent = 'Error: Tier selection unavailable';
                    usageWarning.classList.add('error');
                    return;
                }
                if (!selectedTier || !['beginner', 'pro', 'diamond'].includes(selectedTier)) {
                    console.error(`[ERROR] Invalid or missing tier selected: ${selectedTier}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Error: Invalid tier '${selectedTier || 'none'}'. Choose beginner, pro, or diamond`;
                    usageWarning.classList.add('error');
                    return;
                }
                const username = localStorage.getItem('username');
                if (!username) {
                    console.error(`[ERROR] No username found, redirecting to /auth, time=${new Date().toISOString()}`);
                    window.location.href = '/auth';
                    return;
                }
                const hasDiamond = selectedTier === 'diamond';
                const effectiveTier = selectedTier;
                console.log(`[DEBUG] Initiating tier switch: username=${username}, tier=${effectiveTier}, has_diamond=${hasDiamond}, time=${new Date().toISOString()}`);
                try {
                    const requestBody = JSON.stringify({
                        username: username,
                        tier: effectiveTier,
                        has_diamond: hasDiamond
                    });
                    console.log(`[DEBUG] Sending /create-tier-checkout request with body: ${requestBody}, time=${new Date().toISOString()}`);
                    const response = await fetch('/create-tier-checkout', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': token,
                            'Accept': 'application/json'
                        },
                        credentials: 'include',
                        body: requestBody
                    });
                    console.log(`[DEBUG] /create-tier-checkout response status: ${response.status}, ok: ${response.ok}, headers: ${JSON.stringify([...response.headers])}, time=${new Date().toISOString()}`);
                    if (!response.ok) {
                        const errorData = await response.json().catch(() => ({}));
                        console.error(`[ERROR] /create-tier-checkout failed: status=${response.status}, detail=${errorData.detail || 'Unknown error'}, response_body=${JSON.stringify(errorData)}, time=${new Date().toISOString()}`);
                        throw new Error(errorData.detail || `Failed to initiate tier upgrade: ${response.status}`);
                    }
                    const data = await response.json();
                    console.log(`[DEBUG] Stripe checkout session created: session_url=${data.session_url}, time=${new Date().toISOString()}`);
                    window.location.href = data.session_url;
                } catch (error) {
                    console.error(`[ERROR] Tier switch error: ${error.message}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Error initiating tier upgrade: ${error.message}`;
                    usageWarning.classList.add('error');
                }
            });
        });
        // Section7: Payment Handling – now supports pending_id polling
        const handlePostPaymentRedirect = async () => {
            const urlParams = new URLSearchParams(window.location.search);
            const sessionId = urlParams.get('session_id');
            const tier = urlParams.get('tier');
            const hasDiamond = urlParams.get('has_diamond') === 'true';
            const tempId = urlParams.get('temp_id');
            const username = urlParams.get('username') || localStorage.getItem('username');
            const upgradeStatus = urlParams.get('upgrade');
            const message = urlParams.get('message');
            const pendingId = urlParams.get('pending_id');

            console.log(`[DEBUG] Post-payment redirect: session_id=${sessionId}, tier=${tier}, has_diamond=${hasDiamond}, temp_id=${tempId}, username=${username}, upgrade=${upgradeStatus}, message=${message}, pending_id=${pendingId}`);

            if (username) {
                localStorage.setItem('username', username);
            }

            if (upgradeStatus) {
                usageWarning.textContent = message || (upgradeStatus === 'success' ? 'Tier upgrade completed' : 'Tier upgrade failed');
                usageWarning.classList.add(upgradeStatus === 'success' ? 'success' : 'error');
                window.history.replaceState({}, document.title, '/ui');
                await fetchTierData();
                return;
            }

            if (pendingId) {
                pollPendingStatus(pendingId);
                return;
            }

            if (sessionId && username) {
                try {
                    let endpoint = '';
                    let query = '';
                    if (tempId) {
                        endpoint = '/complete-diamond-audit';
                        query = `session_id=${encodeURIComponent(sessionId)}&temp_id=${encodeURIComponent(tempId)}&username=${encodeURIComponent(username)}`;
                    } else if (tier) {
                        endpoint = '/complete-tier-checkout';
                        query = `session_id=${encodeURIComponent(sessionId)}&tier=${encodeURIComponent(tier)}&has_diamond=${hasDiamond}&username=${encodeURIComponent(username)}`;
                    } else {
                        throw new Error('Invalid payment redirect parameters');
                    }

                    const response = await fetch(`${endpoint}?${query}`, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json' },
                        credentials: 'include'
                    });

                    if (!response.ok) {
                        const err = await response.json().catch(() => ({}));
                        throw new Error(err.detail || 'Failed to complete action');
                    }

                    localStorage.setItem('username', username);
                    usageWarning.textContent = `Successfully completed ${tempId ? 'Diamond audit' : 'tier upgrade'}`;
                    usageWarning.classList.add('success');
                    await fetchTierData();
                    window.history.replaceState({}, document.title, '/ui');
                } catch (error) {
                    console.error(`[ERROR] Post-payment error: ${error.message}`);
                    usageWarning.textContent = `Error: ${error.message}`;
                    usageWarning.classList.add('error');
                }
            } else if (username) {
                await fetchTierData();
                window.history.replaceState({}, document.title, '/ui');
            }
        };
        handlePostPaymentRedirect();

        const urlParams = new URLSearchParams(window.location.search);
        const pendingId = urlParams.get('pending_id');
        if (pendingId) {
            console.log(`[DEBUG] Found pending_id=${pendingId} – starting poll`);
            pollPendingStatus(pendingId);
        }

        async function pollPendingStatus(pending_id) {
            const pollInterval = 5000;
            const maxPolls = 60;
            let polls = 0;

            const interval = setInterval(async () => {
                polls++;
                try {
                    const response = await fetch(`/pending-status/${pending_id}`, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json' },
                        credentials: 'include'
                    });

                    if (!response.ok) {
                        if (response.status === 404) {
                            clearInterval(interval);
                            usageWarning.textContent = 'Pending audit not found';
                            usageWarning.classList.add('error');
                            return;
                        }
                        throw new Error(`Status check failed: ${response.status}`);
                    }

                    const data = await response.json();

                    if (data.status === 'complete') {
                        clearInterval(interval);
                        handleAuditResponse(data);
                        usageWarning.textContent = 'Diamond audit completed!';
                        usageWarning.classList.add('success');
                        console.log(`[DEBUG] Pending audit complete (id=${pending_id})`);
                    } else if (data.status === 'processing') {
                        usageWarning.textContent = 'Processing Diamond audit...';
                        usageWarning.classList.add('warning');
                    } else {
                        usageWarning.textContent = `Status: ${data.status}`;
                    }

                    console.log(`[DEBUG] Poll ${polls}/${maxPolls} – id=${pending_id}, status=${data.status}`);

                    if (polls >= maxPolls) {
                        clearInterval(interval);
                        usageWarning.textContent = 'Audit taking longer than expected. Please refresh.';
                        usageWarning.classList.add('warning');
                    }
                } catch (error) {
                    console.error(`[ERROR] Poll error: ${error.message}`);
                    clearInterval(interval);
                    usageWarning.textContent = `Error checking audit: ${error.message}`;
                    usageWarning.classList.add('error');
                }
            }, pollInterval);
        }
        // Section8: Facet Preview
        const fetchFacetPreview = async (contractAddress, attempt = 1, maxAttempts = 3) => {
            if (!contractAddress || contractAddress === 'undefined') {
                console.error(`[ERROR] Invalid contract address: ${contractAddress}, skipping fetch, time=${new Date().toISOString()}`);
                return;
            }
            facetWell.textContent = '';
            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'facet-loading';
            loadingDiv.setAttribute('aria-live', 'polite');
            loadingDiv.innerHTML = `
                <div class="spinner"></div>
                <p>Loading facet preview...</p>
            `;
            facetWell.appendChild(loadingDiv);
            try {
                const username = localStorage.getItem('username') || '';
                const response = await fetch(`/facets/${contractAddress}?username=${encodeURIComponent(username)}&_=${Date.now()}`, {
                    method: 'GET',
                    headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' },
                    credentials: 'include'
                });
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.detail || 'Failed to fetch facet data');
                }
                const data = await response.json();
                facetWell.textContent = '';
                if (data.facets.length === 0) {
                    facetWell.textContent = 'No facets found for this contract.';
                    return;
                }
                const table = document.createElement('table');
                table.className = 'table is-striped is-fullwidth';
                table.setAttribute('role', 'table');
                table.setAttribute('aria-describedby', 'facet-desc');
                table.innerHTML = `
                    <thead>
                        <tr>
                            <th>Facet Address</th>
                            <th>Function Selectors</th>
                            <th>Functions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.facets.map(facet => `
                            <tr tabindex="0">
                                <td>${facet.facetAddress}</td>
                                <td>${facet.functionSelectors.join(', ')}</td>
                                <td>${facet.functions.join(', ')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                `;
                const heading = document.createElement('h3');
                heading.className = 'title is-4';
                heading.setAttribute('aria-label', 'Diamond Facet Preview');
                heading.textContent = 'Diamond Facet Preview';
                const desc = document.createElement('small');
                desc.id = 'facet-desc';
                desc.textContent = 'Table of facet addresses and function selectors for Diamond Pattern contracts.';
                facetWell.appendChild(heading);
                facetWell.appendChild(table);
                facetWell.appendChild(desc);
                if (data.is_preview) {
                    const watermark = document.createElement('p');
                    watermark.className = 'has-text-warning';
                    watermark.textContent = 'Pro Tier Preview – Upgrade to Diamond add-on for Full Audit';
                    facetWell.appendChild(watermark);
                }
                console.log(`[DEBUG] Facet preview loaded for address: ${contractAddress}, is_preview=${data.is_preview}, time=${new Date().toISOString()}`);
            } catch (error) {
                console.error(`Facet preview error (attempt ${attempt}/${maxAttempts}): ${error.message}`);
                if (attempt < maxAttempts && !error.message.includes('Pro or Diamond tier')) {
                    console.log(`Retrying facet fetch in 1s...`);
                    setTimeout(() => fetchFacetPreview(contractAddress, attempt + 1, maxAttempts), 1000);
                } else {
                    facetWell.textContent = `Error loading facet preview: ${error.message}`;
                    facetWell.className = 'has-text-danger';
                    facetWell.setAttribute('aria-live', 'assertive');
                    if (error.message.includes('Pro or Diamond tier')) {
                        facetWell.innerHTML = `<p class="has-text-warning" aria-live="assertive">Diamond Pattern facet preview requires Pro tier or Diamond add-on. <a href="/upgrade">Upgrade now</a></p>`;
                    }
                }
            }
        };
        if (contractAddressInput) {
            contractAddressInput.addEventListener('input', (e) => {
                const address = e.target.value.trim();
                if (address && address.match(/^0x[a-fA-F0-9]{40}$/)) {
                    fetchFacetPreview(address);
                } else {
                    facetWell.textContent = '';
                }
            });
        }
        // Section10: Diamond Audit
diamondAuditButton?.addEventListener('click', () => {
    withCsrfToken(async (token) => {
        if (!token) {
            usageWarning.textContent = 'Unable to establish secure connection.';
            usageWarning.classList.add('error');
            console.error(`[ERROR] No CSRF token for diamond audit, time=${new Date().toISOString()}`);
            return;
        }
        const fileInput = document.querySelector('#file');
        const file = fileInput.files[0];
        if (!file) {
            usageWarning.textContent = 'Please select a file for Diamond audit';
            usageWarning.classList.add('error');
            console.error(`[ERROR] No file selected for diamond audit, time=${new Date().toISOString()}`);
            return;
        }
        const username = localStorage.getItem('username');
        if (!username) {
            console.error(`[ERROR] No username found, redirecting to /auth, time=${new Date().toISOString()}`);
            window.location.href = '/auth';
            return;
        }
        const formData = new FormData();
        formData.append('file', file);
        formData.append('csrf_token', token);
        try {
            console.log(`[DEBUG] Sending /diamond-audit request for username=${username}, time=${new Date().toISOString()}`);
            const response = await fetch(`/diamond-audit?username=${encodeURIComponent(username)}`, {
                method: 'POST',
                headers: { 'X-CSRF-Token': token },
                body: formData,
                credentials: 'include'
            });
            console.log(`[DEBUG] /diamond-audit response status: ${response.status}, ok: ${response.ok}, headers: ${JSON.stringify([...response.headers])}, time=${new Date().toISOString()}`);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                console.error(`[ERROR] /diamond-audit failed: status=${response.status}, detail=${errorData.detail || 'Unknown error'}, response_body=${JSON.stringify(errorData)}, time=${new Date().toISOString()}`);
                throw new Error(errorData.detail || 'Diamond audit request failed');
            }
            const data = await response.json();
            if (data.session_url) {
                console.log(`[DEBUG] Redirecting to Stripe for Diamond audit, session_url=${data.session_url}, time=${new Date().toISOString()}`);
                window.location.href = data.session_url;
            } else {
                handleAuditResponse(data);
                console.log(`[DEBUG] Direct Diamond audit response handled, time=${new Date().toISOString()}`);
            }
        } catch (error) {
            console.error(`[ERROR] Diamond audit error: ${error.message}, time=${new Date().toISOString()}`);
            usageWarning.textContent = `Error initiating Diamond audit: ${error.message}`;
            usageWarning.classList.add('error');
        }
    });
});
});
});   // end waitForDOM