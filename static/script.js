// Section1: DOM Handling (replace existing Section1)
function waitForDOM(selectors, callback, maxAttempts = 20, interval = 200) { // Increased attempts and interval
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
    // Section2: CSRF Token Management
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
            console.error('Max CSRF fetch attempts reached.');
            throw error;
        }
    };

    const withCsrfToken = async (fetchFn) => {
        await new Promise(resolve => setTimeout(resolve, 100)); // Ensure token storage
        let token;
        try {
            token = await fetchCsrfToken();
            console.log(`[DEBUG] Using CSRF token for POST: ${token}, type=${typeof token}, time=${new Date().toISOString()}`);
        } catch (error) {
            console.error(`[ERROR] Failed to fetch CSRF token for POST: ${error.message}`);
            return null;
        }
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
        hamburger: '#hamburger',
        sidebar: '#sidebar',
        mainContent: '.main-content',
        logoutSidebar: '#logout-sidebar',
        authStatus: '#auth-status' // Added to access the auth status element
    }, ({ auditForm, loading, resultsDiv, riskScoreSpan, issuesBody, predictionsList, recommendationsList, fuzzingList, remediationRoadmap, usageWarning, tierInfo, tierDescription, sizeLimit, features, upgradeLink, tierSelect, tierSwitchButton, contractAddressInput, facetWell, downloadReportButton, diamondAuditButton, customReportInput, apiKeySpan, hamburger, sidebar, mainContent, logoutSidebar, authStatus }) => {
        let maxFileSize = null;
        let auditCount = 0;
        let auditLimit = 3;

        // Section4: File and Pricing Logic
        const calculateDiamondOverage = (file) => {
            if (!file) {
                document.getElementById('diamond-price').style.display = 'none';
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
                        const remainingAfter50 = remainingMb - 40;
                        if (remainingAfter50 <= 2) {
                            overageCost += remainingAfter50 * 2.00;
                        } else {
                            overageCost += 2 * 2.00;
                            overageCost += (remainingAfter50 - 2) * 5.00;
                        }
                    }
                }
            }
            const priceElement = document.getElementById('diamond-price');
            priceElement.textContent = `Diamond Audit Overage: $${overageCost.toFixed(2)} for ${(size / 1024 / 1024).toFixed(2)}MB`;
            priceElement.style.display = overageCost > 0 ? 'block' : 'none';
            console.log(`[DEBUG] Diamond overage calculated: $${overageCost.toFixed(2)} for ${size} bytes, time=${new Date().toISOString()}`);
            return overageCost;
        };

        document.getElementById('file')?.addEventListener('change', (event) => {
            const file = event.target.files[0];
            calculateDiamondOverage(file);
        });

        // Section5: Hamburger Menu (replace existing Section5)
console.log(`[DEBUG] Initializing hamburger menu: hamburger=${!!hamburger}, sidebar=${!!sidebar}, mainContent=${!!mainContent}, time=${new Date().toISOString()}`);
if (hamburger && sidebar && mainContent) {
    document.addEventListener('click', (e) => {
        const ham = e.target.closest('#hamburger');
        if (ham) {
            try {
                sidebar.classList.toggle('open');
                ham.classList.toggle('open'); // Use ham to ensure correct element
                mainContent.style.marginLeft = sidebar.classList.contains('open') ? '270px' : '0';
                console.log(`[DEBUG] Hamburger menu toggled: sidebar.open=${sidebar.classList.contains('open')}, mainContent.marginLeft=${mainContent.style.marginLeft}, time=${new Date().toISOString()}`);
            } catch (error) {
                console.error(`[ERROR] Hamburger menu toggle failed: ${error.message}, time=${new Date().toISOString()}`);
                usageWarning.textContent = `Error with menu: ${error.message}`;
                usageWarning.classList.add('error');
            }
        }
    });
} else {
    console.error(`[ERROR] Hamburger menu initialization failed: hamburger=${!!hamburger}, sidebar=${!!sidebar}, mainContent=${!!mainContent}, time=${new Date().toISOString()}`);
    usageWarning.textContent = 'Error: Menu components not found';
    usageWarning.classList.add('error');
}

        // Section6: Authentication
        const updateAuthStatus = () => {
            const username = localStorage.getItem('username');
            console.log(`[DEBUG] updateAuthStatus: username=${username}, localStorage=${JSON.stringify(localStorage)}, time=${new Date().toISOString()}`);
            if (!authStatus) {
                console.error('[ERROR] #auth-status not found in DOM');
                return;
            }
            authStatus.textContent = username ? `Signed in as ${username}` : 'Sign In / Create Account';
            if (username) {
                authStatus.innerHTML = `Signed in as ${username}`;
                sidebar.classList.add('logged-in'); // Show logout when signed in
            } else {
                authStatus.innerHTML = '<a href="/auth">Sign In / Create Account</a>';
                sidebar.classList.remove('logged-in'); // Hide logout when signed out
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

        logoutSidebar.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('[DEBUG] Logout initiated from sidebar, time=${new Date().toISOString()}');
            localStorage.removeItem('username');
            localStorage.removeItem('tier');
            localStorage.removeItem('size_limit');
            localStorage.removeItem('diamond_feature');
            localStorage.removeItem('csrfToken');
            console.log('[DEBUG] Local storage cleared');
            updateAuthStatus(); // Refresh auth status and hide logout
            window.location.href = '/auth';
        });

        // Section7: Payment Handling
        const handlePostPaymentRedirect = async () => {
            const urlParams = new URLSearchParams(window.location.search);
            const sessionId = urlParams.get('session_id');
            const tier = urlParams.get('tier');
            const hasDiamond = urlParams.get('has_diamond') === 'true';
            const tempId = urlParams.get('temp_id');
            const username = urlParams.get('username') || localStorage.getItem('username');
            const upgradeStatus = urlParams.get('upgrade');
            const message = urlParams.get('message');
            console.log(`[DEBUG] Handling post-payment redirect: session_id=${sessionId}, tier=${tier}, has_diamond=${hasDiamond}, temp_id=${tempId}, username=${username}, upgrade=${upgradeStatus}, message=${message}, time=${new Date().toISOString()}`);
            if (upgradeStatus) {
                usageWarning.textContent = message || (upgradeStatus === 'success' ? 'Tier upgrade completed' : 'Tier upgrade failed');
                usageWarning.classList.add(upgradeStatus === 'success' ? 'success' : 'error');
                console.log(`[DEBUG] Post-payment status: upgrade=${upgradeStatus}, message=${message}, time=${new Date().toISOString()}`);
                window.history.replaceState({}, document.title, '/ui');
                await fetchTierData(); // ID 8: Immediate feature update on redirect
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
                        console.error(`[ERROR] Invalid post-payment redirect: missing tier or temp_id, time=${new Date().toISOString()}`);
                        usageWarning.textContent = 'Error: Invalid payment redirect parameters';
                        usageWarning.classList.add('error');
                        return;
                    }
                    console.log(`[DEBUG] Fetching ${endpoint}?${query}, time=${new Date().toISOString()}`);
                    const response = await fetch(`${endpoint}?${query}`, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' },
                        credentials: 'include'
                    });
                    if (!response.ok) {
                        const errorData = await response.json().catch(() => ({}));
                        throw new Error(errorData.detail || `Failed to complete ${tempId ? 'Diamond audit' : 'tier upgrade'}`);
                    }
                    localStorage.setItem('username', username);
                    usageWarning.textContent = `Successfully completed ${tempId ? 'Diamond audit' : 'tier upgrade'}`;
                    usageWarning.classList.add('success');
                    console.log(`[DEBUG] Post-payment completed: endpoint=${endpoint}, time=${new Date().toISOString()}`);
                    await fetchTierData();
                    window.history.replaceState({}, document.title, '/ui');
                } catch (error) {
                    console.error(`[ERROR] Post-payment redirect error: ${error.message}, endpoint=${endpoint}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Error completing ${tempId ? 'Diamond audit' : 'tier upgrade'}: ${error.message}`;
                    usageWarning.classList.add('error');
                    if (error.message.includes('User not found') || error.message.includes('Please login')) {
                        console.log(`[DEBUG] Redirecting to /auth due to user not found, time=${new Date().toISOString()}`);
                        window.location.href = '/auth?redirect_reason=post_payment';
                    }
                }
            } else {
                console.warn(`[DEBUG] No post-payment redirect params found: session_id=${sessionId}, username=${username}, time=${new Date().toISOString()}`);
            }
        };

        handlePostPaymentRedirect();

        // Section8: Facet Preview
        const fetchFacetPreview = async (contractAddress, attempt = 1, maxAttempts = 3) => {
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
                    headers: {
                        'Accept': 'application/json',
                        'Cache-Control': 'no-cache'
                    },
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
                if (attempt < maxAttempts && !error.message.includes("Pro or Diamond tier")) {
                    console.log(`Retrying facet fetch in 1s...`);
                    setTimeout(() => fetchFacetPreview(contractAddress, attempt + 1, maxAttempts), 1000);
                } else {
                    facetWell.textContent = `Error loading facet preview: ${error.message}`;
                    facetWell.className = 'has-text-danger';
                    facetWell.setAttribute('aria-live', 'assertive');
                    if (error.message.includes("Pro or Diamond tier")) {
                        facetWell.innerHTML = `<p class="has-text-warning" aria-live="assertive">Diamond Pattern facet preview requires Pro tier or Diamond add-on. <a href="/upgrade">Upgrade now</a>.</p>`;
                    }
                }
            }
        };

        contractAddressInput?.addEventListener('input', (e) => {
            const address = e.target.value.trim();
            if (address && address.match(/^0x[a-fA-F0-9]{40}$/)) {
                fetchFacetPreview(address);
            } else {
                facetWell.textContent = '';
            }
        });

        // Section9: Tier Management
        const fetchTierData = async () => {
            try {
                const username = localStorage.getItem('username') || '';
                const url = username ? `/tier?username=${encodeURIComponent(username)}` : '/tier';
                const response = await fetch(url, {
                    headers: { 'Accept': 'application/json' },
                    credentials: 'include'
                });
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.detail || 'Failed to fetch tier data');
                }
                const data = await response.json();
                const { tier, size_limit, feature_flags, api_key, audit_count, audit_limit, has_diamond } = data;
                auditCount = audit_count;
                auditLimit = audit_limit;
                tierInfo.textContent = `Tier: ${tier.charAt(0).toUpperCase() + tier.slice(1)}${has_diamond ? ' + Diamond' : ''} (${size_limit === 'Unlimited' ? 'Unlimited audits' : `${auditCount}/${auditLimit} audits`})`;
                tierDescription.textContent = `${tier.charAt(0).toUpperCase() + tier.slice(1)}${has_diamond ? ' + Diamond' : ''} Tier: ${has_diamond ? 'Unlimited file size, full Diamond audits, fuzzing, priority support, NFT rewards' : tier === 'pro' ? 'Unlimited audits, Diamond add-on access ($50/mo), fuzzing, priority support' : tier === 'beginner' ? `Up to 10 audits, 1MB file size (${auditCount}/${auditLimit} remaining), priority support` : `Up to 3 audits, 1MB file size (${auditCount}/${auditLimit} remaining)`}`;
                sizeLimit.textContent = `Max file size: ${size_limit}`;
                features.textContent = `Features: ${has_diamond ? 'Diamond audits, Diamond Pattern previews, priority support, NFT rewards' : tier === 'pro' ? 'Diamond add-on access, standard audits, Diamond Pattern previews, fuzzing, priority support' : 'Standard audit features'}${feature_flags.predictions ? ', AI predictions' : ''}${feature_flags.onchain ? ', on-chain analysis' : ''}${feature_flags.reports ? ', exportable reports' : ''}${feature_flags.fuzzing ? ', fuzzing analysis' : ''}${feature_flags.priority_support ? ', priority support' : ''}${feature_flags.nft_rewards ? ', NFT rewards' : ''}`;
                usageWarning.textContent = tier === 'free' || tier === 'beginner' ? `${tier.charAt(0).toUpperCase() + tier.slice(1)} tier: ${auditCount}/${auditLimit} audits remaining` : '';
                usageWarning.classList.remove('error');
                upgradeLink.style.display = !has_diamond ? 'inline-block' : 'none';
                maxFileSize = size_limit === 'Unlimited' ? Infinity : parseFloat(size_limit.replace('MB', '')) * 1024 * 1024;
                document.querySelector('#file-help').textContent = `Max size: ${size_limit}. Ensure code is valid Solidity.`;
                document.querySelectorAll('.pro-diamond-only').forEach(el => el.style.display = tier === 'pro' || has_diamond ? 'block' : 'none');
                customReportInput.style.display = tier === 'pro' || has_diamond ? 'block' : 'none';
                downloadReportButton.style.display = feature_flags.reports ? 'block' : 'none';
                document.querySelectorAll('.diamond-only').forEach(el => el.style.display = has_diamond ? 'block' : 'none');
                document.querySelector('.remediation-placeholder').style.display = has_diamond ? 'block' : 'none';
                document.querySelector('.fuzzing-placeholder').style.display = feature_flags.fuzzing ? 'block' : 'none';
                document.querySelector('.priority-support').style.display = feature_flags.priority_support ? 'block' : 'none';
                apiKeySpan.textContent = api_key || 'N/A';
                document.getElementById('api-key').style.display = api_key ? 'block' : 'none';
                console.log(`[DEBUG] Tier data fetched: tier=${tier}, has_diamond=${has_diamond}, auditCount=${auditCount}, auditLimit=${auditLimit}, time=${new Date().toISOString()}`);
            } catch (error) {
                console.error('Tier fetch error:', error);
                usageWarning.textContent = `Error fetching tier data: ${error.message}`;
                usageWarning.classList.add('error');
            }
        };

        tierSwitchButton?.addEventListener('click', () => {
            withCsrfToken(async (token) => {
                if (!token) {
                    usageWarning.textContent = 'Unable to establish secure connection.';
                    usageWarning.classList.add('error');
                    console.error(`[ERROR] No CSRF token for tier switch, time=${new Date().toISOString()}`);
                    return;
                }
                const selectedTier = tierSelect?.value;
                if (!selectedTier) {
                    console.error(`[ERROR] tierSelect element not found, time=${new Date().toISOString()}`);
                    usageWarning.textContent = 'Error: Tier selection unavailable';
                    usageWarning.classList.add('error');
                    return;
                }
                if (!['beginner', 'pro', 'diamond'].includes(selectedTier)) {
                    console.error(`[ERROR] Invalid tier selected: ${selectedTier}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Error: Invalid tier '${selectedTier}'. Choose beginner, pro, or diamond`;
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
                const effectiveTier = selectedTier === 'diamond' ? 'pro' : selectedTier;
                console.log(`[DEBUG] Initiating tier switch: username=${username}, tier=${effectiveTier}, has_diamond=${hasDiamond}, time=${new Date().toISOString()}`);
                try {
                    const requestBody = JSON.stringify({
                        username: username,
                        tier: effectiveTier,
                        has_diamond: hasDiamond,
                        csrf_token: token
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
                    console.log(`[DEBUG] Redirecting to Stripe for Diamond audit, session_url=${data.session_url}, time=${new Date().toISOString()}`);
                    window.location.href = data.session_url;
                } catch (error) {
                    console.error(`[ERROR] Diamond audit error: ${error.message}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Error initiating Diamond audit: ${error.message}`;
                    usageWarning.classList.add('error');
                }
            });
        });

        // Section11: Audit Handling
        const handleAuditResponse = (data) => {
            const report = data.report;
            const overageCost = data.overage_cost;
            riskScoreSpan.textContent = report.risk_score;
            riskScoreSpan.parentElement.setAttribute('aria-live', 'polite');
            issuesBody.innerHTML = '';
            if (report.issues.length === 0) {
                issuesBody.innerHTML = '<tr><td colspan="4">No issues found.</td></tr>';
            } else {
                report.issues.forEach((issue, index) => {
                    const row = document.createElement('tr');
                    row.setAttribute('tabindex', '0');
                    row.innerHTML = `
                        <td>${issue.type}</td>
                        <td>${issue.severity}</td>
                        <td>${issue.description || 'N/A'}</td>
                        <td>${issue.fix}</td>
                    `;
                    issuesBody.appendChild(row);
                });
            }
            predictionsList.innerHTML = '';
            if (report.predictions.length === 0) {
                predictionsList.innerHTML = '<li>No predictions available.</li>';
            } else {
                report.predictions.forEach(prediction => {
                    const li = document.createElement('li');
                    li.textContent = `Scenario: ${prediction.scenario} | Impact: ${prediction.impact}`;
                    li.setAttribute('tabindex', '0');
                    predictionsList.appendChild(li);
                });
            }
            recommendationsList.innerHTML = '';
            if (report.recommendations.length === 0) {
                recommendationsList.innerHTML = '<li>No recommendations available.</li>';
            } else {
                report.recommendations.forEach(rec => {
                    const li = document.createElement('li');
                    li.textContent = rec;
                    li.setAttribute('tabindex', '0');
                    recommendationsList.appendChild(li);
                });
            }
            fuzzingList.innerHTML = '';
            if (report.fuzzing_results.length === 0) {
                fuzzingList.innerHTML = '<li>No fuzzing results available.</li>';
            } else {
                report.fuzzing_results.forEach(result => {
                    const li = document.createElement('li');
                    li.textContent = `Vulnerability: ${result.vulnerability} | Description: ${result.description}`;
                    li.setAttribute('tabindex', '0');
                    fuzzingList.appendChild(li);
                });
            }
            if (remediationRoadmap && report.remediation_roadmap) {
                remediationRoadmap.textContent = report.remediation_roadmap;
            }
            if (overageCost) {
                usageWarning.textContent = `Diamond audit completed with $${overageCost.toFixed(2)} overage charged.`;
                usageWarning.classList.add('success');
            }
            loading.classList.remove('show');
            resultsDiv.classList.add('show');
            loading.setAttribute('aria-hidden', 'true');
            resultsDiv.setAttribute('aria-hidden', 'false');
            resultsDiv.focus();
            // Elegant scroll to results
            resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
            console.log(`[DEBUG] Audit results displayed and scrolled to, risk_score=${report.risk_score}, overage_cost=${overageCost}, time=${new Date().toISOString()}`);
        };

        const handleSubmit = (event) => {
            event.preventDefault();
            withCsrfToken(async (token) => {
                if (!token) {
                    loading.classList.remove('show');
                    usageWarning.textContent = 'Unable to establish secure connection.';
                    usageWarning.classList.add('error');
                    console.error(`[ERROR] No CSRF token for audit, time=${new Date().toISOString()}`);
                    return;
                }
                loading.classList.add('show');
                resultsDiv.classList.remove('show');
                usageWarning.textContent = '';
                usageWarning.classList.remove('error', 'success');
                loading.setAttribute('aria-hidden', 'false');
                resultsDiv.setAttribute('aria-hidden', 'true');
                const fileInput = auditForm.querySelector('#file');
                const file = fileInput.files[0];
                if (!file) {
                    loading.classList.remove('show');
                    usageWarning.textContent = 'Please select a file to audit';
                    usageWarning.classList.add('error');
                    console.error(`[ERROR] No file selected for audit, time=${new Date().toISOString()}`);
                    return;
                }
                const username = localStorage.getItem('username');
                if (!username) {
                    console.error(`[ERROR] No username found, redirecting to /auth, time=${new Date().toISOString()}`);
                    window.location.href = '/auth';
                    loading.classList.remove('show');
                    usageWarning.textContent = 'Please sign in to perform an audit';
                    usageWarning.classList.add('error');
                    return;
                }
                if (maxFileSize !== null && file.size > maxFileSize) {
                    loading.classList.remove('show');
                    const overageCost = calculateDiamondOverage(file);
                    usageWarning.textContent = `File size (${(file.size / 1024 / 1024).toFixed(2)}MB) exceeds ${maxFileSize === Infinity ? 'unlimited' : (maxFileSize / 1024 / 1024) + 'MB'} limit for your tier. Upgrade to Diamond add-on ($50/mo + $${overageCost.toFixed(2)} overage).`;
                    usageWarning.classList.add('error');
                    const upgradeButton = document.createElement('button');
                    upgradeButton.textContent = 'Upgrade to Pro + Diamond';
                    upgradeButton.className = 'upgrade-button';
                    upgradeButton.addEventListener('click', () => {
                        withCsrfToken(async (token) => {
                            if (!token) {
                                usageWarning.textContent = 'Unable to establish secure connection.';
                                usageWarning.classList.add('error');
                                console.error(`[ERROR] No CSRF token for upgrade, time=${new Date().toISOString()}`);
                                return;
                            }
                            try {
                                const requestBody = JSON.stringify({
                                    username: username,
                                    tier: 'pro',
                                    has_diamond: true,
                                    csrf_token: token
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
                                    throw new Error(errorData.detail || 'Failed to initiate tier upgrade');
                                }
                                const data = await response.json();
                                console.log(`[DEBUG] Redirecting to Stripe for Pro + Diamond upgrade due to file size, session_url=${data.session_url}, time=${new Date().toISOString()}`);
                                window.location.href = data.session_url;
                            } catch (error) {
                                console.error(`[ERROR] Upgrade error: ${error.message}, time=${new Date().toISOString()}`);
                                usageWarning.textContent = `Error initiating upgrade: ${error.message}`;
                                usageWarning.classList.add('error');
                            }
                        });
                    });
                    usageWarning.appendChild(upgradeButton);
                    return;
                }
                if (auditCount >= auditLimit) {
                    loading.classList.remove('show');
                    usageWarning.textContent = `Usage limit exceeded (${auditCount}/${auditLimit} audits). Upgrade your tier.`;
                    usageWarning.classList.add('error');
                    const upgradeButton = document.createElement('button');
                    upgradeButton.textContent = 'Upgrade to Beginner';
                    upgradeButton.className = 'upgrade-button';
                    upgradeButton.addEventListener('click', () => {
                        withCsrfToken(async (token) => {
                            if (!token) {
                                usageWarning.textContent = 'Unable to establish secure connection.';
                                usageWarning.classList.add('error');
                                console.error(`[ERROR] No CSRF token for upgrade, time=${new Date().toISOString()}`);
                                return;
                            }
                            try {
                                const requestBody = JSON.stringify({
                                    username: username,
                                    tier: 'beginner',
                                    has_diamond: false,
                                    csrf_token: token
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
                                    throw new Error(errorData.detail || 'Failed to initiate tier upgrade');
                                }
                                const data = await response.json();
                                console.log(`[DEBUG] Redirecting to Stripe for Beginner upgrade due to audit limit, session_url=${data.session_url}, time=${new Date().toISOString()}`);
                                window.location.href = data.session_url;
                            } catch (error) {
                                console.error(`[ERROR] Upgrade error: ${error.message}, time=${new Date().toISOString()}`);
                                usageWarning.textContent = `Error initiating upgrade: ${error.message}`;
                                usageWarning.classList.add('error');
                            }
                        });
                    });
                    usageWarning.appendChild(upgradeButton);
                    return;
                }
                const formData = new FormData(auditForm);
                formData.append('csrf_token', token);
                const loadingText = loading.querySelector('p');
                let stage = 0;
                const stages = ['Uploading...', 'Analyzing...', 'Generating Report...'];
                const interval = setInterval(() => {
                    if (stage < stages.length) {
                        loadingText.textContent = stages[stage];
                        stage++;
                    } else {
                        loadingText.textContent = 'Processing...';
                        stage = 0;
                    }
                }, 2000);

                // Add spinner and remove progress bar
                let spinner = loading.querySelector('.spinner');
                if (!spinner) {
                    spinner = document.createElement('div');
                    spinner.className = 'spinner';
                    loading.insertBefore(spinner, loadingText);
                }
                const progressBar = loading.querySelector('.progress-bar');
                if (progressBar) progressBar.remove();

                try {
                    console.log(`[DEBUG] Sending /audit request for username=${username}, time=${new Date().toISOString()}`);
                    const response = await fetch(`/audit?username=${encodeURIComponent(username)}`, {
                        method: 'POST',
                        headers: { 'X-CSRF-Token': token },
                        body: formData,
                        credentials: 'include'
                    });
                    console.log(`[DEBUG] /audit response status: ${response.status}, ok: ${response.ok}, headers: ${JSON.stringify([...response.headers])}, time=${new Date().toISOString()}`);
                    if (!response.ok) {
                        const errorData = await response.json().catch(() => ({}));
                        console.error(`[ERROR] /audit failed: status=${response.status}, detail=${errorData.detail || 'Unknown error'}, response_body=${JSON.stringify(errorData)}, time=${new Date().toISOString()}`);
                        if (errorData.session_url) {
                            console.log(`[DEBUG] Redirecting to Stripe for audit limit/file size upgrade, session_url=${errorData.session_url}, time=${new Date().toISOString()}`);
                            window.location.href = errorData.session_url;
                            return;
                        }
                        throw new Error(errorData.detail || 'Audit request failed');
                    }
                    const data = await response.json();
                    handleAuditResponse(data);
                    await fetchTierData();
                } catch (error) {
                    console.error(`[ERROR] Audit error: ${error.message}, time=${new Date().toISOString()}`);
                    loading.classList.remove('show');
                    usageWarning.textContent = `Error initiating audit: ${error.message}`;
                    usageWarning.classList.add('error');
                } finally {
                    clearInterval(interval);
                    loadingText.textContent = 'Complete';
                }
            });
        };
        auditForm?.addEventListener('submit', handleSubmit);

        // Section12: Report Download
        downloadReportButton?.addEventListener('click', () => {
            const reportData = {
                risk_score: riskScoreSpan.textContent,
                issues: Array.from(issuesBody.querySelectorAll('tr')).map(row => ({
                    type: row.cells[0].textContent,
                    severity: row.cells[1].textContent,
                    description: row.cells[2].textContent,
                    fix: row.cells[3].textContent
                })),
                predictions: Array.from(predictionsList.querySelectorAll('li')).map(li => ({
                    scenario: li.textContent.split(' | ')[0].replace('Scenario: ', ''),
                    impact: li.textContent.split(' | ')[1].replace('Impact: ', '')
                })),
                recommendations: Array.from(recommendationsList.querySelectorAll('li')).map(li => li.textContent),
                fuzzing_results: Array.from(fuzzingList.querySelectorAll('li')).map(li => ({
                    vulnerability: li.textContent.split(' | ')[0].replace('Vulnerability: ', ''),
                    description: li.textContent.split(' | ')[1].replace('Description: ', '')
                })),
                remediation_roadmap: remediationRoadmap?.textContent || null
            };
            const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `DeFiGuard_Audit_Report_${new Date().toISOString()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            console.log('[DEBUG] Report downloaded');
        });

       // Section13: Header Scroll Behavior (replace existing Section13)
window.addEventListener('scroll', () => {
    const header = document.querySelector('header');
    if (!header) return;
    if (window.scrollY > 100) {
        header.style.opacity = '0'; // Explicit fade out
        header.classList.add('scrolled');
        if (!header.classList.contains('visible')) header.classList.add('visible');
    } else {
        header.style.opacity = '1'; // Explicit fade in
        header.classList.remove('scrolled');
        header.classList.remove('visible');
    }
});