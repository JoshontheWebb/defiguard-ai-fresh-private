// Section1: DOM Handling
function waitForDOM(selectors, callback, maxAttempts = 20, interval = 200) {
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

// Debounce utility for hamburger menu
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

document.addEventListener('DOMContentLoaded', () => {
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
        let token;
        try {
            token = await fetchCsrfToken();
            console.log(`[DEBUG] Using CSRF token for POST: ${token}, type=${typeof token}, time=${new Date().toISOString()}`);
        } catch (error) {
            console.error(`[ERROR] Failed to fetch CSRF token for POST: ${error.message}, proceeding with null`);
            return fetchFn(null);
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
        authStatus: '#auth-status'
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

        // Section5: Hamburger Menu (optimized with debounce)
        console.log(`[DEBUG] Initializing hamburger menu: hamburger=${!!hamburger}, sidebar=${!!sidebar}, mainContent=${!!mainContent}, time=${new Date().toISOString()}`);
        if (hamburger && sidebar && mainContent) {
            const toggleHamburger = debounce((e) => {
                e.preventDefault();
                try {
                    sidebar.classList.toggle('open');
                    hamburger.classList.toggle('open');
                    mainContent.style.marginLeft = sidebar.classList.contains('open') ? '270px' : '0';
                    console.log(`[DEBUG] Hamburger menu toggled: open=${sidebar.classList.contains('open')}, margin=${mainContent.style.marginLeft}, time=${new Date().toISOString()}`);
                } catch (error) {
                    console.error(`[ERROR] Hamburger toggle failed: ${error.message}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Menu error: ${error.message}`;
                    usageWarning.classList.add('error');
                }
            }, 200); // 200ms debounce to prevent rapid clicks

            hamburger.addEventListener('click', toggleHamburger);
            hamburger.setAttribute('tabindex', '0');
            hamburger.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleHamburger(e);
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
                sidebar.classList.add('logged-in');
            } else {
                authStatus.innerHTML = '<a href="/auth">Sign In / Create Account</a>';
                sidebar.classList.remove('logged-in');
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
                console.log('[DEBUG] Stopped periodic auth checks');
            }
        }, 1000);

        // Section7: Tier Data Fetch (with polling)
        const fetchTierData = async () => {
            const username = localStorage.getItem('username');
            if (!username) {
                console.log('[DEBUG] No username, skipping tier fetch');
                return;
            }
            tierInfo.classList.add('loading'); // Show loading state
            try {
                const response = await fetch(`/tier?username=${encodeURIComponent(username)}`, {
                    headers: { 'Accept': 'application/json' },
                    credentials: 'include'
                });
                if (!response.ok) {
                    console.error(`[ERROR] Failed to fetch tier: ${response.status}`);
                    throw new Error('Failed to fetch tier information');
                }
                const data = await response.json();
                console.log(`[DEBUG] Tier data: ${JSON.stringify(data)}`);
                tierInfo.textContent = `Tier: ${data.tier.charAt(0).toUpperCase() + data.tier.slice(1)} (${data.audit_count}/${data.audit_limit} audits)`;
                tierDescription.textContent = data.tier_description;
                sizeLimit.textContent = `Max file size: ${data.size_limit}`;
                features.textContent = `Features: ${data.features.join(', ')}`;
                auditCount = data.audit_count;
                auditLimit = data.audit_limit;
                maxFileSize = parseFloat(data.size_limit) * 1024 * 1024;
                localStorage.setItem('tier', data.tier);
                localStorage.setItem('size_limit', data.size_limit);
                localStorage.setItem('diamond_feature', JSON.stringify(data.feature_flags.diamond));
                if (data.tier === 'pro' || data.tier === 'diamond') {
                    contractAddressInput.style.display = 'block';
                    document.querySelectorAll('.pro-diamond-only').forEach(el => el.style.display = 'block');
                    if (data.tier === 'diamond') {
                        diamondAuditButton.style.display = 'block';
                        document.querySelectorAll('.diamond-only').forEach(el => el.style.display = 'block');
                    }
                }
                if (data.tier !== 'free') {
                    downloadReportButton.style.display = 'block';
                    document.querySelector('.priority-support').style.display = 'block';
                }
                if (data.tier === 'pro') {
                    apiKeySpan.textContent = data.api_key || 'N/A';
                    document.getElementById('api-key').style.display = 'block';
                }
            } catch (error) {
                console.error(`[ERROR] Tier fetch error: ${error.message}`);
                usageWarning.textContent = `Error fetching tier: ${error.message}`;
                usageWarning.classList.add('error');
            } finally {
                tierInfo.classList.remove('loading'); // Hide loading state
            }
        };

        // Start polling tier data every 10 seconds
        fetchTierData();
        setInterval(fetchTierData, 10000); // 10s polling

        // Section8: Facet Preview
        const updateFacetPreview = async () => {
            const username = localStorage.getItem('username');
            if (!username) {
                console.log('[DEBUG] No username, skipping facet preview');
                return;
            }
            try {
                const response = await fetch(`/facet-preview?username=${encodeURIComponent(username)}`, {
                    headers: { 'Accept': 'application/json' },
                    credentials: 'include'
                });
                if (!response.ok) {
                    console.error(`[ERROR] Failed to fetch facet preview: ${response.status}`);
                    throw new Error('Failed to fetch facet preview');
                }
                const data = await response.json();
                facetWell.innerHTML = data.html || '<p>No preview available.</p>';
            } catch (error) {
                console.error(`[ERROR] Facet preview error: ${error.message}`);
                facetWell.innerHTML = `<p>Error: ${error.message}</p>`;
            }
        };

        updateFacetPreview();

        // Section9: Tier Switching
        tierSwitchButton?.addEventListener('click', () => {
            const username = localStorage.getItem('username');
            if (!username) {
                usageWarning.textContent = 'Please sign in to upgrade your tier.';
                usageWarning.classList.add('error');
                return;
            }
            const selectedTier = tierSelect.value;
            withCsrfToken(async (token) => {
                if (!token) {
                    usageWarning.textContent = 'Unable to establish secure connection.';
                    usageWarning.classList.add('error');
                    console.error(`[ERROR] No CSRF token for upgrade, time=${new Date().toISOString()}`);
                    return;
                }
                try {
                    const response = await fetch('/create-tier-checkout', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': token,
                            'Accept': 'application/json'
                        },
                        credentials: 'include',
                        body: JSON.stringify({
                            username: username,
                            tier: selectedTier,
                            has_diamond: selectedTier === 'diamond',
                            csrf_token: token
                        })
                    });
                    console.log(`[DEBUG] /create-tier-checkout response status: ${response.status}, ok: ${response.ok}, headers: ${JSON.stringify([...response.headers])}, time=${new Date().toISOString()}`);
                    if (!response.ok) {
                        const errorData = await response.json().catch(() => ({}));
                        console.error(`[ERROR] /create-tier-checkout failed: status=${response.status}, detail=${errorData.detail || 'Unknown error'}, response_body=${JSON.stringify(errorData)}, time=${new Date().toISOString()}`);
                        throw new Error(errorData.detail || 'Failed to initiate tier upgrade');
                    }
                    const data = await response.json();
                    console.log(`[DEBUG] Redirecting to Stripe for ${selectedTier} upgrade, session_url=${data.session_url}, time=${new Date().toISOString()}`);
                    window.location.href = data.session_url;
                } catch (error) {
                    console.error(`[ERROR] Upgrade error: ${error.message}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Error initiating upgrade: ${error.message}`;
                    usageWarning.classList.add('error');
                }
            });
        });

        // Section10: Diamond Audit
        diamondAuditButton?.addEventListener('click', () => {
            const fileInput = document.getElementById('file');
            const file = fileInput?.files[0];
            const username = localStorage.getItem('username');
            if (!username) {
                usageWarning.textContent = 'Please sign in to request a Diamond audit.';
                usageWarning.classList.add('error');
                return;
            }
            if (!file) {
                usageWarning.textContent = 'Please select a file for audit.';
                usageWarning.classList.add('error');
                return;
            }
            withCsrfToken(async (token) => {
                if (!token) {
                    usageWarning.textContent = 'Unable to establish secure connection.';
                    usageWarning.classList.add('error');
                    console.error(`[ERROR] No CSRF token for Diamond audit, time=${new Date().toISOString()}`);
                    return;
                }
                const formData = new FormData();
                formData.append('file', file);
                formData.append('csrf_token', token);
                formData.append('username', username);
                try {
                    console.log(`[DEBUG] Sending /diamond-audit request for username=${username}, time=${new Date().toISOString()}`);
                    const response = await fetch('/diamond-audit', {
                        method: 'POST',
                        headers: { 'X-CSRF-Token': token },
                        body: formData,
                        credentials: 'include'
                    });
                    console.log(`[DEBUG] /diamond-audit response status: ${response.status}, ok: ${response.ok}, headers: ${JSON.stringify([...response.headers])}, time=${new Date().toISOString()}`);
                    if (!response.ok) {
                        const errorData = await response.json().catch(() => ({}));
                        console.error(`[ERROR] /diamond-audit failed: status=${response.status}, detail=${errorData.detail || 'Unknown error'}, response_body=${JSON.stringify(errorData)}, time=${new Date().toISOString()}`);
                        if (errorData.session_url) {
                            console.log(`[DEBUG] Redirecting to Stripe for Diamond audit upgrade, session_url=${errorData.session_url}, time=${new Date().toISOString()}`);
                            window.location.href = errorData.session_url;
                            return;
                        }
                        throw new Error(errorData.detail || 'Diamond audit request failed');
                    }
                    const data = await response.json();
                    console.log(`[DEBUG] Diamond audit response: ${JSON.stringify(data)}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = 'Diamond audit initiated successfully!';
                    usageWarning.classList.remove('error');
                    usageWarning.classList.add('success');
                } catch (error) {
                    console.error(`[ERROR] Diamond audit error: ${error.message}, time=${new Date().toISOString()}`);
                    usageWarning.textContent = `Error initiating Diamond audit: ${error.message}`;
                    usageWarning.classList.add('error');
                }
            });
        });

        // Section11: Audit Form Submission
        const handleAuditResponse = (data) => {
            console.log(`[DEBUG] Handling audit response: ${JSON.stringify(data)}, time=${new Date().toISOString()}`);
            loading.classList.remove('show');
            resultsDiv.innerHTML = `<p>Audit Results: ${JSON.stringify(data, null, 2)}</p>`;
            if (data.risk_score) {
                riskScoreSpan.textContent = `${data.risk_score}/100`;
            }
            if (data.issues?.length) {
                issuesBody.innerHTML = data.issues.map(issue => `
                    <tr>
                        <td>${issue.type}</td>
                        <td>${issue.severity}</td>
                        <td>${issue.description}</td>
                        <td>${issue.fix}</td>
                    </tr>
                `).join('');
            } else {
                issuesBody.innerHTML = '<tr><td colspan="4">No issues found.</td></tr>';
            }
            if (data.predictions?.length) {
                predictionsList.innerHTML = data.predictions.map(prediction => `
                    <li>Scenario: ${prediction.scenario} | Impact: ${prediction.impact}</li>
                `).join('');
            } else {
                predictionsList.innerHTML = '<li>No predictions available.</li>';
            }
            if (data.recommendations?.length) {
                recommendationsList.innerHTML = data.recommendations.map(rec => `<li>${rec}</li>`).join('');
            } else {
                recommendationsList.innerHTML = '<li>No recommendations available.</li>';
            }
            if (data.fuzzing_results?.length) {
                fuzzingList.innerHTML = data.fuzzing_results.map(result => `
                    <li>Vulnerability: ${result.vulnerability} | Description: ${result.description}</li>
                `).join('');
            } else {
                fuzzingList.innerHTML = '<li>No fuzzing results available.</li>';
            }
            if (data.remediation_roadmap) {
                remediationRoadmap.textContent = data.remediation_roadmap;
            } else {
                remediationRoadmap.textContent = 'No roadmap available.';
            }
            usageWarning.textContent = 'Audit completed successfully!';
            usageWarning.classList.remove('error');
            usageWarning.classList.add('success');
            auditCount++;
            tierInfo.textContent = `Tier: ${localStorage.getItem('tier')?.charAt(0).toUpperCase() + localStorage.getItem('tier')?.slice(1)} (${auditCount}/${auditLimit} audits)`;
        };

        const handleSubmit = async (e) => {
            e.preventDefault();
            const username = localStorage.getItem('username');
            if (!username) {
                loading.classList.remove('show');
                usageWarning.textContent = 'Please sign in to submit an audit.';
                usageWarning.classList.add('error');
                return;
            }
            const fileInput = document.getElementById('file');
            const file = fileInput?.files[0];
            if (!file) {
                loading.classList.remove('show');
                usageWarning.textContent = 'Please select a file for audit.';
                usageWarning.classList.add('error');
                return;
            }
            if (maxFileSize && file.size > maxFileSize) {
                loading.classList.remove('show');
                usageWarning.textContent = `File size exceeds limit (${(file.size / 1024 / 1024).toFixed(2)}MB > ${localStorage.getItem('size_limit')}). Upgrade to Pro or Diamond.`;
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

        // Section13: Header Scroll Behavior
        window.addEventListener('scroll', () => {
            const header = document.querySelector('header');
            if (!header) return;
            console.log(`[DEBUG] Header scroll triggered: scrollY=${window.scrollY}, time=${new Date().toISOString()}`);
            if (window.scrollY > 100) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
        }, { passive: true });
    });
});