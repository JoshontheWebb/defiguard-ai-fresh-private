document.addEventListener('DOMContentLoaded', () => {
    const auditForm = document.querySelector('.audit-section form');
    const loading = document.querySelector('.loading');
    const resultsDiv = document.querySelector('.results');
    const riskScoreSpan = document.querySelector('#risk-score');
    const issuesBody = document.querySelector('#issues-body');
    const predictionsList = document.querySelector('#predictions-list');
    const recommendationsList = document.querySelector('#recommendations-list');
    const fuzzingList = document.querySelector('#fuzzing-list');
    const remediationRoadmap = document.querySelector('#remediation-roadmap');
    const usageWarning = document.querySelector('.usage-warning p');
    const tierInfo = document.querySelector('.tier-info span');
    const tierDescription = document.querySelector('#tier-description');
    const sizeLimit = document.querySelector('#size-limit');
    const features = document.querySelector('#features');
    const upgradeLink = document.querySelector('#upgrade-link');
    const tierSelect = document.querySelector('#tier-select');
    const tierSwitchButton = document.querySelector('#tier-switch');
    const contractAddressInput = document.getElementById('contract_address');
    const facetWell = document.getElementById('facet-preview');
    const downloadReportButton = document.getElementById('download-report');
    const diamondAuditButton = document.getElementById('diamond-audit');
    const customReportInput = document.getElementById('custom_report');
    const apiKeySpan = document.getElementById('api-key-value');
    const hamburger = document.getElementById('hamburger');
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.querySelector('.main-content');
    let maxFileSize = null;

    // Fetch CSRF token with retry
    const fetchCsrfToken = async (attempt = 1, maxAttempts = 3) => {
        try {
            const response = await fetch(`/csrf-token?_=${Date.now()}`, {
                method: 'GET',
                headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' },
                credentials: 'include'
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(`Failed to fetch CSRF token: ${errorData.detail || response.statusText}`);
            }
            const data = await response.json();
            if (!data.csrf_token || data.csrf_token === 'undefined') {
                throw new Error('Invalid CSRF token received');
            }
            localStorage.setItem('csrfToken', data.csrf_token);
            console.log(`[DEBUG] CSRF token fetched and stored: ${data.csrf_token}, time=${new Date().toISOString()}`);
            return data.csrf_token;
        } catch (error) {
            console.error(`[ERROR] CSRF token fetch error (attempt ${attempt}/${maxAttempts}): ${error.message}`);
            if (attempt < maxAttempts) {
                console.log(`Retrying CSRF token fetch in 1s...`);
                await new Promise(resolve => setTimeout(resolve, 1000));
                return fetchCsrfToken(attempt + 1, maxAttempts);
            }
            usageWarning.textContent = `Error setting up secure connection: ${error.message}`;
            usageWarning.classList.add('error');
            throw error;
        }
    };

    // Wrapper to ensure CSRF token is available
    const withCsrfToken = async (fetchFn) => {
        let token = localStorage.getItem('csrfToken');
        if (!token || token === 'undefined') {
            console.log(`[DEBUG] No valid CSRF token in localStorage, fetching new token, time=${new Date().toISOString()}`);
            token = await fetchCsrfToken();
        }
        return fetchFn(token);
    };

    // Calculate Diamond audit price
    const calculateDiamondPrice = (file) => {
        if (!file) {
            document.getElementById('diamond-price').style.display = 'none';
            return;
        }
        const size = file.size;
        const price = size < 10 * 1024 ? 5000 : size < 50 * 1024 ? 10000 : size < 100 * 1024 ? 15000 : 25000;
        const priceElement = document.getElementById('diamond-price');
        priceElement.textContent = `Diamond Audit Cost: $${price} for ${(size / 1024 / 1024).toFixed(2)}MB`;
        priceElement.style.display = 'block';
        console.log(`[DEBUG] Diamond price calculated: $${price} for ${size} bytes, time=${new Date().toISOString()}`);
    };

    // Fetch CSRF token
    fetchCsrfToken();

    // File input listener for price calculation
    document.getElementById('file').addEventListener('change', (event) => {
        const file = event.target.files[0];
        calculateDiamondPrice(file);
    });

    // Hamburger menu initialization
    console.log(`[DEBUG] Initializing hamburger menu: hamburger=${!!hamburger}, sidebar=${!!sidebar}, mainContent.marginLeft=${mainContent?.style.marginLeft || 'unknown'}, time=${new Date().toISOString()}`);
    if (hamburger && sidebar && mainContent) {
        hamburger.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            hamburger.classList.toggle('open');
            console.log(`[DEBUG] Hamburger menu toggled: sidebar.open=${sidebar.classList.contains('open')}, mainContent.marginLeft=${mainContent.style.marginLeft || getComputedStyle(mainContent).marginLeft}, time=${new Date().toISOString()}`);
        });
    } else {
        console.error('[ERROR] Hamburger, sidebar, or main-content elements not found:', { hamburger: !!hamburger, sidebar: !!sidebar, mainContent: !!mainContent });
    }

    // Auth status update
    const updateAuthStatus = () => {
        const username = localStorage.getItem('username');
        const authStatus = document.querySelector('#auth-status');
        console.log(`[DEBUG] updateAuthStatus: username=${username}, localStorage=${JSON.stringify(localStorage)}, time=${new Date().toISOString()}`);
        if (!authStatus) {
            console.error('[ERROR] #auth-status not found in DOM');
            return;
        }
        authStatus.textContent = username ? `Signed in as ${username}` : 'Sign In / Create Account';
        if (!username) {
            authStatus.innerHTML = '<a href="/auth">Sign In / Create Account</a>';
        }
    };

    // Storage listener
    window.addEventListener('storage', () => {
        console.log('[DEBUG] Storage event detected, re-running updateAuthStatus');
        updateAuthStatus();
    });

    // Periodic auth check
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

    // Auth update listener
    window.addEventListener('authUpdate', () => {
        console.log('[DEBUG] Custom authUpdate event detected, re-running updateAuthStatus');
        updateAuthStatus();
    });

    // Extended auth check
    setTimeout(() => {
        console.log(`[DEBUG] Extended auth check after load, username=${localStorage.getItem('username')}, time=${new Date().toISOString()}`);
        updateAuthStatus();
    }, 5000);

    // Persistent auth check
    setTimeout(() => {
        console.log(`[DEBUG] Persistent auth check, username=${localStorage.getItem('username')}, time=${new Date().toISOString()}`);
        updateAuthStatus();
    }, 10000);

    // Facet preview
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
            const username = localStorage.getItem('username');
            const response = await fetch(`/facets/${contractAddress}?username=${username || ''}&_=${Date.now()}`, {
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
                watermark.textContent = 'Pro Tier Preview – Upgrade to Diamond for Full Audit';
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
                    facetWell.innerHTML = `<p class="has-text-warning" aria-live="assertive">Diamond Pattern facet preview requires Pro or Diamond tier. <a href="/upgrade">Upgrade now</a>.</p>`;
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

    // Fetch tier data
    const fetchTierData = async () => {
        try {
            const username = localStorage.getItem('username');
            const url = username ? `/tier?username=${encodeURIComponent(username)}` : '/tier';
            const response = await fetch(url);
            if (!response.ok) throw new Error('Failed to fetch tier data');
            const data = await response.json();
            const { tier, size_limit, feature_flags, api_key } = data;
            tierInfo.textContent = `Tier: ${tier.charAt(0).toUpperCase() + tier.slice(1)} (${size_limit === 'Unlimited' ? 'Unlimited audits' : 'Limited audits'})`;
            tierDescription.textContent = `${tier.charAt(0).toUpperCase() + tier.slice(1)} Tier: ${tier === 'diamond' ? 'Unlimited file size, full Diamond audits, fuzzing' : tier === 'pro' ? 'Unlimited audits, Diamond audit access, fuzzing' : tier === 'beginner' ? 'Up to 10 audits, 1MB file size' : 'Up to 3 audits, 1MB file size'}`;
            sizeLimit.textContent = `Max file size: ${size_limit}`;
            features.textContent = `Features: ${feature_flags.diamond ? 'Diamond audit access, Diamond Pattern previews' : 'Standard audit features'}${feature_flags.predictions ? ', AI predictions' : ''}${feature_flags.onchain ? ', on-chain analysis' : ''}${feature_flags.reports ? ', exportable reports' : ''}${feature_flags.fuzzing ? ', fuzzing analysis' : ''}`;
            upgradeLink.style.display = tier !== 'diamond' ? 'inline-block' : 'none';
            maxFileSize = size_limit === 'Unlimited' ? Infinity : parseFloat(size_limit) * 1024 * 1024;
            document.querySelector('#file-help').textContent = `Max size: ${size_limit}. Ensure code is valid Solidity.`;
            document.querySelectorAll('.pro-diamond-only').forEach(el => el.style.display = tier === 'pro' || tier === 'diamond' ? 'block' : 'none');
            customReportInput.style.display = tier === 'pro' || tier === 'diamond' ? 'block' : 'none';
            downloadReportButton.style.display = feature_flags.reports ? 'block' : 'none';
            document.querySelectorAll('.diamond-only').forEach(el => el.style.display = feature_flags.diamond ? 'block' : 'none');
            document.querySelector('.remediation-placeholder').style.display = tier === 'diamond' ? 'block' : 'none';
            document.querySelector('.fuzzing-placeholder').style.display = feature_flags.fuzzing ? 'block' : 'none';
            document.querySelector('.priority-support').style.display = tier === 'beginner' || tier === 'pro' || tier === 'diamond' ? 'block' : 'none';
            apiKeySpan.textContent = api_key || 'N/A';
            document.getElementById('api-key').style.display = api_key ? 'block' : 'none';
        } catch (error) {
            usageWarning.textContent = `Error fetching tier data: ${error.message}`;
            usageWarning.classList.add('error');
            console.error('Tier fetch error:', error);
        }
    };

    // Handle tier switching
    tierSwitchButton?.addEventListener('click', () => {
        withCsrfToken(async (token) => {
            const selectedTier = tierSelect?.value;
            if (!selectedTier) {
                console.error('[ERROR] tierSelect element not found');
                return;
            }
            try {
                const username = localStorage.getItem('username');
                if (!username) throw new Error('Must be signed in to upgrade');
                const response = await fetch(`/set-tier/${username}/${selectedTier}`, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': token }
                });
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Failed to switch tier');
                }
                const data = await response.json();
                alert(data.message);
                await fetchTierData();
            } catch (error) {
                usageWarning.textContent = `Error switching tier: ${error.message}`;
                usageWarning.classList.add('error');
                console.error('Tier switch error:', error);
            }
        });
    });

    // Handle Diamond audit request
    diamondAuditButton?.addEventListener('click', () => {
        withCsrfToken(async (token) => {
            const fileInput = document.querySelector('#file');
            const file = fileInput.files[0];
            if (!file) {
                usageWarning.textContent = 'Please select a file for Diamond audit';
                usageWarning.classList.add('error');
                return;
            }
            const formData = new FormData();
            formData.append('file', file);
            formData.append('username', localStorage.getItem('username') || '');
            try {
                const response = await fetch(`/diamond-audit?username=${localStorage.getItem('username')}`, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': token },
                    body: formData
                });
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Diamond audit request failed');
                }
                const data = await response.json();
                alert(`Diamond audit purchased for $${data.price}`);
                handleAuditResponse(data.audit_result);
            } catch (error) {
                usageWarning.textContent = `Error: ${error.message}`;
                usageWarning.classList.add('error');
                console.error('Diamond audit error:', error);
            }
        });
    });

    // Handle audit form submission
    const handleAuditResponse = (data) => {
        const report = data.report;
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
        loading.classList.remove('show');
        resultsDiv.classList.add('show');
        loading.setAttribute('aria-hidden', 'true');
        resultsDiv.setAttribute('aria-hidden', 'false');
        resultsDiv.focus();
    };

    const handleSubmit = (event) => {
        event.preventDefault();
        withCsrfToken(async (token) => {
            loading.classList.add('show');
            resultsDiv.classList.remove('show');
            usageWarning.textContent = 'Free tier: Limited audits.';
            loading.setAttribute('aria-hidden', 'false');
            resultsDiv.setAttribute('aria-hidden', 'true');
            const fileInput = auditForm.querySelector('#file');
            const file = fileInput.files[0];
            if (file && maxFileSize !== null && file.size > maxFileSize) {
                loading.classList.remove('show');
                usageWarning.textContent = `File size (${(file.size / 1024 / 1024).toFixed(2)}MB) exceeds ${maxFileSize === Infinity ? 'unlimited' : (maxFileSize / 1024 / 1024) + 'MB'} limit for your tier.`;
                usageWarning.classList.add('error');
                return;
            }
            const formData = new FormData(auditForm);
            const username = localStorage.getItem('username');
            if (username) {
                formData.append('username', username);
            }
            try {
                const response = await fetch(`/audit?username=${username || ''}`, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': token },
                    body: formData
                });
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Audit request failed');
                }
                const data = await response.json();
                handleAuditResponse(data);
            } catch (error) {
                loading.classList.remove('show');
                usageWarning.textContent = error.message || 'Audit request failed';
                usageWarning.classList.add('error');
                console.error('Audit error:', error);
            }
        });
    };

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

    auditForm?.addEventListener('submit', handleSubmit);
    auditForm?.addEventListener('keypress', (event) => {
        if (event.key === 'Enter' && event.target.tagName !== 'BUTTON') {
            handleSubmit(event);
        }
    });

    // Initialize tier data
    fetchTierData();

    // Initialize auth status
    updateAuthStatus();
});