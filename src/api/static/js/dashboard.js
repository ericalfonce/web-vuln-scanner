/**
 * Web Vulnerability Scanner Dashboard
 * Modern, clean UI with easy debugging
 */

// State management
const state = {
    scanResults: null,
    isScanning: false,
    lastScanTime: null
};

// DOM Elements
const scanForm = document.getElementById('scanForm');
const scanBtn = document.getElementById('scanBtn');
const resultsContainer = document.getElementById('resultsContainer');
const exportContainer = document.getElementById('exportContainer');
const exportBtn = document.getElementById('exportBtn');
const notification = document.getElementById('notification');

// Scanner mapping
const scannerMap = {
    'media_link': 'MediaLinkScanner',
    'xss': 'XSSScanner',
    'csrf': 'CSRFScanner',
    'auth': 'AuthenticationFlawsScanner',
    'deserialization': 'InsecureDeserializationScanner'
};

/**
 * Initialize event listeners
 */
function init() {
    scanForm.addEventListener('submit', handleScanSubmit);
    exportBtn.addEventListener('click', handleExport);
    console.log('✅ Dashboard initialized');
}

/**
 * Handle scan form submission
 */
async function handleScanSubmit(e) {
    e.preventDefault();
    
    if (state.isScanning) {
        showNotification('Scan already in progress...', 'info');
        return;
    }

    const target = document.getElementById('targetUrl').value.trim();
    const selectedScanners = Array.from(document.querySelectorAll('input[name="scanners"]:checked'))
        .map(cb => scannerMap[cb.value]);

    if (!target) {
        showNotification('Please enter a target URL or HTML content', 'error');
        return;
    }

    if (selectedScanners.length === 0) {
        showNotification('Please select at least one scanner', 'error');
        return;
    }

    startScan(target, selectedScanners);
}

/**
 * Execute scan
 */
async function startScan(target, scanners) {
    state.isScanning = true;
    scanBtn.disabled = true;
    
    // Show loading state
    const btnText = scanBtn.querySelector('.btn-text');
    const spinner = scanBtn.querySelector('.spinner');
    btnText.classList.add('hidden');
    spinner.classList.remove('hidden');
    
    showNotification('🔍 Scanning in progress...', 'info');
    
    try {
        // Call the scan API
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                scanners: scanners
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('📊 Scan response:', data);

        // Get results
        if (data.vulnerabilities) {
            displayResults(data.vulnerabilities, target);
            state.scanResults = data;
            state.lastScanTime = new Date();
            showNotification('✅ Scan completed successfully!', 'success');
        } else {
            showNotification('❌ No results returned from server', 'error');
        }

    } catch (error) {
        console.error('❌ Scan error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    } finally {
        // Reset button state
        state.isScanning = false;
        scanBtn.disabled = false;
        btnText.classList.remove('hidden');
        spinner.classList.add('hidden');
    }
}

/**
 * Display scan results
 */
function displayResults(vulnerabilities, target) {
    console.log(`📈 Displaying ${vulnerabilities.length} vulnerabilities`);

    // Clear previous results
    resultsContainer.innerHTML = '';
    exportContainer.classList.remove('hidden');

    if (vulnerabilities.length === 0) {
        resultsContainer.innerHTML = `
            <div class="no-vulnerabilities">
                <p>🎉 No vulnerabilities found!</p>
                <p style="font-size: 0.85rem; margin-top: 0.5rem;">Target appears to be secure.</p>
            </div>
        `;
        updateStats({ vulnerabilities: [] });
        return;
    }

    // Group vulnerabilities by severity
    const grouped = groupBySeverity(vulnerabilities);

    // Display results
    vulnerabilities.forEach((vuln, index) => {
        const item = createVulnerabilityItem(vuln);
        resultsContainer.appendChild(item);
        
        // Stagger animation
        setTimeout(() => {
            item.style.opacity = '1';
        }, index * 50);
    });

    // Update statistics
    updateStats({ vulnerabilities });
}

/**
 * Create vulnerability item element
 */
function createVulnerabilityItem(vuln) {
    const severity = vuln.severity || 'medium';
    
    const item = document.createElement('div');
    item.className = `vulnerability-item ${severity}`;
    item.style.opacity = '0';
    item.style.transition = 'opacity 0.3s ease-out';

    const url = vuln.url || 'N/A';
    const issue = (vuln.issue || 'Unknown').replace(/_/g, ' ').toUpperCase();
    const description = vuln.description || vuln.context || '';

    item.innerHTML = `
        <div class="vulnerability-header">
            <div class="vulnerability-title">${issue}</div>
            <span class="severity-badge ${severity}">${severity}</span>
        </div>
        <div class="vulnerability-url">${escapeHtml(url)}</div>
        ${description ? `<div class="vulnerability-description">${escapeHtml(description)}</div>` : ''}
    `;

    return item;
}

/**
 * Group vulnerabilities by severity
 */
function groupBySeverity(vulnerabilities) {
    return vulnerabilities.reduce((acc, vuln) => {
        const severity = vuln.severity || 'medium';
        if (!acc[severity]) acc[severity] = [];
        acc[severity].push(vuln);
        return acc;
    }, {});
}

/**
 * Update statistics footer
 */
function updateStats(data) {
    const vulns = data.vulnerabilities || [];
    
    const stats = {
        total: vulns.length,
        critical: vulns.filter(v => v.severity === 'critical').length,
        high: vulns.filter(v => v.severity === 'high').length,
        medium: vulns.filter(v => v.severity === 'medium').length
    };

    document.getElementById('scanCount').textContent = stats.total;
    document.getElementById('criticalCount').textContent = stats.critical;
    document.getElementById('highCount').textContent = stats.high;
    document.getElementById('mediumCount').textContent = stats.medium;

    console.log('📊 Stats updated:', stats);
}

/**
 * Export results as JSON
 */
function handleExport() {
    if (!state.scanResults) {
        showNotification('No results to export', 'error');
        return;
    }

    const dataStr = JSON.stringify(state.scanResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `scan-results-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    
    URL.revokeObjectURL(url);
    showNotification('✅ Results exported!', 'success');
    console.log('📥 Exported results');
}

/**
 * Show notification toast
 */
function showNotification(message, type = 'info') {
    notification.textContent = message;
    notification.className = `notification ${type}`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        notification.classList.add('hidden');
    }, 5000);
}

/**
 * Escape HTML to prevent XSS in display
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Log debug info
 */
function debugLog(msg, data = null) {
    console.log(`[WVS Dashboard] ${msg}`, data || '');
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', init);

// Export functions for debugging (accessible via browser console)
window.debugDashboard = {
    state,
    displayResults,
    showNotification,
    escapeHtml
};

console.log('🚀 Web Vulnerability Scanner Dashboard loaded');
console.log('💡 Tip: Use window.debugDashboard in console to debug');
