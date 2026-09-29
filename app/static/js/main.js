document.addEventListener('DOMContentLoaded', () => {
    const contentInput = document.getElementById('content-input');
    const btnAnalyze = document.getElementById('btn-analyze');
    const charCount = document.getElementById('char-count');
    const sampleContainer = document.getElementById('samples-container');
    const resultContainer = document.getElementById('result-container');
    const historyBody = document.getElementById('history-body');

    let currentAnalysisResult = null;

    // Update character counter
    if (contentInput) {
        contentInput.addEventListener('input', () => {
            const len = contentInput.value.length;
            charCount.textContent = `${len} characters`;
        });
    }

    // Load test samples
    fetchSamples();

    // Load initial history
    fetchHistory();

    // Submit content for analysis
    if (btnAnalyze) {
        btnAnalyze.addEventListener('click', analyzeContent);
    }

    function fetchSamples() {
        fetch('/api/samples')
            .then(res => res.json())
            .then(samples => {
                if (!sampleContainer) return;
                sampleContainer.innerHTML = '';
                samples.forEach(sample => {
                    const btn = document.createElement('button');
                    btn.className = 'btn-sample';
                    btn.textContent = sample.title;
                    btn.title = sample.description;
                    btn.addEventListener('click', () => {
                        document.querySelectorAll('.btn-sample').forEach(b => b.classList.remove('active'));
                        btn.classList.add('active');
                        contentInput.value = sample.content;
                        charCount.textContent = `${sample.content.length} characters`;
                        analyzeContent();
                    });
                    sampleContainer.appendChild(btn);
                });
            })
            .catch(err => console.error('Failed to load samples:', err));
    }

    function analyzeContent() {
        const content = contentInput.value;
        if (!content.trim()) {
            renderResults({
                risk_score: 0,
                risk_level: 'SAFE',
                recommended_action: 'ALLOW',
                summary: 'Content is empty or contains no readable text.',
                flagged_snippets: [],
                stats: { length: 0, lines: 0, patterns_flagged: 0 }
            });
            return;
        }

        btnAnalyze.disabled = true;
        btnAnalyze.textContent = 'Analyzing...';

        fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        })
        .then(res => res.json())
        .then(data => {
            currentAnalysisResult = data;
            renderResults(data);
        })
        .catch(err => {
            console.error('Analysis error:', err);
            alert('Analysis failed. Please try again.');
        })
        .finally(() => {
            btnAnalyze.disabled = false;
            btnAnalyze.textContent = 'Analyze Content';
        });
    }

    function renderResults(data) {
        if (!resultContainer) return;

        const level = data.risk_level;
        const score = data.risk_score;

        let snippetsHTML = '';
        if (data.flagged_snippets && data.flagged_snippets.length > 0) {
            snippetsHTML = `
                <div class="snippets-title">Flagged Instructions & Threat Vectors (${data.flagged_snippets.length})</div>
                ${data.flagged_snippets.map(s => `
                    <div class="snippet-item">
                        <div class="snippet-header">
                            <span>Line ${s.line} • ${escapeHTML(s.category)}</span>
                            <span>${s.severity}</span>
                        </div>
                        <div class="snippet-text">${escapeHTML(s.snippet)}</div>
                        <div class="snippet-expl">${escapeHTML(s.explanation)}</div>
                    </div>
                `).join('')}
            `;
        } else {
            snippetsHTML = `<div class="snippets-title">No suspicious patterns detected.</div>`;
        }

        resultContainer.innerHTML = `
            <div class="status-banner ${level}">
                <div>
                    <strong style="font-size: 1.1rem;">${level} CONTENT</strong>
                    <div style="font-size: 0.85rem; opacity: 0.9;">Recommended Action: <strong>${data.recommended_action}</strong></div>
                </div>
                <span class="risk-badge ${level}">${score}/100</span>
            </div>

            <div class="score-container">
                <div style="display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-muted);">
                    <span>Risk Assessment Meter</span>
                    <span>Score: ${score}%</span>
                </div>
                <div class="score-bar-bg">
                    <div class="score-bar-fill ${level}" style="width: ${score}%;"></div>
                </div>
            </div>

            <div class="summary-text">
                ${escapeHTML(data.summary)}
            </div>

            ${snippetsHTML}

            <div class="decision-panel">
                <div class="decision-title">Take Security Action:</div>
                <div class="decision-buttons">
                    <button class="btn-decision btn-allow" onclick="handleDecision('ALLOW')">✓ Allow Content</button>
                    <button class="btn-decision btn-isolate" onclick="handleDecision('ISOLATE')">⚠ Isolate / Review</button>
                    <button class="btn-decision btn-block" onclick="handleDecision('BLOCK')">⛔ Block Content</button>
                </div>
            </div>
        `;
    }

    window.handleDecision = function(action) {
        if (!currentAnalysisResult) return;

        const payload = {
            action: action,
            risk_level: currentAnalysisResult.risk_level,
            risk_score: currentAnalysisResult.risk_score,
            snippet_preview: contentInput.value.trim()
        };

        fetch('/api/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(res => res.json())
        .then(resData => {
            renderHistory(resData.history);
            alert(`Decision Recorded: [${action}] for content with risk score ${currentAnalysisResult.risk_score}.`);
        })
        .catch(err => console.error('Failed to log action:', err));
    };

    function fetchHistory() {
        fetch('/api/history')
            .then(res => res.json())
            .then(data => renderHistory(data))
            .catch(err => console.error('History fetch error:', err));
    }

    function renderHistory(historyList) {
        if (!historyBody) return;

        if (!historyList || historyList.length === 0) {
            historyBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No analysis actions logged yet.</td></tr>`;
            return;
        }

        historyBody.innerHTML = historyList.map(item => `
            <tr>
                <td>${item.timestamp}</td>
                <td><span class="risk-badge ${item.risk_level}" style="font-size: 0.75rem; padding: 2px 8px;">${item.risk_level} (${item.risk_score})</span></td>
                <td><strong>${item.action}</strong></td>
                <td style="font-family: monospace;">${escapeHTML(item.preview)}...</td>
            </tr>
        `).join('');
    }

    function escapeHTML(str) {
        if (!str) return '';
        return str.replace(/[&<>'"]/g, 
            tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                "'": '&#39;',
                '"': '&quot;'
            }[tag] || tag)
        );
    }
});
