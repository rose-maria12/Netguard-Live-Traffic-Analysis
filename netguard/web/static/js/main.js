// NetGuard — Premium Dashboard Client Logic

// ============================================================
// Clipboard Copy
// ============================================================
function copyToClipboard(text, buttonElement) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function() {
            showCopyFeedback(buttonElement);
        }).catch(function() {
            fallbackCopyText(text, buttonElement);
        });
    } else {
        fallbackCopyText(text, buttonElement);
    }
}

function fallbackCopyText(text, buttonElement) {
    var textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
        showCopyFeedback(buttonElement);
    } catch (err) {
        console.error('Fallback copy failed', err);
    }
    document.body.removeChild(textArea);
}

function showCopyFeedback(buttonElement) {
    if (!buttonElement) return;
    var origText = buttonElement.innerText;
    buttonElement.innerText = "Copied";
    buttonElement.style.background = "#f0fdf4";
    buttonElement.style.color = "#15803d";
    buttonElement.style.borderColor = "#bbf7d0";
    setTimeout(function() {
        buttonElement.innerText = origText;
        buttonElement.style.background = "";
        buttonElement.style.color = "";
        buttonElement.style.borderColor = "";
    }, 1800);
}

// ============================================================
// Animated Bar Chart Rendering
// ============================================================
function renderBarChart(containerId, data, maxVal) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var barColors = ['bar-blue', 'bar-purple', 'bar-orange', 'bar-red', 'bar-pink', 'bar-green', 'bar-cyan'];
    var html = '<div class="chart-bar-group">';

    if (!maxVal || maxVal === 0) {
        maxVal = 1;
        data.forEach(function(d) {
            if (d.value > maxVal) maxVal = d.value;
        });
    }

    data.forEach(function(d, i) {
        var pct = Math.max(2, Math.min(100, (d.value / maxVal) * 100));
        var colorClass = d.color || barColors[i % barColors.length];
        html += '<div class="chart-bar-item">';
        html += '<div class="chart-bar-label">' + d.label + '</div>';
        html += '<div class="chart-bar-track">';
        html += '<div class="chart-bar-fill ' + colorClass + '" style="width:0%" data-width="' + pct + '%">' + d.value + '</div>';
        html += '</div></div>';
    });

    html += '</div>';
    container.innerHTML = html;

    // Animate bars on load
    setTimeout(function() {
        var fills = container.querySelectorAll('.chart-bar-fill');
        fills.forEach(function(fill) {
            fill.style.width = fill.getAttribute('data-width');
        });
    }, 100);
}

// ============================================================
// Donut Chart (CSS-based)
// ============================================================
function renderDonutChart(containerId, segments, centerValue, centerLabel) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var total = 0;
    segments.forEach(function(s) { total += s.value; });

    // Build conic-gradient
    var gradParts = [];
    var cumPct = 0;
    segments.forEach(function(s) {
        var pct = total > 0 ? (s.value / total) * 100 : 0;
        gradParts.push(s.color + ' ' + cumPct + '% ' + (cumPct + pct) + '%');
        cumPct += pct;
    });

    if (cumPct < 100) {
        gradParts.push('#ece8df ' + cumPct + '% 100%');
    }

    var gradient = 'conic-gradient(' + gradParts.join(', ') + ')';

    var html = '<div class="donut-container">';
    html += '<div class="donut-chart" style="background:' + gradient + '">';
    html += '<div class="donut-center" style="background:var(--bg-card);width:70%;height:70%;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;">';
    html += '<div class="donut-center-value">' + centerValue + '</div>';
    html += '<div class="donut-center-label">' + centerLabel + '</div>';
    html += '</div></div>';

    html += '<div class="donut-legend">';
    segments.forEach(function(s) {
        html += '<div class="donut-legend-item">';
        html += '<div class="donut-legend-dot" style="background:' + s.color + '"></div>';
        html += '<span>' + s.label + ': <strong>' + s.value + '</strong></span>';
        html += '</div>';
    });
    html += '</div></div>';

    container.innerHTML = html;
}

// ============================================================
// Upload Drag & Drop Enhancement
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
    var uploadZone = document.getElementById('upload-zone');
    var fileInput = document.getElementById('pcap-file-input');

    if (uploadZone && fileInput) {
        uploadZone.addEventListener('dragover', function(e) {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });
        uploadZone.addEventListener('dragleave', function() {
            uploadZone.classList.remove('dragover');
        });
        uploadZone.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                document.getElementById('upload-filename').textContent = e.dataTransfer.files[0].name;
                document.getElementById('upload-filename').style.display = 'block';
            }
        });
        uploadZone.addEventListener('click', function() {
            fileInput.click();
        });
        fileInput.addEventListener('change', function() {
            if (fileInput.files.length) {
                document.getElementById('upload-filename').textContent = fileInput.files[0].name;
                document.getElementById('upload-filename').style.display = 'block';
            }
        });
    }

    // Keep stat values crisp and immediate (no count-from-zero delay)
    document.querySelectorAll('.stat-value[data-count]').forEach(function(el) {
        el.textContent = el.getAttribute('data-count');
    });

    // Animate progress bars
    document.querySelectorAll('.progress-fill[data-width]').forEach(function(el) {
        setTimeout(function() {
            el.style.width = el.getAttribute('data-width');
        }, 300);
    });
});

// ============================================================
// Counter Animation
// ============================================================
function animateCounter(element, start, end, duration) {
    if (start === end) {
        element.textContent = end;
        return;
    }
    var range = end - start;
    var startTime = null;

    function step(timestamp) {
        if (!startTime) startTime = timestamp;
        var progress = Math.min((timestamp - startTime) / duration, 1);
        var ease = 1 - Math.pow(1 - progress, 3); // Ease out cubic
        element.textContent = Math.floor(start + range * ease);
        if (progress < 1) {
            requestAnimationFrame(step);
        } else {
            element.textContent = end;
        }
    }
    requestAnimationFrame(step);
}

// ============================================================
// Format Timestamps
// ============================================================
function formatTimestamp(ts) {
    if (!ts || ts <= 0) return '—';
    var d = new Date(ts * 1000);
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

// Format timestamps on page
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('[data-ts]').forEach(function(el) {
        el.textContent = formatTimestamp(parseFloat(el.getAttribute('data-ts')));
    });
});

// ============================================================
// Score circle animation
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.score-circle').forEach(function(el) {
        var score = parseFloat(el.getAttribute('data-score') || 0);
        setTimeout(function() {
            el.style.setProperty('--score-pct', score + '%');
        }, 200);
    });
});
