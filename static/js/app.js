// ─── Toast notifications ──────────────────────────────────────────
function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ─── Modal helpers ────────────────────────────────────────────────
function closeModal() {
  document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
  document.getElementById('modal-overlay')?.classList.add('hidden');
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

// ─── CSRF token helper ────────────────────────────────────────────
function getCSRFToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

function csrfHeaders(extra = {}) {
  return { 'X-CSRF-Token': getCSRFToken(), ...extra };
}

// ─── Global fetch wrapper with CSRF + error handling ─────────────
async function apiFetch(url, options = {}) {
  // Add CSRF header for state-changing methods
  if (!['GET', 'HEAD', 'OPTIONS'].includes((options.method || 'GET').toUpperCase())) {
    options.headers = csrfHeaders(options.headers || {});
  }
  try {
    const res = await fetch(url, options);
    if (res.status === 401) {
      // Session expired — redirect to login
      window.location.href = '/login';
      return null;
    }
    if (res.status === 403) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || 'Permission denied', 'error');
      return null;
    }
    return res;
  } catch (e) {
    showToast('Connection error', 'error');
    return null;
  }
}

// ─── Format bytes ─────────────────────────────────────────────────
function formatBytes(bytes) {
  bytes = Number(bytes || 0);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  for (const unit of units) {
    if (bytes < 1024) return `${bytes.toFixed(1)} ${unit}`;
    bytes /= 1024;
  }
  return `${bytes.toFixed(1)} PB`;
}

// ─── Relative time ────────────────────────────────────────────────
function relativeTime(isoString) {
  if (!isoString) return '—';
  const diff = Date.now() - new Date(isoString).getTime();
  if (diff < 0) return 'future';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

// ─── Loading state helper ─────────────────────────────────────────
function setLoading(btnId, spinnerId, loading) {
  const btn = document.getElementById(btnId);
  const spinner = document.getElementById(spinnerId);
  if (btn) btn.disabled = loading;
  if (spinner) spinner.classList.toggle('hidden', !loading);
}

// ─── Escape HTML ──────────────────────────────────────────────────
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── Copy to clipboard ────────────────────────────────────────────
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(
    () => showToast('Copied to clipboard', 'success'),
    () => showToast('Failed to copy', 'error')
  );
}
