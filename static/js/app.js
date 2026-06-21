// ─── Toast notifications ──────────────────────────────────────────
function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

// ─── Modal helpers ────────────────────────────────────────────────
function closeModal() {
  document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
  document.getElementById('modal-overlay')?.classList.add('hidden');
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

// ─── Global fetch error handler ───────────────────────────────────
async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, options);
    if (res.status === 401 || res.status === 302) {
      window.location.href = '/login';
      return null;
    }
    return res;
  } catch (e) {
    showToast('خطای اتصال به سرور', 'error');
    return null;
  }
}

// ─── Format bytes ─────────────────────────────────────────────────
function formatBytes(bytes) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let n = bytes;
  for (const unit of units) {
    if (n < 1024) return `${n.toFixed(1)} ${unit}`;
    n /= 1024;
  }
  return `${n.toFixed(1)} PB`;
}

// ─── Relative time ────────────────────────────────────────────────
function relativeTime(isoString) {
  if (!isoString) return 'هرگز';
  const diff = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'همین الان';
  if (mins < 60) return `${mins} دقیقه پیش`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} ساعت پیش`;
  return `${Math.floor(hours / 24)} روز پیش`;
}

// ─── Loading state helper ─────────────────────────────────────────
function setLoading(btnId, spinnerId, loading) {
  const btn = document.getElementById(btnId);
  const spinner = document.getElementById(spinnerId);
  if (btn) btn.disabled = loading;
  if (spinner) spinner.classList.toggle('hidden', !loading);
}
