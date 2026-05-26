'use strict';

let currentRecoveryToken = null;

// ========== API HELPER ==========
async function api(endpoint, body = null) {
    try {
        const opts = {
            method: body !== null ? 'POST' : 'GET',
            headers: { 'Content-Type': 'application/json' },
        };
        if (body !== null) opts.body = JSON.stringify(body);
        const res = await fetch(endpoint, opts);
        const data = await res.json();
        return { ok: res.ok, status: res.status, ...data };
    } catch {
        return { ok: false, message: 'Erro de conexão. Verifique se o servidor está rodando.' };
    }
}

// ========== INIT ==========
async function init() {
    applyTheme();
    const result = await api('/api/me');
    if (result.ok && result.user) {
        showDashboard(result.user);
    } else {
        switchForm('loginForm');
    }
}

// ========== AUTH HANDLERS ==========
async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const remember = document.getElementById('rememberMe').checked;

    setButtonLoading(event.target, true);
    const result = await api('/api/login', { username, password, remember });
    setButtonLoading(event.target, false);

    if (result.ok) {
        document.getElementById('attemptCounter').textContent = '';
        showMessage(result.message, 'success');
        showDashboard(result.user);
    } else {
        showMessage(result.message, 'error');
        updateAttemptCounter(result.attempts);
    }
}

async function handleRegister(event) {
    event.preventDefault();
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (password !== confirmPassword) {
        showMessage('As senhas não coincidem.', 'error');
        return;
    }

    setButtonLoading(event.target, true);
    const result = await api('/api/register', { username, email, password });
    setButtonLoading(event.target, false);

    showMessage(result.message, result.ok ? 'success' : 'error');
    if (result.ok) switchForm('loginForm');
}

async function handleRecoveryInit(event) {
    event.preventDefault();
    const username = document.getElementById('recoveryUsername').value.trim();
    const email = document.getElementById('recoveryEmail').value.trim();

    setButtonLoading(event.target, true);
    const result = await api('/api/recovery/init', { username, email });
    setButtonLoading(event.target, false);

    if (result.ok && result.token) {
        currentRecoveryToken = result.token;
        const safeEmail = escapeHtml(email);
        const safeToken = escapeHtml(result.token);
        document.getElementById('recoveryLinkDisplay').innerHTML = `
            <p class="small">Código simulado enviado para <strong>${safeEmail}</strong>:</p>
            <a href="#" onclick="applyRecoveryLink('${safeToken}'); return false;">
                https://example.com/redefinir-senha?token=${safeToken}
            </a>
        `;
        document.getElementById('recoveryMessage').textContent =
            `Link enviado para ${email}. Use o código ou clique no link.`;
        document.getElementById('recoveryStep1').style.display = 'none';
        document.getElementById('recoveryStep2').style.display = 'block';
    } else {
        showMessage(result.message, 'error');
    }
}

async function handleNewPassword(event) {
    event.preventDefault();
    const token = document.getElementById('recoveryToken').value.trim();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmNewPassword').value;

    if (newPassword !== confirmPassword) {
        showMessage('As senhas não coincidem.', 'error');
        return;
    }

    setButtonLoading(event.target, true);
    const result = await api('/api/recovery/reset', { token, new_password: newPassword });
    setButtonLoading(event.target, false);

    showMessage(result.message, result.ok ? 'success' : 'error');
    if (result.ok) {
        currentRecoveryToken = null;
        switchForm('loginForm');
    }
}

async function handleLogout() {
    await api('/api/logout', {});
    showMessage('Sessão encerrada com sucesso.', 'info');
    switchForm('loginForm');
}

// ========== DASHBOARD ==========
function showDashboard(user) {
    document.getElementById('dashboardAvatar').textContent =
        (user.username || 'U')[0].toUpperCase();
    document.getElementById('dashboardUsername').textContent = user.username || '';
    document.getElementById('dashboardEmail').textContent = user.email || '';
    document.getElementById('dashboardLastLogin').textContent =
        user.last_login ? formatDate(user.last_login) : 'Primeiro acesso';
    document.getElementById('dashboardCreatedAt').textContent =
        user.created_at ? formatDate(user.created_at) : '—';
    switchForm('dashboardForm');
}

function formatDate(iso) {
    try {
        return new Date(iso).toLocaleString('pt-BR', {
            day: '2-digit', month: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit',
        });
    } catch {
        return iso;
    }
}

// ========== ATTEMPT COUNTER ==========
function updateAttemptCounter(attempts) {
    const el = document.getElementById('attemptCounter');
    if (!el || attempts == null) return;
    if (attempts >= 5) {
        el.textContent = 'Conta bloqueada. Use a recuperação de senha.';
        el.className = 'attempt-counter blocked';
    } else if (attempts > 0) {
        el.textContent = `${attempts}/5 tentativas falhas — ${5 - attempts} restante(s).`;
        el.className = 'attempt-counter';
    } else {
        el.textContent = '';
    }
}

// ========== LOADING STATE ==========
function setButtonLoading(form, loading) {
    const btn = form.querySelector('button[type="submit"]');
    if (!btn) return;
    if (loading) {
        btn.dataset.label = btn.textContent;
        btn.textContent = '';
        btn.classList.add('btn--loading');
        btn.disabled = true;
    } else {
        btn.textContent = btn.dataset.label || btn.textContent;
        btn.classList.remove('btn--loading');
        btn.disabled = false;
    }
}

// ========== THEME ==========
function applyTheme() {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.getElementById('themeToggle');
    if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    document.getElementById('themeToggle').textContent = next === 'dark' ? '🌙' : '☀️';
}

// ========== UI HELPERS ==========
function showMessage(message, type = 'info') {
    const alert = document.getElementById('messageAlert');
    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.style.display = 'block';

    if (type === 'error') {
        const activeForm = document.querySelector('.form-container.active');
        if (activeForm) {
            activeForm.classList.add('shake');
            setTimeout(() => activeForm.classList.remove('shake'), 550);
        }
    }

    setTimeout(() => { alert.style.display = 'none'; }, 5000);
}

function switchForm(formId) {
    const current = document.querySelector('.form-container.active');
    const next = document.getElementById(formId);

    document.querySelectorAll('.recovery-step').forEach(step => step.style.display = 'none');
    if (formId === 'recoveryForm') {
        document.getElementById('recoveryStep1').style.display = 'block';
    }

    if (!current || current === next) {
        if (next) next.classList.add('active');
        return;
    }

    current.classList.add('flip-out');
    current.classList.remove('active');

    setTimeout(() => {
        current.classList.remove('flip-out');
        next.classList.add('active', 'flip-in');
        setTimeout(() => next.classList.remove('flip-in'), 300);
    }, 280);
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

function applyRecoveryLink(token) {
    const input = document.getElementById('recoveryToken');
    if (input) {
        input.value = token;
        showMessage('Código de recuperação preenchido automaticamente.', 'success');
    }
}

function resetRecovery() {
    currentRecoveryToken = null;
    document.getElementById('recoveryStep1').style.display = 'block';
    document.getElementById('recoveryStep2').style.display = 'none';
    document.getElementById('recoveryUsername').value = '';
    document.getElementById('recoveryEmail').value = '';
    const tokenInput = document.getElementById('recoveryToken');
    if (tokenInput) tokenInput.value = '';
    document.getElementById('recoveryLinkDisplay').innerHTML = '';
    document.getElementById('recoveryMessage').textContent =
        'Verifique seu email para encontrar o link de redefinição.';
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ========== STRENGTH INDICATOR ==========
function updateStrengthIndicator(password) {
    const bar = document.getElementById('strengthBar');
    const label = document.getElementById('strengthLabel');
    if (!bar || !label) return;

    let score = 0;
    if (password.length >= 6) score++;
    if (password.length >= 10) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    const levels = [
        { text: '', color: '#e5e7eb', width: '0%' },
        { text: 'Muito fraca', color: '#ef4444', width: '20%' },
        { text: 'Fraca', color: '#f97316', width: '40%' },
        { text: 'Média', color: '#eab308', width: '60%' },
        { text: 'Forte', color: '#22c55e', width: '80%' },
        { text: 'Muito forte', color: '#16a34a', width: '100%' },
    ];

    const level = levels[Math.min(score, 5)];
    bar.style.width = password.length ? level.width : '0%';
    bar.style.backgroundColor = password.length ? level.color : '#e5e7eb';
    label.textContent = password.length ? level.text : '';
    label.style.color = level.color;

    updateChecklist(password);
}

function updateChecklist(password) {
    const rules = {
        'check-length': password.length >= 6,
        'check-upper': /[A-Z]/.test(password),
        'check-number': /[0-9]/.test(password),
    };
    Object.entries(rules).forEach(([id, valid]) => {
        const item = document.getElementById(id);
        if (!item) return;
        item.classList.toggle('valid', valid);
        item.querySelector('.check-icon').textContent = valid ? '✓' : '✗';
    });
}

// ========== RIPPLE ==========
(function initRipple() {
    document.addEventListener('click', function (e) {
        const btn = e.target.closest('.btn');
        if (!btn) return;
        const ripple = document.createElement('span');
        ripple.classList.add('ripple');
        const rect = btn.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        ripple.style.width = ripple.style.height = size + 'px';
        ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
        ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';
        btn.appendChild(ripple);
        setTimeout(() => ripple.remove(), 600);
    });
}());

// ========== BOOT ==========
init();
