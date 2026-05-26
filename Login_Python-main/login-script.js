const STORAGE_KEY = 'secureLoginUsers';
let currentRecoveryToken = null;

function getStoredUsers() {
    try {
        const json = localStorage.getItem(STORAGE_KEY);
        return json ? JSON.parse(json) : {};
    } catch (error) {
        console.error('Erro ao ler usuários:', error);
        return {};
    }
}

function saveUsers(users) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(users));
}

function showMessage(message, type = 'info') {
    const alert = document.getElementById('messageAlert');
    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.style.display = 'block';

    if (type === 'error') {
        const activeForm = document.querySelector('.form-container.active');
        if (activeForm) {
            activeForm.classList.remove('shake');
            void activeForm.offsetWidth;
            activeForm.classList.add('shake');
            setTimeout(() => activeForm.classList.remove('shake'), 550);
        }
    }

    setTimeout(() => { alert.style.display = 'none'; }, 5000);
}

function switchForm(formId) {
    const current = document.querySelector('.form-container.active');
    const next = document.getElementById(formId);

    document.querySelectorAll('.recovery-step').forEach((step) => {
        step.style.display = 'none';
    });
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

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
    if (password.length < 6) {
        return 'A senha deve ter pelo menos 6 caracteres.';
    }
    if (!/[A-Z]/.test(password)) {
        return 'A senha deve conter pelo menos uma letra maiúscula.';
    }
    if (!/[0-9]/.test(password)) {
        return 'A senha deve conter pelo menos um número.';
    }
    return '';
}

function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const users = getStoredUsers();

    if (!username || !password) {
        showMessage('Preencha todos os campos para fazer login.', 'error');
        return;
    }

    if (!(username in users)) {
        showMessage('Usuário não encontrado.', 'error');
        return;
    }

    if (users[username].password !== password) {
        showMessage('Nome de usuário ou senha incorretos.', 'error');
        return;
    }

    showMessage(`Login realizado com sucesso! Bem-vindo, ${username}.`, 'success');
}

function handleRegister(event) {
    event.preventDefault();

    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const users = getStoredUsers();

    if (!username || !email || !password || !confirmPassword) {
        showMessage('Preencha todos os campos para se registrar.', 'error');
        return;
    }

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        showMessage('Nome de usuário inválido. Use 3-20 caracteres, letras, números ou _.', 'error');
        return;
    }

    if (!validateEmail(email)) {
        showMessage('Email inválido.', 'error');
        return;
    }

    const passwordValidation = validatePassword(password);
    if (passwordValidation) {
        showMessage(passwordValidation, 'error');
        return;
    }

    if (password !== confirmPassword) {
        showMessage('As senhas não coincidem.', 'error');
        return;
    }

    if (username in users) {
        showMessage('Nome de usuário já existe.', 'error');
        return;
    }

    if (Object.values(users).some((user) => user.email === email)) {
        showMessage('Email já cadastrado.', 'error');
        return;
    }

    users[username] = {
        email,
        password
    };

    saveUsers(users);
    showMessage(`Conta criada com sucesso para ${username}!`, 'success');
    switchForm('loginForm');
}

function generateRecoveryCode() {
    return Math.random().toString(36).substring(2, 8) + Math.random().toString(36).substring(2, 8);
}

function handleRecoveryInit(event) {
    event.preventDefault();

    const username = document.getElementById('recoveryUsername').value.trim();
    const email = document.getElementById('recoveryEmail').value.trim();
    const users = getStoredUsers();

    if (!username || !email) {
        showMessage('Preencha usuário e email para recuperar a senha.', 'error');
        return;
    }

    if (!(username in users) || users[username].email !== email) {
        showMessage('Usuário ou email incorreto.', 'error');
        return;
    }

    const recoveryToken = generateRecoveryCode();
    const expiration = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    users[username].recovery = {
        token: recoveryToken,
        expires_at: expiration
    };

    saveUsers(users);
    currentRecoveryToken = username;

    const linkDisplay = document.getElementById('recoveryLinkDisplay');
    linkDisplay.innerHTML = `
        <p class="small">Link simulado enviado para <strong>${email}</strong>:</p>
        <a href="#" onclick="applyRecoveryLink('${recoveryToken}')">https://example.com/redefinir-senha?token=${recoveryToken}</a>
    `;

    document.getElementById('recoveryMessage').textContent = `Link de redefinição enviado para ${email}. Use o código ou clique no link.`;
    document.getElementById('recoveryStep1').style.display = 'none';
    document.getElementById('recoveryStep2').style.display = 'block';
}

function applyRecoveryLink(token) {
    const tokenInput = document.getElementById('recoveryToken');
    if (tokenInput) {
        tokenInput.value = token;
        showMessage('Código de recuperação preenchido automaticamente.', 'success');
    }
}

function handleNewPassword(event) {
    event.preventDefault();

    const username = currentRecoveryToken;
    const recoveryToken = document.getElementById('recoveryToken').value.trim();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmNewPassword').value;
    const users = getStoredUsers();

    if (!username || !(username in users)) {
        showMessage('Inicie o processo de recuperação novamente.', 'error');
        resetRecovery();
        return;
    }

    if (!recoveryToken || !newPassword || !confirmPassword) {
        showMessage('Preencha todos os campos para redefinir a senha.', 'error');
        return;
    }

    if (newPassword !== confirmPassword) {
        showMessage('As senhas não coincidem.', 'error');
        return;
    }

    const recovery = users[username].recovery;
    if (!recovery || recovery.token !== recoveryToken) {
        showMessage('Código de recuperação inválido.', 'error');
        return;
    }

    if (new Date(recovery.expires_at) < new Date()) {
        showMessage('O código de recuperação expirou.', 'error');
        resetRecovery();
        return;
    }

    const passwordValidation = validatePassword(newPassword);
    if (passwordValidation) {
        showMessage(passwordValidation, 'error');
        return;
    }

    users[username].password = newPassword;
    delete users[username].recovery;
    saveUsers(users);
    showMessage('Senha alterada com sucesso.', 'success');
    currentRecoveryToken = null;
    switchForm('loginForm');
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
    document.getElementById('recoveryMessage').textContent = 'Verifique seu email para encontrar o link de redefinição.';
}

switchForm('loginForm');

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
