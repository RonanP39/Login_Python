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
    setTimeout(() => {
        alert.style.display = 'none';
    }, 5000);
}

function switchForm(formId) {
    document.querySelectorAll('.form-container').forEach((container) => {
        container.classList.remove('active');
    });

    document.querySelectorAll('.recovery-step').forEach((step) => {
        step.style.display = 'none';
    });

    document.getElementById(formId).classList.add('active');
    if (formId === 'recoveryForm') {
        document.getElementById('recoveryStep1').style.display = 'block';
    }
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
        password,
        securityQuestions: {}
    };

    saveUsers(users);
    showMessage(`Conta criada com sucesso para ${username}!`, 'success');
    switchForm('loginForm');
}

function handleSecurityQuestions(event) {
    event.preventDefault();

    const username = document.getElementById('secUsername').value.trim();
    const password = document.getElementById('secPassword').value;
    const questionInputs = Array.from(document.querySelectorAll('.security-question'));
    const answerInputs = Array.from(document.querySelectorAll('.security-answer'));
    const users = getStoredUsers();

    if (!username || !password) {
        showMessage('Preencha usuário e senha para configurar perguntas.', 'error');
        return;
    }

    if (!(username in users)) {
        showMessage('Usuário não encontrado.', 'error');
        return;
    }

    if (users[username].password !== password) {
        showMessage('Senha incorreta.', 'error');
        return;
    }

    const questions = {};
    for (let i = 0; i < questionInputs.length; i += 1) {
        const question = questionInputs[i].value.trim();
        const answer = answerInputs[i].value.trim();
        if (!question || !answer) {
            showMessage('Preencha todas as perguntas e respostas.', 'error');
            return;
        }
        questions[question] = answer;
    }

    users[username].securityQuestions = questions;
    saveUsers(users);
    showMessage('Perguntas de segurança configuradas com sucesso.', 'success');
    switchForm('loginForm');
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

    if (!users[username].securityQuestions || Object.keys(users[username].securityQuestions).length < 2) {
        showMessage('Configure perguntas de segurança antes de recuperar a senha.', 'error');
        return;
    }

    currentRecoveryToken = username;
    const questionsContainer = document.getElementById('questionsContainer');
    questionsContainer.innerHTML = '';

    Object.keys(users[username].securityQuestions).forEach((question, index) => {
        const block = document.createElement('div');
        block.classList.add('form-group');
        block.innerHTML = `
            <label>${question}</label>
            <input type="text" class="security-answer-recovery" placeholder="Resposta" required>
        `;
        questionsContainer.appendChild(block);
    });

    document.getElementById('recoveryStep1').style.display = 'none';
    document.getElementById('recoveryStep2').style.display = 'block';
}

function handleRecoveryQuestions() {
    const username = currentRecoveryToken;
    const users = getStoredUsers();

    if (!username || !(username in users)) {
        showMessage('Inicie o processo de recuperação novamente.', 'error');
        resetRecovery();
        return;
    }

    const answers = Array.from(document.querySelectorAll('.security-answer-recovery')).map((input) => input.value.trim());
    const questions = Object.keys(users[username].securityQuestions);

    if (answers.some((answer) => !answer)) {
        showMessage('Responda todas as perguntas.', 'error');
        return;
    }

    const allCorrect = questions.every((question, index) => users[username].securityQuestions[question] === answers[index]);
    if (!allCorrect) {
        showMessage('Respostas de segurança incorretas.', 'error');
        return;
    }

    document.getElementById('recoveryStep2').style.display = 'none';
    document.getElementById('recoveryStep3').style.display = 'block';
}

function handleNewPassword(event) {
    event.preventDefault();

    const username = currentRecoveryToken;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmNewPassword').value;
    const users = getStoredUsers();

    if (!username || !(username in users)) {
        showMessage('Inicie o processo de recuperação novamente.', 'error');
        resetRecovery();
        return;
    }

    if (!newPassword || !confirmPassword) {
        showMessage('Preencha a nova senha e a confirmação.', 'error');
        return;
    }

    if (newPassword !== confirmPassword) {
        showMessage('As senhas não coincidem.', 'error');
        return;
    }

    const passwordValidation = validatePassword(newPassword);
    if (passwordValidation) {
        showMessage(passwordValidation, 'error');
        return;
    }

    users[username].password = newPassword;
    saveUsers(users);
    showMessage('Senha alterada com sucesso.', 'success');
    currentRecoveryToken = null;
    switchForm('loginForm');
}

function resetRecovery() {
    currentRecoveryToken = null;
    document.getElementById('recoveryStep1').style.display = 'block';
    document.getElementById('recoveryStep2').style.display = 'none';
    document.getElementById('recoveryStep3').style.display = 'none';
    document.getElementById('recoveryUsername').value = '';
    document.getElementById('recoveryEmail').value = '';
    document.getElementById('questionsContainer').innerHTML = '';
}

switchForm('loginForm');
