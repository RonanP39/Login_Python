const formulario = document.getElementById('form-login');

formulario.addEventListener('submit', function (evento) {
    // Evita que a página recarregue ao enviar o formulário
    evento.preventDefault();

    // Captura os valores digitados
    const emailInput = document.getElementById('email').value;
    const senhaInput = document.getElementById('senha').value;

    // Validação básica
    if (emailInput === '' || senhaInput === '') {
        alert('Por favor, preencha todos os campos.');
        return;
    }

    // Exemplo de autenticação simulada (substitua pela sua chamada de API)
    if (emailInput === 'usuario@exemplo.com' && senhaInput === '123456') {
        alert('Login realizado com sucesso!');
        // window.location.href = 'painel.html'; // Redireciona o usuário
    } else {
        alert('E-mail ou senha incorretos.');
    }
});
