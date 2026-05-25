import re
import json
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional

class LoginSystem:
    """Sistema de login seguro com validação e armazenamento de usuários"""
    
    def __init__(self, users_file: str = "users.json"):
        self.users_file = users_file
        self.users: Dict = self._load_users()
        self.recovery_codes: Dict = {}  # Armazena códigos de recuperação temporários
    
    def _load_users(self) -> Dict:
        """Carrega usuários do arquivo JSON"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def _save_users(self) -> None:
        """Salva usuários no arquivo JSON"""
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=4, ensure_ascii=False)
        except IOError as e:
            print(f"Erro ao salvar usuários: {e}")
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Criptografa a senha usando SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def _validate_email(email: str) -> bool:
        """Valida o formato do email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def _validate_password(password: str) -> Tuple[bool, str]:
        """Valida a força da senha"""
        if len(password) < 6:
            return False, "A senha deve ter pelo menos 6 caracteres"
        
        if not any(c.isupper() for c in password):
            return False, "A senha deve conter pelo menos uma letra maiúscula"
        
        if not any(c.isdigit() for c in password):
            return False, "A senha deve conter pelo menos um número"
        
        return True, "Senha válida"
    
    @staticmethod
    def _validate_username(username: str) -> Tuple[bool, str]:
        """Valida o nome de usuário"""
        if len(username) < 3:
            return False, "O nome de usuário deve ter pelo menos 3 caracteres"
        
        if len(username) > 20:
            return False, "O nome de usuário não pode ter mais de 20 caracteres"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "O nome de usuário pode conter apenas letras, números e '_'"
        
        return True, "Nome de usuário válido"
    
    def register(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """Registra um novo usuário"""
        # Validar nome de usuário
        is_valid_username, msg = self._validate_username(username)
        if not is_valid_username:
            return False, msg
        
        # Validar email
        if not self._validate_email(email):
            return False, "Email inválido"
        
        # Validar senha
        is_valid_password, msg = self._validate_password(password)
        if not is_valid_password:
            return False, msg
        
        # Verificar se usuário já existe
        if username in self.users:
            return False, "Nome de usuário já existe"
        
        # Verificar se email já foi registrado
        if any(user['email'] == email for user in self.users.values()):
            return False, "Email já cadastrado"
        
        # Registrar novo usuário
        self.users[username] = {
            'email': email,
            'password': self._hash_password(password),
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'attempts': 0,
            'locked': False
        }
        
        self._save_users()
        return True, f"Usuário '{username}' registrado com sucesso!"
    
    def set_security_questions(self, username: str, password: str, questions: Dict[str, str]) -> Tuple[bool, str]:
        """Define as perguntas de segurança para recuperação de senha"""
        if username not in self.users:
            return False, "Usuário não encontrado"
        
        user = self.users[username]
        
        # Verificar senha
        if user['password'] != self._hash_password(password):
            return False, "Senha incorreta"
        
        # Validar número de perguntas
        if len(questions) < 2:
            return False, "Defina pelo menos 2 perguntas de segurança"
        
        # Armazenar respostas criptografadas
        user['security_questions'] = {
            question: self._hash_password(answer.lower())
            for question, answer in questions.items()
        }
        
        self._save_users()
        return True, f"{len(questions)} perguntas de segurança definidas com sucesso!"
    
    def initiate_recovery(self, username: str, email: str) -> Tuple[bool, str, Optional[str]]:
        """Inicia o processo de recuperação de senha"""
        if username not in self.users:
            return False, "Usuário não encontrado", None
        
        user = self.users[username]
        
        # Verificar se o email corresponde
        if user['email'] != email:
            return False, "Email incorreto", None
        
        # Gerar código de recuperação e enviar o link por email (simulado)
        recovery_code = secrets.token_urlsafe(16)
        expiration = datetime.now() + timedelta(minutes=15)
        
        self.recovery_codes[recovery_code] = {
            'username': username,
            'expires_at': expiration.isoformat()
        }
        
        # Retornar o código (em produção, seria enviado por email)
        return True, "Recuperação iniciada. Um link de redefinição foi enviado ao email cadastrado.", recovery_code
    
    def verify_security_questions(self, recovery_code: str, answers: Dict[str, str]) -> Tuple[bool, str]:
        """Verifica as respostas às perguntas de segurança"""
        if recovery_code not in self.recovery_codes:
            return False, "Código de recuperação inválido"
        
        recovery = self.recovery_codes[recovery_code]
        
        # Verificar expiração
        if datetime.fromisoformat(recovery['expires_at']) < datetime.now():
            del self.recovery_codes[recovery_code]
            return False, "Código de recuperação expirado"
        
        username = recovery['username']
        user = self.users[username]
        
        # Verificar se tem perguntas definidas
        if 'security_questions' not in user:
            return False, "Nenhuma pergunta de segurança configurada"
        
        # Validar respostas
        stored_questions = user['security_questions']
        correct_answers = 0
        
        for question, stored_answer_hash in stored_questions.items():
            if question in answers:
                provided_answer_hash = self._hash_password(answers[question].lower())
                if stored_answer_hash == provided_answer_hash:
                    correct_answers += 1
        
        # Exigir que todas as perguntas sejam respondidas corretamente
        if correct_answers != len(stored_questions):
            return False, f"Respostas incorretas. {correct_answers}/{len(stored_questions)} corretas"
        
        # Marcar como verificado
        recovery['verified'] = True
        return True, "Perguntas de segurança respondidas corretamente!"
    
    def reset_password(self, recovery_code: str, new_password: str) -> Tuple[bool, str]:
        """Reseta a senha com um código de recuperação válido"""
        if recovery_code not in self.recovery_codes:
            return False, "Código de recuperação inválido"
        
        recovery = self.recovery_codes[recovery_code]
        
        # Verificar expiração
        if datetime.fromisoformat(recovery['expires_at']) < datetime.now():
            del self.recovery_codes[recovery_code]
            return False, "Código de recuperação expirado"
        
        # Validar nova senha
        is_valid, msg = self._validate_password(new_password)
        if not is_valid:
            return False, msg
        
        # Resetar senha
        username = recovery['username']
        user = self.users[username]
        user['password'] = self._hash_password(new_password)
        user['attempts'] = 0
        user['locked'] = False
        
        self._save_users()
        
        # Deletar código usado
        del self.recovery_codes[recovery_code]
        
        return True, "Senha resetada com sucesso!"
    
    def get_security_questions(self, username: str, email: str) -> Tuple[bool, list, Optional[str]]:
        """Retorna as perguntas de segurança para o usuário"""
        if username not in self.users:
            return False, [], None
        
        user = self.users[username]
        
        # Verificar email
        if user['email'] != email:
            return False, [], None
        
        # Verificar se tem perguntas
        if 'security_questions' not in user:
            return False, [], None
        
        # Retornar apenas as perguntas (não as respostas)
        questions = list(user['security_questions'].keys())
        recovery_code = [code for code, data in self.recovery_codes.items() 
                        if data['username'] == username and not data['verified']]
        
        return True, questions, recovery_code[0] if recovery_code else None
    
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Faz login de um usuário"""
        if username not in self.users:
            return False, "Usuário não encontrado"
        
        user = self.users[username]
        
        # Verificar se conta está bloqueada
        if user['locked']:
            return False, "Conta bloqueada. Tente mais tarde"
        
        # Verificar senha
        if user['password'] != self._hash_password(password):
            user['attempts'] += 1
            if user['attempts'] >= 5:
                user['locked'] = True
                self._save_users()
                return False, "Conta bloqueada após 5 tentativas falhas"
            
            self._save_users()
            return False, f"Senha incorreta ({user['attempts']}/5 tentativas)"
        
        # Login bem-sucedido
        user['last_login'] = datetime.now().isoformat()
        user['attempts'] = 0
        self._save_users()
        
        return True, f"Bem-vindo, {username}!"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Altera a senha do usuário"""
        if username not in self.users:
            return False, "Usuário não encontrado"
        
        user = self.users[username]
        
        # Verificar senha antiga
        if user['password'] != self._hash_password(old_password):
            return False, "Senha atual incorreta"
        
        # Validar nova senha
        is_valid, msg = self._validate_password(new_password)
        if not is_valid:
            return False, msg
        
        # Atualizar senha
        user['password'] = self._hash_password(new_password)
        self._save_users()
        
        return True, "Senha alterada com sucesso!"
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """Retorna informações do usuário (sem a senha)"""
        if username not in self.users:
            return None
        
        user = self.users[username].copy()
        user.pop('password', None)  # Remove a senha
        return user
    
    def delete_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Deleta a conta do usuário"""
        if username not in self.users:
            return False, "Usuário não encontrado"
        
        user = self.users[username]
        
        # Verificar senha
        if user['password'] != self._hash_password(password):
            return False, "Senha incorreta"
        
        # Deletar usuário
        del self.users[username]
        self._save_users()
        
        return True, "Conta deletada com sucesso"


def main():
    """Interface interativa do sistema de login"""
    system = LoginSystem()
    
    print("=" * 50)
    print("    BEM-VINDO AO SISTEMA DE LOGIN")
    print("=" * 50)
    
    while True:
        print("\n[1] Registrar")
        print("[2] Fazer Login")
        print("[3] Alterar Senha")
        print("[4] Ver Informações da Conta")
        print("[5] Deletar Conta")
        print("[6] Recuperar Senha")
        print("[7] Configurar Perguntas de Segurança")
        print("[8] Sair")
        
        choice = input("\nEscolha uma opção: ").strip()
        
        if choice == '1':
            print("\n--- REGISTRO ---")
            username = input("Nome de usuário: ").strip()
            email = input("Email: ").strip()
            password = input("Senha: ").strip()
            
            success, message = system.register(username, email, password)
            print(f"\n{'✓' if success else '✗'} {message}")
        
        elif choice == '2':
            print("\n--- LOGIN ---")
            username = input("Nome de usuário: ").strip()
            password = input("Senha: ").strip()
            
            success, message = system.login(username, password)
            print(f"\n{'✓' if success else '✗'} {message}")
        
        elif choice == '3':
            print("\n--- ALTERAR SENHA ---")
            username = input("Nome de usuário: ").strip()
            old_password = input("Senha atual: ").strip()
            new_password = input("Nova senha: ").strip()
            
            success, message = system.change_password(username, old_password, new_password)
            print(f"\n{'✓' if success else '✗'} {message}")
        
        elif choice == '4':
            print("\n--- INFORMAÇÕES DA CONTA ---")
            username = input("Nome de usuário: ").strip()
            
            user_info = system.get_user_info(username)
            if user_info:
                print(f"\nUsuário: {username}")
                for key, value in user_info.items():
                    print(f"  {key}: {value}")
            else:
                print("\n✗ Usuário não encontrado")
        
        elif choice == '5':
            print("\n--- DELETAR CONTA ---")
            username = input("Nome de usuário: ").strip()
            password = input("Senha: ").strip()
            
            confirm = input("Tem certeza? Digite 'sim' para confirmar: ").lower()
            if confirm == 'sim':
                success, message = system.delete_user(username, password)
                print(f"\n{'✓' if success else '✗'} {message}")
            else:
                print("\nOperação cancelada")
        
        elif choice == '6':
            print("\n--- RECUPERAR SENHA ---")
            username = input("Nome de usuário: ").strip()
            email = input("Email: ").strip()
            
            success, message, recovery_code = system.initiate_recovery(username, email)
            if success:
                assert recovery_code is not None
                print(f"\n✓ {message}")
                print(f"\nCódigo de recuperação: {recovery_code}")
                print("(Este código expirador em 15 minutos)")
                
                # Responder perguntas de segurança
                is_valid, questions, _ = system.get_security_questions(username, email)
                if is_valid:
                    print("\nResponda as seguintes perguntas:")
                    answers = {}
                    for question in questions:
                        answer = input(f"  {question}: ").strip()
                        answers[question] = answer
                    
                    success, msg = system.verify_security_questions(recovery_code, answers)
                    print(f"\n{'✓' if success else '✗'} {msg}")
                    
                    if success:
                        new_password = input("\nDigite a nova senha: ").strip()
                        success, msg = system.reset_password(recovery_code, new_password)
                        print(f"\n{'✓' if success else '✗'} {msg}")
            else:
                print(f"\n✗ {message}")
        
        elif choice == '7':
            print("\n--- CONFIGURAR PERGUNTAS DE SEGURANÇA ---")
            username = input("Nome de usuário: ").strip()
            password = input("Senha: ").strip()
            
            print("\nDefina 2 ou mais perguntas de segurança:")
            print("(Serão usadas para recuperação de senha)")
            
            num_questions = int(input("\nQuantas perguntas? (mín. 2): ").strip() or "2")
            if num_questions < 2:
                print("\n✗ Defina pelo menos 2 perguntas")
            else:
                questions = {}
                for i in range(num_questions):
                    question = input(f"\nPergunta {i+1}: ").strip()
                    answer = input(f"Resposta: ").strip()
                    questions[question] = answer
                
                success, message = system.set_security_questions(username, password, questions)
                print(f"\n{'✓' if success else '✗'} {message}")
        
        elif choice == '8':
            print("\nAté logo!")
            break
        
        else:
            print("\n✗ Opção inválida")


if __name__ == "__main__":
    main()
