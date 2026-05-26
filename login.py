import re
import json
import hashlib
import os
import secrets
import binascii
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional


class LoginSystem:
    """Sistema de login seguro com validação e armazenamento de usuários"""

    def __init__(self, users_file: str = "users.json"):
        self.users_file = users_file
        self.users: Dict = self._load_users()
        self.recovery_codes: Dict = {}

    def _load_users(self) -> Dict:
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_users(self) -> None:
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=4, ensure_ascii=False)
        except IOError as e:
            print(f"Erro ao salvar usuários: {e}")

    @staticmethod
    def _hash_password(password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with PBKDF2-SHA256 and a random salt."""
        if salt is None:
            salt = binascii.hexlify(os.urandom(16)).decode()
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000)
        return binascii.hexlify(dk).decode(), salt

    def _verify_password(self, password: str, user: Dict) -> bool:
        """Verify password — supports both PBKDF2+salt and legacy plain SHA-256."""
        salt = user.get('salt')
        if salt:
            computed, _ = self._hash_password(password, salt)
            return computed == user['password']
        return hashlib.sha256(password.encode()).hexdigest() == user['password']

    def _upgrade_password_if_needed(self, username: str, password: str) -> None:
        """Migrate legacy SHA-256 hash to PBKDF2+salt on successful login."""
        user = self.users[username]
        if not user.get('salt'):
            new_hash, salt = self._hash_password(password)
            user['password'] = new_hash
            user['salt'] = salt
            self._save_users()

    @staticmethod
    def _validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def _validate_password(password: str) -> Tuple[bool, str]:
        if len(password) < 6:
            return False, "A senha deve ter pelo menos 6 caracteres"
        if not any(c.isupper() for c in password):
            return False, "A senha deve conter pelo menos uma letra maiúscula"
        if not any(c.isdigit() for c in password):
            return False, "A senha deve conter pelo menos um número"
        return True, "Senha válida"

    @staticmethod
    def _validate_username(username: str) -> Tuple[bool, str]:
        if len(username) < 3:
            return False, "O nome de usuário deve ter pelo menos 3 caracteres"
        if len(username) > 20:
            return False, "O nome de usuário não pode ter mais de 20 caracteres"
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "O nome de usuário pode conter apenas letras, números e '_'"
        return True, "Nome de usuário válido"

    def get_attempts(self, username: str) -> int:
        if username not in self.users:
            return 0
        return self.users[username].get('attempts', 0)

    def register(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        is_valid, msg = self._validate_username(username)
        if not is_valid:
            return False, msg

        if not self._validate_email(email):
            return False, "Email inválido"

        is_valid, msg = self._validate_password(password)
        if not is_valid:
            return False, msg

        if username in self.users:
            return False, "Nome de usuário já existe"

        if any(u['email'] == email for u in self.users.values()):
            return False, "Email já cadastrado"

        hashed, salt = self._hash_password(password)
        self.users[username] = {
            'email': email,
            'password': hashed,
            'salt': salt,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'attempts': 0,
            'locked': False,
        }
        self._save_users()
        return True, f"Usuário '{username}' registrado com sucesso!"

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        if username not in self.users:
            return False, "Usuário não encontrado"

        user = self.users[username]

        if user['locked']:
            return False, "Conta bloqueada após 5 tentativas falhas. Use a recuperação de senha."

        if not self._verify_password(password, user):
            user['attempts'] += 1
            if user['attempts'] >= 5:
                user['locked'] = True
                self._save_users()
                return False, "Conta bloqueada após 5 tentativas falhas"
            self._save_users()
            return False, f"Senha incorreta ({user['attempts']}/5 tentativas)"

        self._upgrade_password_if_needed(username, password)
        user['last_login'] = datetime.now().isoformat()
        user['attempts'] = 0
        self._save_users()
        return True, f"Bem-vindo, {username}!"

    def set_security_questions(self, username: str, password: str, questions: Dict[str, str]) -> Tuple[bool, str]:
        if username not in self.users:
            return False, "Usuário não encontrado"

        user = self.users[username]
        if not self._verify_password(password, user):
            return False, "Senha incorreta"

        if len(questions) < 2:
            return False, "Defina pelo menos 2 perguntas de segurança"

        user['security_questions'] = {
            question: hashlib.sha256(answer.lower().encode()).hexdigest()
            for question, answer in questions.items()
        }
        self._save_users()
        return True, f"{len(questions)} perguntas de segurança definidas com sucesso!"

    def initiate_recovery(self, username: str, email: str) -> Tuple[bool, str, Optional[str]]:
        if username not in self.users:
            return False, "Usuário não encontrado", None

        user = self.users[username]
        if user['email'] != email:
            return False, "Email incorreto", None

        recovery_code = secrets.token_urlsafe(16)
        expiration = datetime.now() + timedelta(minutes=15)
        self.recovery_codes[recovery_code] = {
            'username': username,
            'expires_at': expiration.isoformat(),
            'verified': False,
        }
        return True, "Recuperação iniciada. Um link de redefinição foi gerado.", recovery_code

    def reset_password(self, recovery_code: str, new_password: str) -> Tuple[bool, str]:
        if recovery_code not in self.recovery_codes:
            return False, "Código de recuperação inválido"

        recovery = self.recovery_codes[recovery_code]

        if datetime.fromisoformat(recovery['expires_at']) < datetime.now():
            del self.recovery_codes[recovery_code]
            return False, "Código de recuperação expirado"

        is_valid, msg = self._validate_password(new_password)
        if not is_valid:
            return False, msg

        username = recovery['username']
        user = self.users[username]
        new_hash, salt = self._hash_password(new_password)
        user['password'] = new_hash
        user['salt'] = salt
        user['attempts'] = 0
        user['locked'] = False
        self._save_users()
        del self.recovery_codes[recovery_code]
        return True, "Senha redefinida com sucesso!"

    def verify_security_questions(self, recovery_code: str, answers: Dict[str, str]) -> Tuple[bool, str]:
        if recovery_code not in self.recovery_codes:
            return False, "Código de recuperação inválido"

        recovery = self.recovery_codes[recovery_code]
        if datetime.fromisoformat(recovery['expires_at']) < datetime.now():
            del self.recovery_codes[recovery_code]
            return False, "Código de recuperação expirado"

        username = recovery['username']
        user = self.users[username]

        if 'security_questions' not in user:
            return False, "Nenhuma pergunta de segurança configurada"

        stored_questions = user['security_questions']
        correct = sum(
            1 for q, stored_hash in stored_questions.items()
            if q in answers and hashlib.sha256(answers[q].lower().encode()).hexdigest() == stored_hash
        )

        if correct != len(stored_questions):
            return False, f"Respostas incorretas. {correct}/{len(stored_questions)} corretas"

        recovery['verified'] = True
        return True, "Perguntas de segurança respondidas corretamente!"

    def get_security_questions(self, username: str, email: str) -> Tuple[bool, list, Optional[str]]:
        if username not in self.users:
            return False, [], None

        user = self.users[username]
        if user['email'] != email:
            return False, [], None
        if 'security_questions' not in user:
            return False, [], None

        questions = list(user['security_questions'].keys())
        active_codes = [
            code for code, data in self.recovery_codes.items()
            if data['username'] == username and not data['verified']
        ]
        return True, questions, active_codes[0] if active_codes else None

    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        if username not in self.users:
            return False, "Usuário não encontrado"

        user = self.users[username]
        if not self._verify_password(old_password, user):
            return False, "Senha atual incorreta"

        is_valid, msg = self._validate_password(new_password)
        if not is_valid:
            return False, msg

        new_hash, salt = self._hash_password(new_password)
        user['password'] = new_hash
        user['salt'] = salt
        self._save_users()
        return True, "Senha alterada com sucesso!"

    def get_user_info(self, username: str) -> Optional[Dict]:
        if username not in self.users:
            return None
        user = self.users[username].copy()
        user.pop('password', None)
        user.pop('salt', None)
        return user

    def delete_user(self, username: str, password: str) -> Tuple[bool, str]:
        if username not in self.users:
            return False, "Usuário não encontrado"

        user = self.users[username]
        if not self._verify_password(password, user):
            return False, "Senha incorreta"

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
