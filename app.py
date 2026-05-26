from flask import Flask, request, jsonify, send_from_directory, session
from datetime import timedelta
import os
import secrets
from login import LoginSystem

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=30)

system = LoginSystem()


@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'login.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(BASE_DIR, path)


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json() or {}
    success, message = system.register(
        data.get('username', '').strip(),
        data.get('email', '').strip(),
        data.get('password', ''),
    )
    return jsonify({'success': success, 'message': message}), (200 if success else 400)


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    remember = bool(data.get('remember', False))

    success, message = system.login(username, password)
    if success:
        session.permanent = remember
        session['username'] = username
        user_info = system.get_user_info(username) or {}
        return jsonify({'success': True, 'message': message,
                        'user': {**user_info, 'username': username}})

    attempts = system.get_attempts(username)
    return jsonify({'success': False, 'message': message, 'attempts': attempts}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('username', None)
    return jsonify({'success': True, 'message': 'Sessão encerrada.'})


@app.route('/api/me', methods=['GET'])
def api_me():
    username = session.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'Não autenticado'}), 401
    user_info = system.get_user_info(username)
    if not user_info:
        session.pop('username', None)
        return jsonify({'success': False, 'message': 'Usuário não encontrado'}), 404
    return jsonify({'success': True, 'user': {**user_info, 'username': username}})


@app.route('/api/recovery/init', methods=['POST'])
def api_recovery_init():
    data = request.get_json() or {}
    success, message, token = system.initiate_recovery(
        data.get('username', '').strip(),
        data.get('email', '').strip(),
    )
    resp = {'success': success, 'message': message}
    if success and token:
        resp['token'] = token
    return jsonify(resp), (200 if success else 400)


@app.route('/api/recovery/reset', methods=['POST'])
def api_recovery_reset():
    data = request.get_json() or {}
    success, message = system.reset_password(
        data.get('token', '').strip(),
        data.get('new_password', ''),
    )
    return jsonify({'success': success, 'message': message}), (200 if success else 400)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
