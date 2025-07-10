from flask import Flask, render_template, request, redirect, url_for, flash, session # Sessões, redirecionamento, renderização de templates, requisições.
from werkzeug.security import generate_password_hash, check_password_hash # Funções de hash para senhas.
import sqlite3 # Biblioteca para manipulação de banco de dados SQLite.
import os # Biblioteca para manipulação de variáveis de ambiente e caminhos de arquivos.
from authlib.integrations.flask_client import OAuth # Biblioteca para integração do Flask com OAuth.
from dotenv import load_dotenv # Biblioteca para carregar variáveis de ambiente de um arquivo .env.

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY não definida. Defina no .env ou como variável de ambiente do sistema.") 

# --- Configurações do Google OAuth ---
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise ValueError("Credenciais GOOGLE_CLIENT_ID ou GOOGLE_CLIENT_SECRET não definidas no .env ou variáveis de ambiente.")

oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
    redirect_uri='http://127.0.0.1:5000/auth/google/callback'
)

# Configuração do banco de dados
DATABASE = os.path.join(app.instance_path, 'database.db')
os.makedirs(app.instance_path, exist_ok=True)

def init_db():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE NOT NULL, 
                password TEXT, 
                google_id TEXT UNIQUE 
            )
        ''')
        conn.commit()

        # --- Inserir usuário de teste ---
        test_username = "teste"
        test_email = "teste@gmail.com"
        test_password_plain = "123"

        # Verifica se o usuário 'teste' já existe
        cursor.execute("SELECT id FROM users WHERE username = ?", (test_username,))
        existing_user = cursor.fetchone()

        if existing_user is None:
            # Se o usuário 'teste' não existe, insere-o
            hashed_password = generate_password_hash(test_password_plain)
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (test_username, test_email, hashed_password)
            )
            conn.commit()
            print(f"Usuário de teste '{test_username}' com senha '123' (hash) inserido.")
        else:
            print(f"Usuário de teste '{test_username}' já existe no banco de dados.")

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']
        error = None
        user = None
        conn = None

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM users WHERE (username = ? OR email = ?) AND password IS NOT NULL", (username_or_email, username_or_email) #Passa o valor duas vezes para os dois placeholders
            )
            user = cursor.fetchone()
        except Exception as e:
            error = f"Erro no banco de dados: {e}"
        finally:
            if conn:
                conn.close()

        if user is None or not check_password_hash(user['password'], password):
            error = 'E-mail/usuário ou senha incorretos.'
        if error is None:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('main'))
        else:
            flash(error, 'danger')

    return render_template('login.html')

# --- Rotas para Autenticação Google ---
@app.route('/auth/google')
def google_login():
    if 'user_id' in session:
        return redirect(url_for('main'))
    return oauth.google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/auth/google/callback')
def google_callback():
    conn = None
    try:
        token = oauth.google.authorize_access_token()     
        userinfo = oauth.google.parse_id_token(token, nonce=None) 

        session.clear()
    
        google_id = userinfo['sub'] # 'sub' é o ID do usuário no Google (identificador único)
        email = userinfo['email']
        username_from_google = userinfo.get('name', userinfo['email'].split('@')[0]) 

        conn = get_db()
        cursor = conn.cursor()

        user_id = None

        cursor.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
        user = cursor.fetchone()

        # Verifica se o usuário Google já existe no BD pelo google_id
        if user: 
            user_id = user['id']
            conn.commit()

        # Se não encontrou pelo google_id, tenta encontrar pelo email
        else:      
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            # Se encontrou pelo email, é uma conta local que precisa ser associada
            if user: 
                user_id = user['id']
                # Verifica se a conta existente já tem um google_id (pode acontecer se o user_id for NULL)
                if user['google_id'] is None:
                    # Associa o google_id à conta local existente
                    cursor.execute("UPDATE users SET google_id = ?, username = ? WHERE id = ?", 
                                   (google_id, username_from_google, user_id))
                    conn.commit()

                else:
                    flash(f'Bem-vindo(a) de volta, {username_from_google}!', 'info')
            
            # Se não encontrou nem pelo google_id nem pelo email, cria uma nova conta
            else:
                cursor.execute(
                    "INSERT INTO users (username, email, google_id) VALUES (NULL, ?, ?)",
                    (email, google_id)
                )
                conn.commit()
                user_id = cursor.lastrowid
                flash(f'Bem-vindo(a), {username_from_google}!', 'success')

        session['user_id'] = user_id
        session['username'] = username_from_google 
        session['google_logged_in'] = True

        return redirect(url_for('main'))

    except Exception as e:
        flash(f'Erro na autenticação Google: {e}', 'danger')
        return redirect(url_for('login')) 
    finally:
        if conn:
            conn.close()

@app.route('/main')
def main():
    if 'user_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'danger')
        return redirect(url_for('login'))
    
    logged_in_as = session.get('username', 'Usuário') 
    
    return render_template('main.html', username=logged_in_as)

@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db() 
    app.run(debug=True)