from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
import logging
from logging.handlers import RotatingFileHandler
import os
import sqlite3
import main_function
import json

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)

# Setup JWT and Rate Limiter
jwt = JWTManager(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["25 per minute"])

# Setup Logging
handler = RotatingFileHandler('APIlog.log', maxBytes=100000, backupCount=3)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logging.getLogger('').addHandler(handler)
logging.getLogger('').setLevel(logging.INFO)

# Initialize SQLite database
"""
def database():
    with sqlite3.connect('iotdatabase.db') as con:
        con.execute('''CREATE TABLE IF NOT EXISTS iot_data
                     (device TEXT, temperature REAL, humidity REAL, timestamp DATETIME)''')
        con.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY, encrypt_password TEXT)''')
        encrypt = bcrypt.generate_password_hash("password").decode('utf-8')
        con.execute('INSERT OR IGNORE INTO users (username, encrypt_password) VALUES (?, ?)', ('admin', encrypt))
"""
def database():
    connect = sqlite3.connect('iotdatabase.db')
    cursor = connect.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS iot_data (device TEXT, temperature Real, humidity REAL, timestamp DATETIME)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, encrypted_password TEXT)''')

    encrypt = bcrypt.generate_password_hash("password").decode('utf-8')
    cursor.execute('INSERT OR IGNORE INTO users (username, encrypted_password) VALUES (?, ?)', ('admin', encrypt))

    connect.commit()
    cursor.close()
    connect.close()

database()

# Load authorized devices
authorized_devices = main_function.read_from_file("device_config.json").get("devices",[])

# API Endpoints
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        message = {"response":"welcome, use POST to login, or add /login to the end of the URL"}
        return jsonify(message), 200
    
    """
    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415
    """

    jsonData = request.get_json()
    username = ""
    password = ""
    result = ""
    storedPassword = ""
    connect = None
    cursor = None

    if jsonData:
        if "username" in jsonData:
            username = jsonData["username"]
        if "password" in jsonData:
            password = jsonData["password"]
    
    connect = sqlite3.connect ('iotdatabase.db')
    cursor = connect.cursor()
    cursor.execute("SELECT encrypted_password FROM users WHERE username = ?",(username,))
    result = cursor.fetchone()

    if result is not None:
        storedPassword = result[0]
        if bcrypt.check_password_hash(storedPassword, password):
            token = create_access_token(identity=username)
            message = {"token":token}
            return jsonify(message), 200
    
    cursor.close()
    connect.close()
    
    message = {"response": "invalid credentials"}
    return jsonify(message), 401


    """
        data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    with sqlite3.connect('iotdatabase.db') as conn:
        cursor = conn.execute('SELECT encrypt_password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result and bcrypt.check_password_hash(result[0], password):
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Bad credentials"}), 401
    """
    
    
"""
@app.route('/sensor-data', methods=['POST'])
@jwt_required()
@limiter.limit("5 per minute")
def receive_sensor_data():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    device = data.get("device")
    if not device or device not in authorized_devices:
        logging.warning(f"Unauthorized device attempted access: {device}")
        return jsonify({"error": "Unauthorized device"}), 403

    required_keys = {"temperature", "humidity"}
    if not all(k in data for k in required_keys):
        return jsonify({"error": "Missing required fields"}), 400

    temp = float(data['temperature'])
    humidity = float(data['humidity'])
    if not (-50 <= temp <= 150) or not (0 <= humidity <= 100):
        return jsonify({"error": "Invalid temperature or humidity values"}), 400

    with sqlite3.connect('iotdatabase.db') as conn:
        conn.execute('INSERT INTO iot_data (device, temperature, humidity, timestamp) VALUES (?, ?, ?, datetime("now"))',
                    (device, temp, humidity))

    logging.info(f"Data from {device}: Temp={temp}, Humidity={humidity}")
    return jsonify({"message": "Sensor data received successfully"}), 200

"""
@app.route('/sensor-data', methods=['POST'])
@jwt_required()
@limiter.limit("110 per minute")
def recivedSensorData():
    jsonData = request.get_json()
    connect = sqlite3.connect('iotdatabase.db')
    cursor = connect.cursor()
    device = ""
    authorized = False
    allFields = True
    temperature = 0.0
    humidity = 0.0

    if "device" in jsonData:
        device = jsonData["device"]
    for validDevice in authorized_devices:
        if device == validDevice:
            authorized = True
            break
    if not device or not authorized:
        logging.warning("unathorized attempt")
        message = {"error": "unauthorized device"}
        return jsonify(message), 403
    required = ["temperature", "humidity"]
    for field in required:
        if field not in jsonData:
            allFields = False
            break
    if not allFields:
        message = {"error": "missing fields"}
        return jsonify(message), 400
    if "temperature" in jsonData:
        temperature = float(jsonData["temperature"])
    if "humidity" in jsonData:
        humidity = float(jsonData["humidity"])
    validTemp = temperature >= -50 and temperature <=130
    validHumid = humidity >= 0 and humidity <= 100
    if not validHumid or not validTemp:
        message = {"error": "invalid temperature or humidity data"}
        return jsonify(message), 400
    cursor.execute("INSERT INTO iot_data (device, temperature, humidity, timestamp) VALUES (?, ?, ?, datetime('now'))", (device, temperature, humidity))
    connect.commit()

    cursor.close()
    connect.close()

    logMessage = "data from " + str(device) + ": Temp = " + str(temperature) + ", Humidity = " + str(humidity)
    logging.info(logMessage)
    
    message = {"response": "data received successfuly"}
    return jsonify(message), 200


# Web Interface Routes
"""
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        with sqlite3.connect('iotdatabase.db') as db:
            cursor = db.execute('SELECT encrypt_password FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result and bcrypt.check_password_hash(result[0], password):
                access_token = create_access_token(identity=username)
                return render_template('dashboard.html', token=access_token, username=username)
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')
"""
@app.route('/login', methods=['GET', 'POST'])
def login():
    username = ""
    password = ""
    loginStatus = False

    requestMethod = request.method
    if requestMethod == "POST":
        if request.form:
            if "username" in request.form:
                username = request.form["username"]
            if "password" in request.form:
                password = request.form["password"]

        print ("user= " + str(username) + ", pass= " +str(password))
        connect = sqlite3.connect('iotdatabase.db')
        cursor = connect.cursor()
        cursor.execute("SELECT encrypted_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result is not None:
            storedPass = result[0]
            if storedPass is not None:
                if bcrypt.check_password_hash(storedPass, password):
                    loginStatus = True
        
        cursor.close()
        connect.close()

        if loginStatus:
            token = create_access_token(identity=username)
            return render_template('dashboard.html', token=token, username=username)
        else:
            flash("invalid credentails", "error")
            return redirect(url_for('login'))                         
    return render_template('login.html')

"""
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    token = request.form.get('token') if request.method == 'POST' else None
    if token:
        try:
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            identity = decoded['sub']
            logging.debug(f"Form submission with token for user: {identity}")
        except Exception as e:
            logging.error(f"Invalid token in form submission: {e}")
            flash('Invalid or expired token', 'error')
            return redirect(url_for('login'))
    else:
        try:
            @jwt_required()
            def check_jwt():
                return get_jwt_identity()
            identity = check_jwt()
        except Exception as e:
            logging.error(f"JWT error: {e}")
            flash('Please log in to access the dashboard', 'error')
            return redirect(url_for('login'))

    if request.method == 'POST':
        device = request.form.get('device')
        try:
            temperature = float(request.form.get('temperature'))
            humidity = float(request.form.get('humidity'))
            if not (-50 <= temperature <= 150) or not (0 <= humidity <= 100):
                flash('Invalid temperature or humidity values', 'error')
                return render_template('dashboard.html', token=token, username=identity)
        except (ValueError, TypeError):
            flash('Temperature and humidity must be numbers', 'error')
            return render_template('dashboard.html', token=token, username=identity)

        if not device or device not in authorized_devices:
            flash('Unauthorized device', 'error')
            return render_template('dashboard.html', token=token, username=identity)

        with sqlite3.connect('iotdatabase.db') as conn:
            conn.execute('INSERT INTO iot_data (device, temperature, humidity, timestamp) VALUES (?, ?, ?, datetime("now"))',
                        (device, temperature, humidity))

        logging.info(f"Data from {device} via web by {identity}: Temp={temperature}, Humidity={humidity}")
        flash('Sensor data submitted successfully', 'success')

    with sqlite3.connect('iotdatabase.db') as conn:
        cursor = conn.execute('SELECT device, temperature, humidity, timestamp FROM iot_data ORDER BY timestamp DESC LIMIT 10')
        iot_data = cursor.fetchall()

    return render_template('dashboard.html', token=token, username=identity, iot_data=iot_data)
"""

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    id = ""
    token = ""
    device = ""
    temperature = 0.0
    humidity = 0.0
    requestMethod = request.method

    if requestMethod == "POST":
        if request.form and "token" in request.form:
            token = request.form["token"]
    if token:
        decodeToken = decode_token(token)
        if decodeToken and "sub" in decodeToken:
            id = decodeToken["sub"]
            logging.debug("token for user: " + str(id))
        else:
            flash("invalid token", "error")
            return redirect(url_for('login'))
    else:
        jwtValid = False
        jwtId = get_jwt_identity()
        if jwtId:
            id = jwtId
            jwtValid = True
        if not jwtValid:
            flash("log in to access dashboard", "error")
            return redirect(url_for('login'))
    if requestMethod == "POST":
        if request.form:
            if "device" in request.form:
                device = request.form["device"]
            if "temperature" in request.form:
                temperature = float(request.form["temperature"])
            if "humidity" in request.form:
                humidity = float(request.form["humidity"])
        validTemp = temperature >= -50 and temperature <= 130
        validHumidity = humidity >= 0 and humidity <= 100

        if not validTemp or not validHumidity:
            flash("invalid temperature or humidity data", "error")
            return render_template('dashboard.html', token=token, username=id)
        if not device or device not in authorized_devices:
            flash('invalid device', 'error')
            return render_template('dashboard.html', token=token, username=id)
        
        connect = sqlite3.connect('iotdatabase.db')
        cursor = connect.cursor()

        cursor.execute("INSERT INTO iot_data (device, temperature, humidity, timestamp) VALUES (?, ?, ?, datetime('now'))", (device, temperature, humidity))
        connect.commit()
        cursor.close()
        connect.close()

        message = "data from " + str(device) + " via website by " + str(id) + ": temp = " + str(temperature) + ", humidity=" +str(humidity)
        logging.info(message)
        flash("data submitted successfully", "success")
    connect = sqlite3.connect('iotdatabase.db')
    cursor = connect.cursor()

    cursor.execute("SELECT device, temperature, humidity, timestamp FROM iot_data ORDER BY timestamp DESC LIMIT 6")
    iot_data = cursor.fetchall()

    cursor.close()
    connect.close()

    return render_template('dashboard.html', token=token, username=id, iot_data=iot_data)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))