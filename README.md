🔐 IoT Gateway Security Project
This project simulates an IoT environment with a secure edge gateway that authenticates devices and manages sensor data using JWT tokens. It demonstrates key concepts in IoT security including token-based access control, structured logging, and modular sensor simulation.

🚀 Features
🧪 Simulated IoT sensor (sensor_simulator.py)

🌐 Flask API gateway with JWT authentication

🔐 Secure login via /login endpoint

📥 Sensor data submission to /sensor-data

📝 Real-time logging to gateway.log

🛡️ Device config via device_config.json

🛠 Requirements

Python 3.8+

Flask

PyJWT

Requests

▶️ Run the Project
Start the Flask API server:
python apitest.py

Run the sensor simulator:
python sensor_simulator.py

📄 Project Structure

apitest.py – Main Flask server

sensor_simulator.py – Simulates temperature & humidity data

device_config.json – Device list

gateway.log – Request and data logs
