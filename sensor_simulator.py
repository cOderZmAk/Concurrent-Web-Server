import requests
import time
import random

url = "https://127.0.0.1:5000"

def getToken():
    login = {"username": "admin", "password": "password"}
    header = {"Content-Type": "application/json"}
    response = requests.post(url + "/", json=login, headers=header, timeout=5, verify=False)
    status = response.status_code

    print(f"Login Request Headers: {response.request.headers}")
    print(f"Login Response: Code={status}, Text={response.text}")

    if status == 200:
        responseData = response.json()
        print("hello1")
        if "token" in responseData:
            print("hello2")
            return responseData["token"]
        else:
            print("token not found")
            return None
    
def sendData(token, device, maxTries):
    attempt = 0
    while attempt < maxTries:
        authorize = "Bearer " + str(token)
        requestHeader = {"Authorization": str(authorize), "Content-Type": "application/json"}

        randTemperature = round(random.uniform(-20.0, 100.0), 2)
        randHumidity = round(random.uniform(10.0, 90.0), 2)

        data = {"device": device, "temperature": randTemperature, "humidity": randHumidity}

        print("hello3")
        message = requests.post(url + "/sensor-data", json=data, headers=requestHeader, verify=False)
        status = message.status_code
        data = message.json()
        print("code: " + str(status) + ", response: " + str(data))

        attempt += 1
    

def main():
    authToken = getToken()
    if authToken:
        count = 0
        maxi = 3
        while count < maxi:
            sendData(authToken, "sensor_001", 3)
            time.sleep(4)
            count +=1

if __name__ == "__main__":
    main()

"""
def getToken():
    login_payload = {"username": "admin", "password": "password"}
    try:
        # Disable SSL verification for self-signed certificate (local testing only)
        response = requests.post(f"{BASE_URL}/", json=login_payload, timeout=5, verify=False)
        if response.status_code == 200:
            return response.json()["access_token"]
        else:
            print(f"Failed to get token: {response.status_code}, {response.json()}")
            return None
    except RequestException as e:
        print(f"Error getting token: {e}")
        return None

def send_sensor_data(token, device_id, retries=3):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "device_id": device_id,
        "temperature": round(random.uniform(20.0, 30.0), 2),
        "humidity": round(random.uniform(30.0, 70.0), 2)
    }
    for attempt in range(retries):
        try:
            response = requests.post(f"{BASE_URL}/sensor-data", json=payload, headers=headers, timeout=5, verify=False)
            print(f"Status Code: {response.status_code}, Response: {response.json()}")
            return
        except RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(2)
    print("Failed to send data after retries")

if __name__ == "__main__":
    token = get_token()
    if token:
        for i in range(5):
            send_sensor_data(token, "sensor_001")
            time.sleep(2)
"""