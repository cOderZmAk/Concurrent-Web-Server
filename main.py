#Concurrent Web Server with Python

import socket
import threading
import os
import multiprocessing

#Added to test code (In Progress)
import unittest
from unittest.mock import Mock, patch


#counter for client greetings
counter = 0
counter_lock = threading.Lock()

#HTTP response for 404 (File not found)
def response_404():
    return "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>" # Might change with to simply text message without the <h1> tag


#HTTP response for 200 (OK) with a greeting
def response_200(client_num):
    return f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hello, client {client_num}</h1>"

#Function to handle client requests
def handle_client(client_socket, client_num):
    global counter
    with counter_lock:
        counter += 1
    print(f"Client {client_num} connected")
    request = client_socket.recv(1024).decode()
    print(request)

    #response to GET request
    if request.startswith("GET / HTTP/1.1"):
        response = response_200(client_num)
    else:
        response = response_404()
    client_socket.sendall(response.encode())
    print(f"Response sent to client {client_num}")

    #Response to POST request
    if request.startswith("POST / HTTP/1.1"):
        response = response_200(client_num)
        client_socket.sendall(response.encode())
        print(f"Response sent to client {client_num}")
    client_socket.close()
    print(f"Client {client_num} disconnected")


#Function to serve static files
def serve_static_files(requested_file):
    try:
        with open(requested_file, "rb") as file:
            response = file.read()
            return f"HTTP/1.1 200 OK\r\nContent-type: text/html\r\n\r\n".encode() + response
    except FileNotFoundError:
        return response_404().encode()
        

