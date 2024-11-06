#Concurrent Web Server with Python

import socket
import threading
import os
import multiprocessing


#counter for clinen greetings
counter = 0

#HTTP response for 404 (File not found)
def response_404():
    return "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>"