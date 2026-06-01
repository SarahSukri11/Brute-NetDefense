BRUTE-NETDEFENSE

Project Description
Brute-NetDefense is a web-based cybersecurity monitoring system developed to detect brute-force attacks using a Random Forest machine learning model. The system provides real-time traffic monitoring, attack detection, alert generation, and response management through a Flask web interface.

Technology Stack

* Python
* Flask
* Flask-SocketIO
* Scikit-Learn
* Pandas
* NumPy
* Scapy
* PyShark
* HTML
* CSS
* JavaScript

System Features

* User Authentication
* Dashboard Monitoring
* Traffic Analysis
* Brute Force Detection
* Alert and Response Module
* Security Reporting

Installation

1. Install Python 3.12 or later.

2. Open Command Prompt in the project folder.

3. Install required packages:

pip install -r requirements.txt

4. Run the application:

python app.py

5. Open browser:

http://127.0.0.1:5000 (127.0.0.1-ip address)

Important Files

app.py
Main Flask application.

model/rf_bruteforce_model.pkl
Trained Random Forest model.

logs/
Stores system logs and reports.

templates/
HTML pages.

static/
CSS, JavaScript, and image resources.

Notes

* Ensure rf_bruteforce_model.pkl exists before starting the application.
* Ensure the logs folder exists.
* Packet capture functionality may require administrator privileges.
* Real-time monitoring depends on Flask-SocketIO and packet capture modules.



Final Year Project (FYP)
Brute-NetDefense:Network Monitoring Tool to detect Brute Force Attack using Random Forest algorithm
