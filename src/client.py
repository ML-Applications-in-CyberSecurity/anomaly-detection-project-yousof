import os
import socket
import json
import pandas as pd
import joblib
from IPython.display import display
import numpy as np
from together import Together
import csv
from datetime import datetime, UTC
HOST = 'localhost'
PORT = 9999

model = joblib.load("anomaly_model.joblib")
filename = f'risk_analysis.csv'

def write_risk_analysis_to_csv(risk_analysis):
    try:
          # Check if file exists to determine if we need to write headers
        file_exists = os.path.isfile(filename)
        
        # Open file in append mode ('a' instead of 'w')
        with open(filename, 'a', newline='') as csvfile:
            fieldnames = ['risk_category', 'threat_type', 'severity', 'timestamp', 'src_port','dst_port','packet_size','duration_ms','protocol']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Write header only if file doesn't exist
            if not file_exists:
                writer.writeheader()
            
            # Append the new data
            writer.writerow(risk_analysis)
            return True

    except IOError as e:
        print(f"File I/O error: {str(e)}")
        return False
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

def pre_process_data(data):
    df = pd.DataFrame([data])
    
    # Create dummy variables
    df = pd.get_dummies(df, columns=["protocol"])
    
    # Ensure protocol_UDP column exists and convert to boolean
    if 'protocol_UDP' not in df.columns:
        df['protocol_UDP'] = False
    else:
        df['protocol_UDP'] = df['protocol_UDP'].astype(bool)
        
    if 'protocol_TCP' not in df.columns:
        df['protocol_TCP'] = False
    else:
        df['protocol_TCP'] = df['protocol_TCP'].astype(bool)
        
    # Drop protocol_TCP if it was the first column in your training data
    if 'protocol_TCP' in df.columns:
        df = df.drop('protocol_TCP', axis=1)
    
    # Ensure columns are in the same order as training data
    expected_columns = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']
    df = df[expected_columns]
    
    return np.array(df)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    buffer = ""
    print("Client connected to server.\n")

    while True:
        chunk = s.recv(1024).decode()
        if not chunk:
            break
        buffer += chunk

        while '\n' in buffer:
            line, buffer = buffer.split('\n', 1)
            try:
                data = json.loads(line)
                print(f'Data Received:\n{data}\n')
                preprocessed_data = pre_process_data(data)
                prediction = model.predict(preprocessed_data)
                if prediction[0] == -1:
                   print("Anomaly detected in the data.")
                   os.environ["TOGETHER_API_KEY"] = "f1ca86c9d28a0a0d3ade8cd868b49dae2333556413e4fb2827e3943aa0539cfe" 
                   client = Together()
                   response = client.chat.completions.create(
                 model="Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8",
                 messages=[
                 {
            "role": "system",
            "content": '''You are a network security analyzer. Analyze network traffic patterns and return ONLY a JSON object containing:
1. Primary risk category
2. Specific threat type
3. Severity level (LOW, MEDIUM, HIGH, CRITICAL)

Based on these patterns:
- WEB_ATTACK:
  * If src_port is 80/443 with unusual packet sizes
  * If using non-standard protocols for web ports
  * Types: SQL_INJECTION, XSS_ATTEMPT, WEB_SHELL, UNUSUAL_WEB_TRAFFIC

- PORT_ABUSE:
  * If well-known ports are used unexpectedly
  * If high port numbers show suspicious patterns
  * Types: PORT_SCANNING, SERVICE_ABUSE, UNAUTHORIZED_SERVICE

- PROTOCOL_MISUSE:
  * If protocols are used inappropriately
  * If UDP is used for typically TCP services
  * Types: PROTOCOL_TUNNELING, PROTOCOL_SPOOFING, UDP_FLOOD

- DATA_ANOMALY:
  * If packet sizes are unusual for the protocol
  * If duration patterns are suspicious
  * Types: DATA_EXFILTRATION, COVERT_CHANNEL, SUSPICIOUS_TRANSFER

Return JSON in this format ONLY:
{
    "risk_category": "CATEGORY",
    "threat_type": "SPECIFIC_TYPE",
    "severity": "LEVEL",
    "timestamp": "YYYY-MM-DD HH:MM:SS"
}

NO additional text or explanations.'''
        },
        {
            "role": "user", 
            "content": f"""Analyze this network data:
            Traffic Data: {data}"""
        }
                ])

                   risk_analysis = json.loads(response.choices[0].message.content)
                   print(f"""
                Risk Analysis:
                Category: {risk_analysis['risk_category']}
                Threat Type: {risk_analysis['threat_type']}
                Severity: {risk_analysis['severity']}
                Detected at: {risk_analysis['timestamp']}
                """)
                   risk_analysis['src_port'] = data['src_port']
                   risk_analysis['dst_port'] = data['dst_port']
                   risk_analysis['packet_size'] = data['packet_size']
                   risk_analysis['duration_ms'] = data['duration_ms']
                   risk_analysis['protocol'] = data['protocol']
                # Write to CSV file
                   write_risk_analysis_to_csv(risk_analysis)
            except json.JSONDecodeError:
                print("Error decoding JSON.")
