from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from datetime import datetime

from scapy.all import sniff, get_if_addr
from sklearn.ensemble import IsolationForest
import pandas as pd
import json
import requests
import subprocess
import re

app = Flask(__name__)
CORS(app)
model = None

# ACTION PHASE
def run(cmd):
    completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    return completed    

def run_cmd(command):
    subprocess.Popen(f"cmd.exe /k {command}", creationflags=subprocess.CREATE_NEW_CONSOLE)

def commit_action(remediation, timestamp):
    ipv4_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    port_regex = r"\b\d{1,5}\b"

    ip_match = re.search(ipv4_regex, remediation)
    port_match = re.search(port_regex, remediation)

    ip_address = ip_match.group(0) if ip_match else None
    port_number = port_match.group(0) if port_match and not ip_match else None
    service = remediation.strip().split()[-1]

    if "close" in remediation:
        command = f"echo this is an example of running code to close {port_number}"
        run_cmd(command)
         
    if "block" in remediation:
        command = f"echo this is an example of running code to block {ip_address}"
        run_cmd(command)

    if "restart" in remediation:
        command = f"echo this is an example of running code to restart {service}"
        run_cmd(command)
        
    if "limit" in remediation:
        command = f"echo this is an example of running code to limit {ip_address}"
        run_cmd(command)

    # Log action with timestamp for tracking
    print(f"Action: {remediation} | Timestamp: {timestamp}")

def get_remediation_action(summary, ruleset):
    url = "https://hackathon.niprgpt.mil/llama/v1/chat/completions"
    headers = {
        "Authorization": "Bearer YOUR-API-KEY-HERE",
        "Content-Type": "application/json"
    }
    prompt = (
        f"Based on the anomaly summary: {summary}, and the ruleset: {ruleset}, "
        f"recommend a specific action in a single line. "
        f"Choose only from these commands: close port [port_number], block IP [ip_address], "
        f"restart service [service_name], limit bandwidth for IP [ip_address]."
        f"ONLY pick one option and specify no other output, for any anomaly ignore the IP 172.25.31.145 as this is the local system's and is not irregular"
        f"if two actions are recommended seperate the commands by comma (,) but always ONLY respond with the previously listed commands"
    )
    
    data = {
        "model": "neuralmagic/Meta-Llama-3.1-70B-Instruct-FP8",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7
    }
    
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        action = response.json().get("choices", [{}])[0].get("message", {}).get("content", "No action recommended.")
        return action.splitlines()[0].strip()  # Only return the first line of the response
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return "Error retrieving action"
    
def respond_compliance(summary):
    url = "https://hackathon.niprgpt.mil/llama/v1/chat/completions"
    headers = {
        "Authorization": "Bearer YOUR-API-KEY-HERE",
        "Content-Type": "application/json"
    }
    prompt = (
        f"Based on the summary of Windows registry key values: {summary}, and the context that: ScanWithAntiVirus should have a value containing 3"
        f"recommend a specific response to the current summary of key values in a non decorated list for each given key value that contains ONLY the following message:"
        f"[change/keep] [key value] [to/as] [value to change or keep as]"
        f"respond with nothing else except your answers for the given context"
    )
    
    data = {
        "model": "neuralmagic/Meta-Llama-3.1-70B-Instruct-FP8",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7
    }
    
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        action = response.json().get("choices", [{}])[0].get("message", {}).get("content", "No action recommended.")
        return action.splitlines()[0].strip()  # Only return the first line of the response
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return "Error retrieving action"
# SUMMARIZE PHASE
def summarize_anomalies(anomalies):
    summaries = []
    for index, row in anomalies.iterrows():
        summary = {
            "src_ip": row['src_ip'],
            "dst_ip": row['dst_ip'],
            "src_port": row['src_port'],
            "dst_port": row['dst_port'],
            "packet_length": row['packet_length'],
            "protocol": row['protocol'],
            "anomaly_type": "Unusual Port Activity" if row['src_port'] == 0 or row['dst_port'] == 0 else "Suspicious Activity"
        }
        summaries.append(summary)
    
    return json.dumps(summaries, indent=4)

# DETECTION PHASE
def extract_features(packet, local_ip):
    # Skip packets from the local machine (src_ip equals local IP address)
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        if src_ip == local_ip:
            return None  # Ignore packets from the local machine
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
    else:
        return None  # Ignore packets without an IP layer

    # Check for TCP layer and extract port information
    if packet.haslayer('TCP'):
        src_port = packet.sport
        dst_port = packet.dport
    else:
        src_port = dst_port = 0  # If not TCP, set ports to 0

    # Return the feature dictionary
    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'packet_length': len(packet),
        'protocol': protocol
    }

def process_batch(packets, model, local_ip):
    features = [extract_features(packet, local_ip) for packet in packets]
    features = [f for f in features if f is not None]  # Filter out None values

    if not features:
        print("No relevant packets in this batch.")
        return

    df = pd.DataFrame(features)
    df_features = df.drop(columns=['src_ip', 'dst_ip'])

    predictions = model.predict(df_features)
    anomalies = df[predictions == -1]

    ruleset = "Example ruleset: avoid unusual ports, restrict repeated login attempts, prevent large data transfers"

    if not anomalies.empty:
        summary = summarize_anomalies(anomalies)  # Call the function to get the summary
        print("Anomalies detected in batch: ")
        print(anomalies[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'packet_length', 'protocol']])

        action = get_remediation_action(summary, ruleset)  # Forward to action phase

        # Get the current timestamp for when the action occurs
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Commit action with timestamp
        commit_action(action, timestamp)
        
        return {"action": action, "timestamp": timestamp}

    else:
        return {"action": 'no anomalies...', "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

def train_model():
    global model
    local_ip = get_if_addr("Wi-Fi")  # or use the desired interface
    print("Training model on baseline traffic...")
    baseline_packets = sniff(iface="Wi-Fi", count=100)  # Adjust interface and packet count as needed
    baseline_features = [extract_features(packet, local_ip) for packet in baseline_packets]
    baseline_features = [f for f in baseline_features if f is not None]  # Filter out None values
    df_baseline = pd.DataFrame(baseline_features)
    df_baseline_features = df_baseline.drop(columns=['src_ip', 'dst_ip'])  # Drop IPs for model training

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df_baseline_features)
    print("Model trained.")

def capture_and_detect(model, interface="Wi-Fi", batch_size=20, interval=5):
    local_ip = get_if_addr(interface)  # Get the local machine's IP address for the given interface

    # Capture network packets and detect anomalies without retraining the model
    packets = sniff(iface=interface, count=batch_size, timeout=interval)
    response = process_batch(packets, model, local_ip)

    return response

def init_model():
    # Train the model once when the application starts
    train_model()

# Windows Compliance
def get_reg_values(key, value):
    try:
        # Construct the full command to query the registry
        cmd = f"reg query \"{key}\" /v {value}"
        print(cmd)
        
        # Run the command
        completed_process = subprocess.run(f"cmd.exe /c {cmd}", capture_output=True, text=True)
        
        # Check if the command was successful
        if completed_process.returncode == 0:
            return completed_process.stdout.strip()  # Return the output (registry value)
        else:
            return f"Error: {completed_process.stderr.strip()}"  # Return error message if registry key/value not found
    except Exception as e:
        return f"An error occurred: {str(e)}"  # Return any exception message

with app.app_context():
    init_model()

@app.route('/check_registry_value', methods=['GET'])
def get_registry_value():
    reg_key = request.args.get('key')  # Get the registry key from query parameter
    reg_value = request.args.get('value')  # Get the registry value name from query parameter
    
    if not reg_key or not reg_value:
        return jsonify({"error": "Please provide both 'key' and 'value' parameters."}), 400
    
    summary = get_reg_values(reg_key, reg_value)
    result = respond_compliance(summary)
    return jsonify({"registry_key": reg_key, "registry_value": reg_value, "result": result})

@app.route('/start_detection_sse', methods=['GET'])
def start_detection_sse():
    def generate_anomalies():
        # Use the pre-trained model to detect anomalies
        if model is None:
            print("Model is not trained!")
            return {"action": "Error: Model not trained yet."}

        result = capture_and_detect(model=model)
        # Return the action and timestamp as JSON response
        return jsonify(result)
    
    anomalies = generate_anomalies()  # Call the function to get anomalies
    return anomalies  # Return the anomalies as JSON

if __name__ == '__main__':
    app.run(debug=True)
