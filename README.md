# 🚀 Real-Time 5G QoS Analytics and Anomaly Detection using ML (In-House Project)

> Intelligent real-time monitoring and anomaly detection platform for 5G Core Networks using QoS analytics, statistical monitoring, and machine learning.

---

# 🌐 Project Overview

Modern 5G networks generate massive amounts of real-time traffic across critical core network functions such as:

- AMF (Access and Mobility Management Function)
- SMF (Session Management Function)
- UPF (User Plane Function)

This project focuses on building an intelligent monitoring and analytics system capable of:

✅ Capturing and processing packet-level network traffic  
✅ Extracting QoS metrics in real time  
✅ Detecting abnormal network behavior using statistical and ML techniques  
✅ Visualizing network health through an interactive dashboard  
✅ Simulating real-world 5G network failures and anomalies  

The system combines networking, machine learning, real-time analytics, and deployment engineering into a unified observability platform.

---
## 🌐 Live Demo

🚀 **Try the application here:** https://5g-qos-dashboard-ns.streamlit.app/

> **Note:** The deployed version runs in **Simulation Mode** because Streamlit Community Cloud does not support raw packet capture (Scapy requires administrator/root privileges). The complete application with **Real Packet Capture Mode** is available when running locally.


# ✨ Key Features

- 📡 Real-time QoS Monitoring
- 🧠 Hybrid Anomaly Detection (Z-Score + Isolation Forest)
- 🏗️ 5G Core Plane Monitoring (AMF, SMF, UPF)
- 📊 Interactive Streamlit Dashboard
- ⚡ Packet-Level Data Processing
- ☁️ Cloud-Compatible Deployment
- 🔁 Dual-Mode Architecture (Real + Simulation)
- 🚨 Attack Simulation Support
- 📑 Event Intelligence Logging
- 👥 User Session Flow Mapping

---

# 📡 QoS Metrics Monitored

| Metric | Description |
|---|---|
| Latency | Packet transmission delay |
| Jitter | Variation in packet delay |
| Throughput | Data transfer performance |

---

# 🧠 Anomaly Detection Pipeline

## 🔹 Statistical Detection using Z-Score

Used for real-time deviation monitoring across:
- AMF Load
- SMF Activity
- UPF Utilization

The system continuously compares current network behavior with historical trends to identify abnormal spikes and deviations.

---

## 🔹 Machine Learning Detection using Isolation Forest

Implemented unsupervised anomaly detection using Isolation Forest on multidimensional QoS features:

- Latency
- Jitter
- Throughput

This enables detection of complex and non-linear anomalies in network behavior.

---

# 🏗️ System Architecture

## 🟢 Real Mode (Local Execution)

- Captures real packets using Scapy
- Performs live QoS analysis
- Supports packet-level monitoring
- Works locally due to raw socket permissions

---

## 🔵 Simulation Mode (Cloud Deployment)

- Generates synthetic traffic packets
- Enables deployment on Streamlit Cloud
- Maintains analytics pipeline without privileged network access

This dual-mode architecture ensures:
- realistic local testing
- scalable cloud deployment

---

# 🚨 Simulated Network Events

The system supports simulation of multiple 5G network anomalies:

### 🚨 AMF Signaling Storm
Simulates excessive control-plane signaling traffic.

### 🚨 UPF DDoS / Heavy Load
Simulates spikes in user-plane traffic and resource utilization.

---

# 📊 Dashboard Features

- Real-time QoS visualization
- Core network analytics
- ML-based anomaly alerts
- Dynamic traffic slicing visualization
- Event intelligence logs
- User flow tracking
- Interactive monitoring interface

---

# 🛠️ Tech Stack

## Languages
- Python

## Libraries & Frameworks
- Streamlit
- Scapy
- NumPy
- Pandas
- Scikit-learn
- Matplotlib

## Concepts Used
- QoS Analytics
- 5G Core Architecture
- Packet Flow Analysis
- Machine Learning
- Statistical Monitoring
- Real-Time Data Processing
- Anomaly Detection

---

# ☁️ Deployment

## Deployment Platform
- Streamlit Community Cloud

## Deployment Engineering

Real packet capture requires privileged/root access and is restricted on cloud platforms.

To solve this, the system was engineered with a simulation fallback layer, enabling successful cloud deployment while preserving the analytics and anomaly detection workflow.

---

# 👩‍💻 My Contribution

As part of a 6-member team, I worked on:

- Data capture and packet-level processing
- Hybrid anomaly detection implementation using:
  - Z-score for real-time deviation monitoring across AMF, SMF, and UPF
  - Isolation Forest for multidimensional QoS anomaly detection
- Deployment engineering using dual-mode architecture:
  - Real packet capture using Scapy (local execution)
  - Simulation layer for cloud compatibility


---

# ▶️ Run Locally

## Clone Repository

```bash
git clone <https://github.com/niharikasingh09/5g-qos-dashboard.git>
cd <5g-qos-dashboard>
