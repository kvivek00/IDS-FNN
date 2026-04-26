# IDS-FNN

Intrution Detection System (Host Based) using Feed-Forword Neural Networks.

## Detection Capabilities

This system can:

* Detect whether network traffic is **Normal or Malicious**
* Classify attacks into the following categories:
  * **DDoS**
  * **DoS**
  * **Bots**
  * **Brute Force**
  * **Scanning**
  * **Exploits**
* Perform **real-time detection** using live packet capture
* Analyze network behavior using **feature extraction and machine learning**
* Provide **fast and accurate predictions** through a trained FNN model
* Enable **continuous monitoring** of host-based network activity
* Deliver results via an **interactive dashboard for visualization**

## Data Flow
* Network traffic is captured in real-time using packet sniffing
* Relevant features are extracted from the captured packets
* Stage 1: Binary Model classifies traffic as Normal or Attack
* If classified as Attack,
* → Stage 2: Multi-Class Model identifies the specific attack type
* The prediction results are sent to the backend API
* Results are displayed on the frontend dashboard
  
## Model Performance

| Stage   | Model Type                 | F1 Score | Accuracy |
| ------- | -------------------------- | -------- | -------- |
| Stage 1 | Binary Classification      | 0.9967   | 0.9957   |
| Stage 2 | Multi-Class Classification | 0.9864   | 0.9942   |

---

## ⚠️ Note

Designed for only linux Operating Systems, Might Not work in the Virtual Machines as the Virtual Machines can only virtualize OS but not the Kernel.

---

## Setup & Run

### 1. Clone the Repository

```bash id="1x1a1a"
git clone https://github.com/kvivek00/IDS-FNN
cd IDS-FNN
```

---

### 2. Setup Python Environment

```bash id="2x2b2b"
python -m venv pyenv
source pyenv/bin/activate
```

---

### 3. Install Dependencies

```bash id="3x3c3c"
pip install -r requirements.txt
```

---

### 5. Setup Backend & Frontend

```bash id="4x4d4d"
cd Full-Stack/backend
npm install

cd ../frontend
npm install

cd ../../
```

---

### 6. Run the Application

```bash id="5x5e5e"
sudo $(which python) main.py
```

---

### 7. Open in Browser

```text id="6x6f6f"
http://localhost:5173
```

---

## Contact

* GitHub: https://github.com/kvivek00
* Docker: https://hub.docker.com/u/kvivek00
* LinkedIn: https://www.linkedin.com/in/konda-vivek-a41a53291/
