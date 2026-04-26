# IDS-FNN

Intrution Detection System (Host Based) using Feed-Forword Neural Networks.

## Model Performance

| Stage   | Model Type                 | F1 Score | Accuracy |
| ------- | -------------------------- | -------- | -------- |
| Stage 1 | Binary Classification      | 0.9864   | 0.9942   |
| Stage 2 | Multi-Class Classification | 0.97XX   | 0.98XX   |

---

## ⚠️ Note

Designed for only linux Operating Systems, Might Not work in the Virtual Machines as the Virtual MAchines can only virtualize OS but not the Kernel.

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
