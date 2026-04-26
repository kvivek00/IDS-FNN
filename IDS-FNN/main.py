import subprocess
import sys

python_path = sys.executable

# Start FastAPI (visible output)
api_process = subprocess.Popen(
    [
        python_path,
        "-m",
        "uvicorn",
        "Flow_api:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ],
    cwd="Application"
)

print("🚀 Starting FastAPI...\n")


# Start backend (visible output)
backend_process = subprocess.Popen(
    ["npm", "run", "dev"],
    cwd="Full-Stack/backend"
)

print("🚀 Starting backend...\n")


# Start frontend (visible output)
frontend_process = subprocess.Popen(
    ["npm", "run", "dev"],
    cwd="Full-Stack/frontend"
)

print("🚀 Starting frontend...\n")


# Wait for all processes (optional: keep script alive)
api_process.wait()
backend_process.wait()
frontend_process.wait()