from fastapi import FastAPI
from fastapi.responses import StreamingResponse
import numpy as np
import json

from Features.Feature_scraping import raw_data
from Features.Pre_processing import preprocess
from models.Predictor import predict

app = FastAPI()


# ===============================
# CLASS NAME MAPPING
# ===============================

CLASS_NAMES = {
    0: "Benign",
    1: "DDOS",
    2: "DOS",
    3: "Bots",
    4: "Brute Force",
    5: "Scanning",
    6: "Exploits"
}


# ===============================
# FLOW INFO EXTRACTION
# ===============================

def get_flow_info(record):
    return {
        "timestamp": record["timestamp"],
        "src_ip": record["src_ip"],
        "dst_ip": record["dst_ip"],
        "src_port": record["src_port"],
        "dst_port": record["dst_port"]
    }


# ===============================
# FEATURE VECTOR EXTRACTION
# ===============================

def get_feature_vector(record):

    excluded = {
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port"
    }

    return [value for key, value in record.items() if key not in excluded]


# ===============================
# IDS STREAM ENDPOINT
# ===============================

@app.get("/predict")
def run_ids():

    def stream():

        last_pred = None
        streak = 0

        for record in raw_data():

            flow_info = get_flow_info(record)

            feature_vector = get_feature_vector(record)

            processed_vector = preprocess(feature_vector)

            features = np.array(processed_vector, dtype=np.float32)

            prediction = int(predict(features)[0])

            # track consecutive predictions
            if prediction != 0 and prediction == last_pred:
                streak += 1
            else:
                streak = 1
                last_pred = prediction

            output = {**flow_info}

            if prediction != 0 and streak >= 35:

                output["prediction"] = CLASS_NAMES.get(prediction, "Unknown")

            yield json.dumps(output) + "\n"

    return StreamingResponse(stream(), media_type="application/json")

# sudo $(which python) -m uvicorn Flow_api:app --host 0.0.0.0 --port 8000
# curl -N http://localhost:8000/predict