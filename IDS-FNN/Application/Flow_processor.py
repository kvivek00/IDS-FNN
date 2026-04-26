from Features.Feature_scraping import raw_data
from Features.Pre_processing import preprocess
from models.Predictor import predict
import numpy as np


# -----------------------------------------
# Flow metadata (addresses + ports)
# -----------------------------------------
def get_flow_info(record):
    return {
        "timestamp": record["timestamp"],
        "src_ip": record["src_ip"],
        "dst_ip": record["dst_ip"],
        "src_port": record["src_port"],
        "dst_port": record["dst_port"]
    }


# -----------------------------------------
# Feature vector for ML model
# -----------------------------------------
def get_feature_vector(record):

    excluded = {
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port"
    }

    return [value for key, value in record.items() if key not in excluded]


# -----------------------------------------
# Main
# -----------------------------------------
def main():

    for record in raw_data():

        # split metadata
        flow_info = get_flow_info(record)

        # extract 37 features
        feature_vector = get_feature_vector(record)

        # preprocess features
        processed_vector = preprocess(feature_vector)

        # convert to numpy
        features = np.array(processed_vector, dtype=np.float32)

        # run IDS prediction
        prediction = predict(features)[0]

        # combine results
        output = {
            **flow_info,
            "prediction": int(prediction)
        }

        print(output)


if __name__ == "__main__":
    main()


