import logging
import time
import joblib
import os
import pandas as pd
from docker import from_env as docker_from_env
from utils.parse_file import get_file_metadata

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

MODEL_PATH = 'ransomware_detection_model.pkl'
model = joblib.load(MODEL_PATH)

docker_client = docker_from_env()


def extract_features_from_container(container_id):
    container = docker_client.containers.get(container_id)
    files = container.get_archive('/app')

    local_path = '/tmp/container_files'
    os.makedirs(local_path, exist_ok=True)

    with open(os.path.join(local_path, 'files.tar'), 'wb') as f:
        for chunk in files[0]:
            f.write(chunk)

    os.system(
        f"tar -xvf {os.path.join(local_path, 'files.tar')} -C {local_path}")

    features = load_features_from_files(local_path)

    return features


def load_features_from_files(path):
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            data = get_file_metadata(file)
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (int, float, str)):
                        if isinstance(value, str) and value.startswith('0x'):
                            data[key] = int(value, 16)
                            df = pd.DataFrame([data])
                        else:
                            df = pd.DataFrame(data)
                    else:
                        df = pd.DataFrame(data)
                if 'md5' in df.columns:
                    df.drop(columns=['md5'], inplace=True)

                expected_features = model.feature_names_in_
                missing_features = set(expected_features) - set(df.columns)

                for feature in missing_features:
                    df[feature] = 0

                df = df[expected_features]
                return df


def detect_ransomware(features):
    prediction = model.predict(features)

    return bool(prediction)


def handle_ransomware(container_id, feature):
    logging.warning(f"Ransomware detected in container {container_id} in file {feature['Name']}!")

    docker_client.containers.get(container_id).stop()


def scan_containers():
    logging.info("Starting container scan.")

    running_containers = [
        container.id for container in docker_client.containers.list()]

    for container_id in running_containers:
        try:
            features = extract_features_from_container(container_id)
            for feature in features:
                if detect_ransomware(feature):
                    handle_ransomware(container_id, feature)
                else:
                    logging.info(f"No ransomware detected in container {container_id}.")
        except Exception as e:
            logging.error(f"Error scanning container {container_id}: {e}")


def start_monitoring(interval=10):
    logging.info("Monitoring system started.")
    try:
        while True:
            scan_containers()
            logging.info(f"Waiting for the next scan in {interval} seconds.")
            time.sleep(interval)
    except KeyboardInterrupt:
        logging.info("Monitoring system stopped by user.")


if __name__ == "__main__":
    start_monitoring()
