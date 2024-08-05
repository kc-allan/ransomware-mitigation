import logging
import time
import joblib
import os
import pandas as pd
import numpy as np
from docker import from_env as docker_from_env
from parse_file import get_file_metadata

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(
    __file__), 'ransomware_detection_model.pkl')
model = joblib.load(MODEL_PATH)

docker_client = docker_from_env()


def extract_features_from_container(container_id):
    try:
        logger.info("Starting container scan.")
        container = docker_client.containers.get(container_id)
        files = container.get_archive('/app')

        local_path = '/tmp/container_files'
        os.makedirs(local_path, exist_ok=True)

        tar_path = os.path.join(local_path, 'files.tar')
        logger.info('Opening tar file for writing.')
        with open(tar_path, 'wb') as f:
            for chunk in files[0]:
                f.write(chunk)

        logger.info('File written, unzipping.')
        os.system(f"tar -xvf {tar_path} -C {local_path}")

        logger.info('Unzipped, now loading features.')
        features = load_features_from_files(local_path)
        logger.info('Features loaded.')

        return features
    except Exception as e:
        logger.error(f"Error scanning container {container_id}: {e}")
        return None


def load_features_from_files(path_):
    path = os.path.join(path_, 'app')
    logger.info(f"Files in directory: {os.listdir(path)}")

    all_data = []
    for file in os.listdir(path):
        file_path = os.path.join(path, file)
        if os.path.isfile(file_path):
            logger.info(f"Processing file: {file_path}")
            try:
                data = get_file_metadata(file_path)
                if isinstance(data, dict):
                    all_data.append(data)
            except Exception as e:
                logger.error(f"Error getting metadata from {file_path}: {e}")

    if not all_data:
        logger.error(f"No valid data found in path {path}.")
        return None

    df = pd.DataFrame(all_data)
    if 'md5' in df.columns:
        df.drop(columns=['md5'], inplace=True)

    expected_features = model.feature_names_in_
    missing_features = set(expected_features) - set(df.columns)
    for feature in missing_features:
        df[feature] = 0

    df = df[expected_features]
    return df


def detect_ransomware(features):
    try:
        predictions = model.predict(features)
        # Check if predictions are in the expected format
        if isinstance(predictions, (list, np.ndarray)):
            return any(predictions)
        return bool(predictions)
    except Exception as e:
        logger.error(f"Error during ransomware detection: {e}")
        return False


def handle_ransomware(container_id, feature):
    logger.warning(f"Ransomware detected in container {
                   container_id} in file {feature['Name']}!")
    docker_client.containers.get(container_id).stop()


def scan_containers():
    logger.info("Starting container scan.")
    running_containers = [
        container.id for container in docker_client.containers.list()]

    for container_id in running_containers:
        try:
            features = extract_features_from_container(container_id)
            if features is not None:
                if detect_ransomware(features):
                    handle_ransomware(container_id, features)
                else:
                    logger.info(f"No ransomware detected in container {
                                container_id}.")
            else:
                logger.info(f"No features extracted for container {
                            container_id}.")
        except Exception as e:
            logger.error(f"Error scanning container {container_id}: {e}")


def start_monitoring(interval=10):
    logger.info("Monitoring system started.")
    try:
        while True:
            scan_containers()
            logger.info(f"Waiting for the next scan in {interval} seconds.")
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Monitoring system stopped by user.")


if __name__ == "__main__":
    start_monitoring()
