import subprocess
import pandas as pd
import pickle
from datetime import datetime
from .parse_file import generate_file_metadata

with open('ransomware_detection_model.pkl', 'rb') as model_file:
    ransomware_model = pickle.load(model_file)

def extract_metadata(container_id):
    command = f'docker exec {container_id} find /data -type f -exec stat --format="%n|%s|%y" {{}} +'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if error:
        print(f"Error extracting metadata from container {container_id}: {error.decode('utf-8')}")
        return None

    metadata_list = []
    for line in output.decode('utf-8').split('\n'):
        if line:
            parts = line.split('|')
            if len(parts) == 3:
                file_name, size, modified_time = parts
                metadata = generate_file_metadata(file_name)
                metadata_list.append(metadata)
    
    return metadata_list

def run_detection(metadata_list):
    df = pd.DataFrame(metadata_list)
    
    if not df.empty:        
        predictions = ransomware_model.predict(df)
        df['is_ransomware'] = predictions
        
        ransomware_files = df[df['is_ransomware'] == 1]
        if not ransomware_files.empty:
            print(f"Ransomware detected in files:")
            print(ransomware_files)

def scan_container(container_id):
    metadata_list = extract_metadata(container_id)
    if metadata_list:
        run_detection(metadata_list)

