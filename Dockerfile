FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./web /app/web
COPY ./utils /app/utils
COPY ./detection_model /app/detection_model

EXPOSE 5000

RUN python ./detection_model/monitor.py

CMD ["python", "./web/server.py"]
