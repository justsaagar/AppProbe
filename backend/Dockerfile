FROM python:3.12-slim

WORKDIR /opt/appprobe

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WORKSPACE_DIR=/data/workspace

COPY requirements.txt /opt/appprobe/requirements.txt
RUN pip install --no-cache-dir -r /opt/appprobe/requirements.txt \
    && mkdir -p /data/workspace

COPY app /opt/appprobe/app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
