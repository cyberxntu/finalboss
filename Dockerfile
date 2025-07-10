FROM python:3.11-slim

RUN adduser --disabled-password --gecos '' appuser
USER appuser

WORKDIR /app

COPY --chown=appuser:appuser requirements.txt .

RUN pip install --upgrade pip setuptools==70.0.0 --no-cache-dir

RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

EXPOSE 5000

CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "app:app"]
