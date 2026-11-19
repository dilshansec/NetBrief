FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock && useradd --create-home netsentry
COPY netsentry ./netsentry
COPY static ./static
COPY samples ./samples
COPY API.md .
USER netsentry
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "netsentry.main:app", "--host", "0.0.0.0", "--port", "8000"]
