# VULN 8: old base image, mutable tag, runs as root -> Trivy / Checkov
FROM python:3.8
ADD . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]
