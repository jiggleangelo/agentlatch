FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY agentgate ./agentgate
COPY tests ./tests
COPY demo.py README.md CRA_READINESS.md RELEASE_GATE.md compose.yaml ./
COPY deploy ./deploy
COPY Dockerfile ./Dockerfile
USER 65532:65532
CMD ["python3", "demo.py"]
