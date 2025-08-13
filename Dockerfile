FROM mcr.microsoft.com/devcontainers/python:3.11

# (optional) Graphviz helps if you later export DOT/PNG locally
RUN apt-get update && apt-get install -y --no-install-recommends graphviz && \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["/bin/bash"]
