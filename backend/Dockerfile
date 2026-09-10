FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Added --default-timeout and --retries flags to bypass network drops
RUN pip install --no-cache-dir --default-timeout=100 --retries=5 -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg && \
    curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | gpg --dearmor -o /usr/share/keyrings/msf.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/msf.gpg] https://apt.metasploit.com/ jammy main" > /etc/apt/sources.list.d/msf.list && \
    apt-get update && apt-get install -y metasploit-framework && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

