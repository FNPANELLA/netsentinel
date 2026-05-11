FROM python:3.12-slim

RUN apt-get update && apt-get install -y gcc

WORKDIR /app
COPY . .

RUN pip install fastapi uvicorn asyncpg --break-system-packages
RUN gcc -shared -fPIC -o libnetsentinel.so sentinel.c

CMD ["python3", "main.py"]