# Lightweight Python image
FROM python:3.12-slim

# Working directory set karein
WORKDIR /app

# Requirements copy aur install karein
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Saara backend code copy karein
COPY . .

# Render dwara diye gaye dynamic PORT variable ka use karein
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}"]
