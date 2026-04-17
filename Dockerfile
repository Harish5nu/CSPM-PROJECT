FROM python:3.11-slim

# Install Ollama
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://ollama.com/install.sh | sh

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pull the AI model during build
RUN ollama pull llama3.2:1b

# Expose Ollama port
EXPOSE 11434

# Expose Streamlit port
EXPOSE 8501

CMD ["python", "scripts/run_with_scoring.py"]