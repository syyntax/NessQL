# Use Python 3.11 base image
FROM python:3.11

# Set working directory
WORKDIR /app

# Install SQLite3 CLI
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY nessql.py .
COPY requirements.txt .
COPY templates/ templates/
COPY static/ static/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask port
EXPOSE 5000

# Run the application
CMD ["python", "nessql.py"]
