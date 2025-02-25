# Use Python 3.11 base image
FROM python:3.11

# Set working directory
WORKDIR /app

# Copy application files
COPY nessql.py .
COPY requirements.txt .
COPY templates/ templates/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask port
EXPOSE 5000

# Run the application
CMD ["python", "nessql.py"]
