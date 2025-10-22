# Dockerfile for SBOM Security Agent
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY sbom_agent.py .
COPY pyproject.toml .

# Create non-root user
RUN useradd --create-home --shell /bin/bash sbom
RUN chown -R sbom:sbom /app
USER sbom

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/ping || exit 1

# Expose port
EXPOSE 8080

# Run the agent
CMD ["python", "sbom_agent.py"]