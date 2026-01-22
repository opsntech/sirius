# Sirius - AI DevOps Agent Dockerfile

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    curl \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash -u 1000 agent \
    && mkdir -p /var/log/sirius \
    && chown -R agent:agent /var/log/sirius \
    && mkdir -p /home/agent/.ssh \
    && chown -R agent:agent /home/agent/.ssh \
    && chmod 700 /home/agent/.ssh \
    && mkdir -p /var/lib/sirius/memory \
    && mkdir -p /var/lib/sirius/training_data \
    && chown -R agent:agent /var/lib/sirius

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/

# Set ownership
RUN chown -R agent:agent /app

# Switch to non-root user
USER agent

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose webhook port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["python", "-m", "src.main"]
