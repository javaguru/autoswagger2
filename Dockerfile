FROM python:3.13-slim

# Set workdir early
WORKDIR /app

# Copy just what's needed
COPY requirements.txt ./
COPY autoswagger2 ./autoswagger2

# Install Python packages and SpaCy model, then cleanup
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_lg && \
    rm -rf ~/.cache/pip

# Set entrypoint directly to run the package module
ENTRYPOINT ["python", "-m", "autoswagger2"]

CMD ["-h"]
