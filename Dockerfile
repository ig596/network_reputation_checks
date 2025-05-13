FROM python:3.12-slim

WORKDIR /app
COPY . /app

# Install poetry and dependencies
RUN pip install --no-cache-dir poetry \
    && export PATH="$PATH:/root/.local/bin" \
    && poetry install
ENTRYPOINT ["poetry", "run", "reputation-check"]
