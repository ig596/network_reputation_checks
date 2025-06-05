FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app
USER appuser

# Install poetry and dependencies as non-root user
RUN pip install --no-cache-dir poetry \
    && export PATH="$PATH:/home/appuser/.local/bin" \
    && poetry install

ENTRYPOINT ["poetry", "run", "reputation-check"]
