FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app
USER appuser

# Add .local/bin to PATH for poetry
ENV PATH="/home/appuser/.local/bin:$PATH"

# Install poetry and dependencies as non-root user
RUN pip install --no-cache-dir poetry \
    && poetry install --without dev

ENTRYPOINT ["poetry", "run", "reputation-check"]
