FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app
USER appuser

# Add .local/bin to PATH for poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV PATH="/home/appuser/.local/bin:$PATH"

# Install poetry and dependencies as non-root user
RUN pip install --no-cache-dir poetry \
    && poetry install --without dev

# GitHub mounts the runner workspace over WORKDIR and requires root for writes.
USER root
ENTRYPOINT ["/app/.venv/bin/python", "-m", "network_reputation_check.action_entrypoint"]
