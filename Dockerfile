FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -e .

# ENTRYPOINT allows GitHub Actions `args` (and `docker run ... scan ...`) to append
# subcommands after the executable instead of replacing the full command line.
ENTRYPOINT ["django_security_hunter"]
CMD ["scan", "--project", "/app", "--format", "console"]

