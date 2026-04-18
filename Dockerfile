FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -e .

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# ENTRYPOINT allows GitHub Actions `args` (and `docker run ... scan ...`) to append
# subcommands after the executable instead of replacing the full command line.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["scan", "--project", "/app", "--format", "console"]

