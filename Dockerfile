FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples
RUN pip install . && useradd --create-home mailhdr
USER mailhdr

# Analyse a message from a mounted folder, or from standard input:
#   docker run --rm -v "$PWD:/mail:ro" mailhdr analyze /mail/message.eml
#   docker run --rm -i mailhdr analyze - < message.eml
# It makes DNS queries (SPF, DKIM keys, DMARC); add --offline to make none.
ENTRYPOINT ["mailhdr"]
CMD ["--help"]
