FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY mail_tester/ mail_tester/

RUN mkdir -p /app/data/emails

EXPOSE 31337 2525

ENV MAILTESTER_DATA_DIR=/app/data
ENV MAILTESTER_SMTP_PORT=2525
ENV MAILTESTER_WEB_PORT=31337
ENV MAILTESTER_WEB_HOST=0.0.0.0
ENV MAILTESTER_SMTP_HOST=0.0.0.0

CMD ["uvicorn", "mail_tester.main:app", "--host", "0.0.0.0", "--port", "31337"]
