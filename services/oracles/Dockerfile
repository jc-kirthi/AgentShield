FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn pydantic pyjwt

COPY libs/ /app/libs/
COPY contracts/ /app/contracts/
COPY services/oracles/ /app/services/oracles/

ENV PYTHONPATH=/app
EXPOSE 8002

CMD ["uvicorn", "services.oracles.app.main:app", "--host", "0.0.0.0", "--port", "8002"]
