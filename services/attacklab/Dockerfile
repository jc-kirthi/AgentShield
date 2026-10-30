FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn pydantic httpx pyjwt cryptography reportlab pypdf

COPY libs/ /app/libs/
COPY contracts/ /app/contracts/
COPY services/erp_sim/ /app/services/erp_sim/
COPY services/attacklab/ /app/services/attacklab/

ENV PYTHONPATH=/app
ENV SANDBOX=1
EXPOSE 8004

CMD ["uvicorn", "services.attacklab.app.main:app", "--host", "0.0.0.0", "--port", "8004"]
