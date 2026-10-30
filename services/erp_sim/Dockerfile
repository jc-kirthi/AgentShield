FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn sqlalchemy psycopg[binary] pydantic reportlab pypdf pyjwt cryptography rapidfuzz

COPY libs/ /app/libs/
COPY contracts/ /app/contracts/
COPY services/erp_sim/ /app/services/erp_sim/

ENV PYTHONPATH=/app
ENV ERP_DB_URL=sqlite:////app/erp_sim.db
EXPOSE 8001

CMD ["uvicorn", "services.erp_sim.app.main:app", "--host", "0.0.0.0", "--port", "8001"]
