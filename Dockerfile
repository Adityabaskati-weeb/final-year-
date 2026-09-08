FROM node:22-bookworm-slim AS dashboard
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ backend/
COPY ml/ ml/
COPY run_demo.py ./
COPY --from=dashboard /build/dist frontend/dist/
RUN useradd --create-home iot && mkdir runtime && chown -R iot:iot /app
USER iot
EXPOSE 8020
CMD ["sh", "-c", "python -m ml.train --demo && DEMO_AUTOSTART=1 python -m uvicorn backend.main:create_app --factory --host 0.0.0.0 --port 8020"]
