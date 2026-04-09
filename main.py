"""
Главная точка входа

После запуска:
  - Swagger: http://localhost:8000/docs
  - OpenAPI JSON: http://localhost:8000/openapi.json

Методы:

1. POST /url/predict
   проверка одного URL

2. POST /url/predict_batch
   проверка списка URL

3. POST /traffic/predict
   проверка одного сетевого потока

4. POST /traffic/predict_batch
   проверка списка сетевых потоков
"""

import uvicorn
from fastapi import FastAPI

from step3 import router as url_router
from step6 import router as traffic_router

app = FastAPI()

app.include_router(url_router)
app.include_router(traffic_router)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)