from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import orders, results, staff

app = FastAPI(title="Lab results")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(results.router)
app.include_router(orders.router)
app.include_router(staff.router)


@app.get("/health")
def health():
    return {"status": "ok"}
