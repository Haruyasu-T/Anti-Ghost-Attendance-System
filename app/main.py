from fastapi import FastAPI

app = FastAPI(title="学内Wi-Fi連動 QR出席管理システム")


@app.get("/health")
def health():
    return {"status": "ok"}
