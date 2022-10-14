from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "hello worldddddd"}

# to run the app  uvicorn main:app --reload --port 4304 --host 0.0.0.0