from fastapi import FastAPI, HTTPException, UploadFile, File
from Analyzer.analyzer import log_check, parse_lines, find_brute_attempts
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)



DEFAULT_LOG_PATH = "syslog.log"


@app.get("/")
def check():
    return {"status" : "ok", "message" : "SysLog Analyzer is running!"}


@app.get("/api/summary")
def get_summary(min_attempts: int = 10):
    try:
        summary_df = log_check(DEFAULT_LOG_PATH, min_attempts=min_attempts)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"{DEFAULT_LOG_PATH} not found on the server")
    return summary_df.to_dict(orient="records")


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), min_attempts: int = 10):
    contents = await file.read()
    lines = contents.decode("utf-8", errors="ignore").splitlines()
    parsed = parse_lines(lines)
    summary_df = find_brute_attempts(parsed, min_attempts=min_attempts)
    return summary_df.to_dict(orient="records")