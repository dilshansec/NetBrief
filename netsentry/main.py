from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from netsentry.parser import CaptureError, analyze

ROOT=Path(__file__).resolve().parents[1]
MAX_UPLOAD=25*1024*1024
app=FastAPI(title='NetSentry MVP',version='0.1.0',docs_url='/api/docs')

@app.get('/')
def home():
    return FileResponse(ROOT/'static'/'index.html')

@app.get('/api/health')
def health():
    return {'status':'ok','version':'0.1.0'}

@app.post('/api/analyze')
async def upload(file: UploadFile=File(...)):
    name=Path(file.filename or '').name
    if not name.lower().endswith(('.pcap','.pcapng','.cap')):
        raise HTTPException(400,'Please upload a .pcap or .pcapng capture')
    data=await file.read(MAX_UPLOAD+1)
    await file.close()
    if len(data)>MAX_UPLOAD:raise HTTPException(413,'Maximum upload size: 25 MB')
    try:return analyze(data,name)
    except (CaptureError,OverflowError,ValueError) as exc:raise HTTPException(400,str(exc)) from exc

@app.get("/sample")
def sample():
    return FileResponse(ROOT/"samples"/"demo_scan.pcap",media_type="application/vnd.tcpdump.pcap")
