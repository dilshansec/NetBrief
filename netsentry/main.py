"""Local-first API. Bounded reports live in memory and expire; uploads are closed."""
import asyncio
from contextlib import asynccontextmanager, suppress
from collections import deque, OrderedDict
import json
import os
from pathlib import Path
import secrets
import sys
import time
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request, Header, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.formparsers import MultiPartException
from pydantic import ValidationError
from netsentry.config import Settings

ROOT=Path(__file__).resolve().parents[1]
MAX_UPLOAD=int(os.getenv('NETSENTRY_MAX_UPLOAD_MB','10'))*1024*1024
TIMEOUT=int(os.getenv('NETSENTRY_TIMEOUT_SECONDS','45'))
TTL=int(os.getenv('NETSENTRY_REPORT_TTL_SECONDS','900'))
@asynccontextmanager
async def lifespan(app):
    async def reap():
        while True:
            await asyncio.sleep(30)
            now=time.monotonic()
            for key in list(reports):
                if now-reports[key][0]>TTL:reports.pop(key,None)
    task=asyncio.create_task(reap())
    try:yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):await task

app=FastAPI(lifespan=lifespan,title='NetSentry Investigation API',version='0.3.0',docs_url=None,redoc_url=None)
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
reports=OrderedDict(); requests=deque(maxlen=100); active=0

class BodyLimit:
    def __init__(self,app):self.app=app
    async def __call__(self,scope,receive,send):
        size=0
        async def bounded_receive():
            nonlocal size
            message=await receive()
            size+=len(message.get('body',b''))
            if size>MAX_UPLOAD+65536:
                # Starlette's multipart handler closes all spooled files on this exception.
                raise MultiPartException('Upload body exceeds configured limit')
            return message
        await self.app(scope,bounded_receive if scope['type']=='http' else receive,send)

app.add_middleware(BodyLimit)

@app.middleware('http')
async def guard(request:Request,call_next):
    if request.method=='POST' and request.url.path=='/api/analyze':
        if request.headers.get('origin') and request.headers['origin']!=str(request.base_url).rstrip('/'):
            return JSONResponse({'detail':'Cross-origin uploads are not allowed'},403)
        try: size=int(request.headers.get('content-length','0'))
        except ValueError:return JSONResponse({'detail':'Invalid Content-Length'},400)
        if size<=0:return JSONResponse({'detail':'Content-Length is required'},411)
        if size>MAX_UPLOAD+65536:return JSONResponse({'detail':'Upload exceeds configured size limit'},413)
        now=time.monotonic()
        while requests and now-requests[0]>60:requests.popleft()
        if len(requests)>=20:return JSONResponse({'detail':'Analysis rate limit reached. Retry in one minute.'},429)
        requests.append(now)
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"})
    return response

@app.get('/')
def home():return FileResponse(ROOT/'static'/'index.html')

@app.get('/api/docs',include_in_schema=False)
def api_docs():return FileResponse(ROOT/'API.md',media_type='text/plain; charset=utf-8')

@app.get('/api/health')
def health():return {'status':'ok','version':'0.3.0'}

@app.get('/api/config')
def config():return {'defaults':Settings().model_dump(),'limits':{'upload_bytes':MAX_UPLOAD,'packets':int(os.getenv('NETSENTRY_MAX_PACKETS','50000')),'timeout_seconds':TIMEOUT,'concurrent_analyses':1,'report_ttl_seconds':TTL,'retained_reports':4,'os_memory_limit':os.name=='posix'}}

@app.post('/api/analyze')
async def upload(file:UploadFile=File(...),settings:str=Form('{}'),include_packets:bool=Query(False)):
    global active
    try:
        try:c=Settings.model_validate_json(settings)
        except (ValidationError,ValueError):raise HTTPException(422,'Invalid detection settings')
        name=Path((file.filename or '').replace('\\','/')).name[:180]
        if not name.lower().endswith(('.pcap','.pcapng','.cap')):raise HTTPException(400,'Please upload a PCAP or PCAPNG capture')
        if active:raise HTTPException(429,'Another capture is being analyzed. Retry shortly.')
        active+=1
        try:
            data=await file.read(MAX_UPLOAD+1)
            if len(data)>MAX_UPLOAD:raise HTTPException(413,'Upload exceeds configured size limit')
            if data[:4] not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'):raise HTTPException(400,'Invalid capture signature')
            proc=await asyncio.create_subprocess_exec(sys.executable,'-m','netsentry.worker',cwd=str(ROOT),stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            try:
                output,_=await asyncio.wait_for(proc.communicate(c.model_dump_json().encode()+b'\n'+data),TIMEOUT)
            except asyncio.TimeoutError:raise HTTPException(408,'Analysis exceeded the time limit')
            finally:
                if proc.returncode is None:
                    proc.kill();await proc.wait()
            if proc.returncode:raise HTTPException(422,'Analysis worker exceeded resources or could not decode this capture')
            result=json.loads(output)
            if 'error' in result:raise HTTPException(400,result['error'])
            report=result['result'];report['filename']=name
            now=time.monotonic()
            for key in list(reports):
                if now-reports[key][0]>TTL:del reports[key]
            while len(reports)>=4:reports.popitem(last=False)
            identifier=secrets.token_urlsafe(24);token=secrets.token_urlsafe(32)
            report['analysis_id']=identifier
            reports[identifier]=(now,token,report)
            return {**{k:v for k,v in report.items() if k!='packets'},'packets':report['packets'] if include_packets else [],'packet_count':len(report['packets']),'access_token':token,'status':'complete'}
        finally:active-=1
    finally:await file.close()


def get_report(identifier,authorization):
    entry=reports.get(identifier)
    if not entry or time.monotonic()-entry[0]>TTL:
        reports.pop(identifier,None);raise HTTPException(404,'Analysis unavailable or expired')
    if not secrets.compare_digest(authorization or '', 'Bearer '+entry[1]):raise HTTPException(404,'Analysis unavailable or expired')
    return entry[2]

@app.get('/api/analyses/{identifier}/{section}')
def section(identifier:str,section:str,authorization:str|None=Header(None),offset:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=1000),query:str=Query('',max_length=200),ip:str=Query('',max_length=100),protocol:str=Query('',max_length=30)):
    r=get_report(identifier,authorization)
    if section=='status':return {'status':'complete'}
    if section=='summary':return r['summary']
    if section not in ('packets','alerts','hosts','flows','timeline','coverage'):raise HTTPException(404,'Unknown section')
    rows=r[section]
    if section=='packets':
        rows=[p for p in rows if (not ip or ip in (p['src'],p['dst'])) and (not protocol or p['protocol']==protocol) and (not query or query.lower() in str(p).lower())]
    return {'total':len(rows),'offset':offset,'items':rows[offset:offset+limit]}

@app.get('/api/analyses/{identifier}/alerts/{alert_id}/evidence')
def evidence(identifier:str,alert_id:str,authorization:str|None=Header(None)):
    r=get_report(identifier,authorization)
    a=next((a for a in r['alerts'] if a['id']==alert_id),None)
    if not a:raise HTTPException(404,'Unknown alert')
    ids=set(a['packet_numbers']);return {'alert':a,'packets':[p for p in r['packets'] if p['no'] in ids]}

@app.get('/sample')
@app.get('/sample/conversation')
def conversation_sample():return FileResponse(ROOT/'samples'/'demo_conversation.pcap',media_type='application/vnd.tcpdump.pcap')

@app.get('/api/samples')
def samples():
    from samples.lab import NAMES
    return NAMES

@app.get('/sample/lab/{name}')
def lab(name:str):
    from samples.lab import generate, NAMES
    from fastapi.responses import Response
    if name not in NAMES:raise HTTPException(404,'Unknown sample')
    return Response(generate(name),media_type='application/vnd.tcpdump.pcap')
