"""Disposable analysis worker. OS memory limits apply on supported Unix systems."""
import json
import os
import sys

def main():
    if os.name=='posix':
        import resource
        memory=int(os.getenv('NETSENTRY_WORKER_MB','512'))*1024*1024
        resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
        resource.setrlimit(resource.RLIMIT_CPU,(30,30))
    from netsentry.parser import analyze
    settings=json.loads(sys.stdin.buffer.readline())
    blob=sys.stdin.buffer.read()
    try:
        result=analyze(blob,'capture',settings)
        sys.stdout.write(json.dumps({'result':result},allow_nan=False))
    except (ValueError,OverflowError,MemoryError):
        sys.stdout.write(json.dumps({'error':'Capture is malformed or exceeds analysis resources.'}))

if __name__=='__main__':main()
