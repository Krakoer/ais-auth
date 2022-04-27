from fastapi import FastAPI
from pydantic import BaseModel
import subprocess
from tsai import TsaiKGC
import json
from hashlib import sha256

app = FastAPI()
@app.get("/params")
async def public(kgc_id :str):
    try:
        id_h = sha256(kgc_id.encode('ascii'))
        with open(f"{id_h}/params.txt", 'r') as f:
            params = json.load(f)
        return params

    except e:
        print(f"Error while fetching public params : {e}")
        raise HTTPException(status_code=404, detail="Params not found")


@app.post("/register")
async def register(_id: str, kgc_id:str):
    print(f"Registering {_id.id} to {kgc_id}")
    try:
        h = sha256(_id.encode('ascii'))
        
        output = res.stdout.strip()
        res = {}
        for l in output.splitlines():
            name = l.split(":")[0]
            value = l.split(":")[1]
            res[name] = value
        return res
    except:
        raise HTTPException(status_code=404, detail="Error while registering")
