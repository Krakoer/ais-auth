from fastapi import FastAPI
from pydantic import BaseModel
import subprocess
import hashlib

class ID(BaseModel):
    id: str

app = FastAPI()
@app.get("/params")
async def public():
    try: 
        with open("p_params.txt", 'r') as f:
            params = {}
            for l in f.readlines():
                name = l.strip().split(':')[0]
                value = l.strip().split(':')[1]
                params[name] = value
        return params

    except e:
        print(f"Error while fetching public params : {e}")
        raise HTTPException(status_code=404, detail="Params not found")


@app.post("/register")
async def register(_id: ID):
    print(f"Registering {_id.id}")
    try:
        h = hashlib.sha256()
        h.update(_id.id.encode("ascii"))
        res = subprocess.run(["./KGC", "register", h.digest()], capture_output=True, text=True, stdin=open("a.param"))
        output = res.stdout.strip()
        res = {}
        for l in output.splitlines():
            name = l.split(":")[0]
            value = l.split(":")[1]
            res[name] = value
        return res
    except:
        raise HTTPException(status_code=404, detail="Error while registering")
