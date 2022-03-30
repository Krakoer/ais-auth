import subprocess
import uvicorn
import time
import os

def main():
    # Launch KGC setup
    print("Setting up public params...")
    subprocess.run(["./KGC", "setup"], stdin=open("a.param"))
    
    # Launch the server
    uvicorn.run("app:app", host="127.0.0.1", port=5000, log_level="info")
    try:
        os.remove("./p_params.txt")
        os.remove("./s_key.txt")
    except:
        pass

if __name__ == "__main__":
    main()