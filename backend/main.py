# backend/main.py  ← this sits OUTSIDE the app/ folder
# This is what you run with uvicorn
# Like the entry point that just starts the server

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
