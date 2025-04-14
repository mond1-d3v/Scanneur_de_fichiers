import uvicorn
from uvicorn.middleware.wsgi import WSGIMiddleware
from api.server import create_app

flask_app = create_app()

app = WSGIMiddleware(flask_app)

if __name__ == "__main__":
    uvicorn.run("asgi:app", host="0.0.0.0", port=5000, log_level="info")
