import uvicorn

from seceventmonitor import create_app


def main() -> None:
    app = create_app()
    uvicorn.run(app, host="127.0.0.1", port=20000, reload=False)


if __name__ == "__main__":
    main()
