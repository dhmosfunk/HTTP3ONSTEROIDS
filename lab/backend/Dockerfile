FROM python:3.8-slim

WORKDIR /app

COPY . /app

RUN pip install Flask

ENV FLASK_APP=app.py

EXPOSE 8080

CMD ["flask", "run", "--host=0.0.0.0", "--port=8080"]
