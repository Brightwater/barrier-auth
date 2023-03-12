FROM python:3.10

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --upgrade pip

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./app /code/apps

WORKDIR /code/apps

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "4344"]