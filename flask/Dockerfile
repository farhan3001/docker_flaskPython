FROM tiangolo/uwsgi-nginx-flask:python3.8

# EXPOSE 5005
WORKDIR /app

COPY ./app/requirements.txt /app/
RUN pip install -r requirements.txt

COPY ./app /app
# COPY main.py /app
# CMD python main.py