FROM python:2.7
ENV PYTHONUNBUFFERED 1
RUN groupadd -r manati \
&& useradd -r -g manati manati_user

RUN apt-get update && apt-get install -y gcc
RUN apt-get install -y python python-pip python-dev libpq-dev python-setuptools \
                        build-essential \
                        software-properties-common
RUN apt-get install -y  libssl-dev libffi-dev
RUN mkdir /code
WORKDIR /code/
ADD ./requirements/base.txt /code/
ADD ./requirements/local.txt /code/
RUN pip install --upgrade pip
RUN pip install --no-cache-dir  setuptools
RUN pip install --no-cache-dir  -r local.txt
ADD . /code/
