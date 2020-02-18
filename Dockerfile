FROM python:3.7.2-alpine3.9

RUN apk add gcc python-dev build-base wget libpng-dev freetype-dev openblas-dev

RUN pip install numpy && \
    pip install pandas && \
    pip install scipy && \
    pip install scikit-learn

RUN pip install pykka && \
    pip install ujson

RUN apk add vim
RUN pip install matplotlib
RUN pip install ipython

