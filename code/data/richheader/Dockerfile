FROM python:alpine

# add tornado
RUN pip3 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

###
# Rich Header specific options
###

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY prodids.py /service
COPY richlibrary.py /service
COPY rich.py /service

CMD ["python3", "rich_web.py"]

EXPOSE 8080
