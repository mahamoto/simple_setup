FROM zokrates/zokrates:0.8.4

USER root
ENV TZ=Europe/Moscow
ENV PROD=true
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update
RUN apt-get install -y python3-pip && apt-get install -y bc
COPY ./audit/requirements.txt requirements.txt
RUN python3 -m pip install -r requirements.txt

COPY . .
RUN mkdir out
RUN chmod u+x run.sh

CMD ["bash", "run.sh"]