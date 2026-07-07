FROM python:3.12-slim
RUN pip install --no-cache-dir lxml
ARG flag=FLAG{selftest-default}
RUN printf '%s\n' "$flag" > /flag.txt
COPY server.py /app/server.py
EXPOSE 8000
CMD ["python", "/app/server.py"]
