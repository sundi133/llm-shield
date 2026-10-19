# The proxy's AI discovery shipper (docs/specs/ai-discovery.md, task 3).
# Standard library only. Build from the repo root:
#   docker build -f deploy/swg/discovery-shipper/Dockerfile -t shield-discovery-shipper .
FROM python:3.12-slim

RUN useradd --system --uid 10001 shipper && mkdir /lists && chown shipper /lists
COPY deploy/swg/discovery-shipper/shipper.py /app/shipper.py
USER shipper
EXPOSE 5140/udp
ENTRYPOINT ["python", "-u", "/app/shipper.py"]
