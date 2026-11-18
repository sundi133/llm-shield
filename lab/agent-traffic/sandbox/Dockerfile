# One sandbox image for the lab's agent fleet (spec task 0b, "sandbox variety").
#
# The controller (agents/fleet.py --sandbox docker) stays on the host; each
# agent gets its own container from this image and drives the browser inside
# it over Playwright's browser server. Every container reports the same
# device: that is the device cohort (spec 3.4) the lab measures.
#
# Keep the tag in step with the Playwright client in the lab venv: the
# server and client versions must match exactly.
FROM mcr.microsoft.com/playwright/python:v1.65.2-noble
# The image ships the browsers; the Python package (and its driver, which
# runs the server) is installed here at the same version.
RUN pip install --no-cache-dir --break-system-packages playwright==1.65.2
EXPOSE 3000
CMD ["python3", "-m", "playwright", "run-server", "--port", "3000", "--host", "0.0.0.0"]
