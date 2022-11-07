FROM python:latest

# Add CA certificates
RUN apt update && apt upgrade -y \
    && apt install openssl \
    && rm -rf /var/lib/apt/lists/

WORKDIR /app

# Directories described in the configuration file
RUN mkdir ./logs
RUN mkdir ./custom_functions
VOLUME "/app/logs"

# In case you use TLS
# ===================
# RUN mkdir ./tls
# COPY /path/to/your/certs /app/tls
# COPY /path/to/your/priv_keys /app/tls

# Port for the interaction in server mode
EXPOSE 8888

# Move the application and the configuration file
COPY src ./
COPY ext_conn_config.ini ./
COPY custom_functions ./custom_functions

# Install dependencies
RUN pip3 install -r requirements.txt

# Run the application
CMD [ "python3", "start.py"]