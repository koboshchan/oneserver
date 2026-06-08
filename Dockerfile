# Stage 1: Build configuration
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy generator and configuration requirements
COPY generate_nginx_config.py .
COPY settings.json .
COPY services/ ./services/

# Generate the monolithic nginx.conf
RUN python3 generate_nginx_config.py --input settings.json --output nginx.conf

# Stage 2: Final production image
FROM nginx:alpine

# Copy generated config from builder
COPY --from=builder /app/nginx.conf /etc/nginx/nginx.conf

# Ensure standard Nginx directories exist
RUN mkdir -p /etc/nginx/ssl /var/www/certbot

EXPOSE 80 443
