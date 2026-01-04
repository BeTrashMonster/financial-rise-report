# Multi-stage build for React Frontend

# Stage 1: Build
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build arguments for Vite environment variables
ARG VITE_API_URL=/api/v1
ARG VITE_APP_NAME="Financial RISE Report"
ARG VITE_ENVIRONMENT=production

# Set environment variables for build
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_APP_NAME=$VITE_APP_NAME
ENV VITE_ENVIRONMENT=$VITE_ENVIRONMENT

# Build the application
RUN npm run build

# Stage 2: Production
FROM caddy:2-alpine AS production

# Copy custom Caddy config
COPY Caddyfile /etc/caddy/Caddyfile

# Copy built files from builder stage
COPY --from=builder /app/dist /usr/share/caddy

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

# Start Caddy
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
