# ==============================================================================
# Stage 1: Build Frontend Static Assets with Vite
# ==============================================================================
FROM node:22-alpine AS frontend-builder

WORKDIR /build

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Unprivileged Nginx Reverse Proxy & Static Server
# ==============================================================================
FROM nginxinc/nginx-unprivileged:1.27-alpine

USER root
RUN rm -rf /etc/nginx/conf.d/default.conf /usr/share/nginx/html/*
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=frontend-builder --chown=nginx:nginx /build/dist /usr/share/nginx/html
USER nginx

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
