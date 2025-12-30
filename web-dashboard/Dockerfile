FROM nginx:alpine

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy web assets
COPY index.html /usr/share/nginx/html/
COPY assets/ /usr/share/nginx/html/assets/

# Create non-root user
RUN addgroup -g 1001 -S www && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G www -g www www

# Set permissions
RUN chown -R www:www /usr/share/nginx/html && \
    chown -R www:www /var/cache/nginx

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

# Run nginx
CMD ["nginx", "-g", "daemon off;"]