package com.example.gateway;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Component
public class ClientContextExtractor {

    public ClientContext extract(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();

        String clientId = headerOrDefault(request, "X-Client-Id", "anonymous");
        String plan = headerOrDefault(request, "X-User-Plan", "free");
        String ip = extractIp(request);
        String path = request.getURI().getPath();
        String method = request.getMethod() != null ? request.getMethod().name() : "GET";

        boolean premium = "premium".equalsIgnoreCase(plan);
        boolean sensitiveEndpoint = path.contains("/login") || path.contains("/auth") || path.contains("/heavy");

        return new ClientContext(clientId, ip, path, method, premium, sensitiveEndpoint);
    }

    private String headerOrDefault(ServerHttpRequest request, String header, String fallback) {
        String value = request.getHeaders().getFirst(header);
        return (value == null || value.isBlank()) ? fallback : value;
    }

    private String extractIp(ServerHttpRequest request) {
        String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        if (request.getRemoteAddress() != null && request.getRemoteAddress().getAddress() != null) {
            return request.getRemoteAddress().getAddress().getHostAddress();
        }
        return "unknown";
    }
}