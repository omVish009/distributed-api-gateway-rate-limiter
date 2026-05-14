package com.example.gateway;

public record ClientContext(
        String clientId,
        String ip,
        String path,
        String method,
        boolean premium,
        boolean sensitiveEndpoint
) {
}