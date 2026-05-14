package com.example.gateway;

public record AdaptivePolicy(
        int capacity,
        int refillRate,
        String reason
) {
}