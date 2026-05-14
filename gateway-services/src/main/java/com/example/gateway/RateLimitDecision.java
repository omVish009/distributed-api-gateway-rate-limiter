package com.example.gateway;

public record RateLimitDecision(
        boolean allowed,
        long remainingTokens,
        long retryAfterSeconds,
        String reason
) {
}