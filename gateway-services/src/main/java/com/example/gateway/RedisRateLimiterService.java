package com.example.gateway;

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class RedisRateLimiterService {

    public Mono<RateLimitDecision> check(ClientContext context, AdaptivePolicy policy) {

        boolean allowed = true;

        return Mono.just(
                new RateLimitDecision(
                        allowed,
                        policy.capacity(),
                        0,
                        "Allowed"
                )
        );
    }
}