package com.example.gateway;

import org.springframework.stereotype.Component;

@Component
public class AdaptivePolicyEngine {

    public AdaptivePolicy resolvePolicy(ClientContext context) {
        int baseCapacity;
        int baseRefill;
        String reason;

        if (context.sensitiveEndpoint()) {
            baseCapacity = 20;
            baseRefill = 20;
            reason = "sensitive-endpoint";
        } else if (context.premium()) {
            baseCapacity = 300;
            baseRefill = 300;
            reason = "premium-user";
        } else if ("anonymous".equalsIgnoreCase(context.clientId())) {
            baseCapacity = 30;
            baseRefill = 30;
            reason = "anonymous-ip";
        } else {
            baseCapacity = 60;
            baseRefill = 60;
            reason = "free-user";
        }

        return new AdaptivePolicy(baseCapacity, baseRefill, reason);
    }
}