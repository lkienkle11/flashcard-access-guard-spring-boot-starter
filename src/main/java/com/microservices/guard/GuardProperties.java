package com.microservices.guard;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "flashcard.guard")
public class GuardProperties {
    /** Số ngày TTL lưu Redis. */
    private int ttlDays = 7;
}