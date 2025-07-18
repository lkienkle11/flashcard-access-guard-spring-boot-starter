package com.microservices.entity;

public record TempSetCard(
        Long setId,
        String hashPassword,
        Object appUserId
) {
}
