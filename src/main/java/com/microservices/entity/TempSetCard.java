package com.microservices.entity;

public record TempSetCard(
        Long setId,
        String hashPassword,
        Object appUserId
) {
    public TempSetCard() {
        this(null, null, null);
    }

    public TempSetCard(Long setId, String hashPassword, Object appUserId) {
        this.setId = setId;
        this.hashPassword = hashPassword;
        this.appUserId = appUserId;
    }
}
