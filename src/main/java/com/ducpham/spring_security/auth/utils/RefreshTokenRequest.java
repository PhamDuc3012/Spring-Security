package com.ducpham.spring_security.auth.utils;

import lombok.Data;

@Data
public class RefreshTokenRequest {
    private String refreshToken;
}
