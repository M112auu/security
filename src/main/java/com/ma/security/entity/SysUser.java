package com.ma.security.entity;

import lombok.Data;

@Data
public class SysUser {
        private String userId;
        private String userName;
        private String passWord;
        private String permission;
}
