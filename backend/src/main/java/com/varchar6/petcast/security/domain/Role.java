package com.varchar6.petcast.security.domain;

public enum Role {
      ADMIN("ADMIN", 1)
    , CUSTOMER("CUSTOMER", 2)
    , COMPANY("COMPANY", 3)
    ;

    private final String type;
    private final int roleId;

    Role(String type, int roleId) {
        this.type = type;
        this.roleId = roleId;
    }

    public String getType() {
        return type;
    }

    public int getRoleId() {
        return roleId;
    }
}
