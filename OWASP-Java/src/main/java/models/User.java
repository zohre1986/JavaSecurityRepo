package models;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.io.Serializable;
import java.sql.Timestamp;

@Data
@RequiredArgsConstructor
public final class User implements Serializable {
    private static final long serialVersionUID = 3848335680382830605L;

    public final String username, role, password;
    public final Timestamp created_at, updated_at;

    public User(String username, String role, String password, Timestamp created_at, Timestamp updated_at) {
        this.username = username;
        this.role = role;
        this.password = password;
        this.created_at = created_at;
        this.updated_at = updated_at;
    }
}
