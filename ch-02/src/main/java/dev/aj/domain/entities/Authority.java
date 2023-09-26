package dev.aj.domain.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.SequenceGenerator;
import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString(exclude = {"users"})
@EqualsAndHashCode(exclude = {"users", "id"})
@Builder
public class Authority implements Serializable {

    @Serial
    private static final long serialVersionUID = 1;

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "authority_gen")
    @SequenceGenerator(name = "authority_gen", sequenceName = "authority_seq")
    @Column(name = "id", nullable = false)
    @JdbcTypeCode(SqlTypes.INTEGER)
    private Integer id;

    private String name;

    @ManyToMany(mappedBy = "authorities")
    private Set<User> users;

    public void addUser(User user) {
        if (Objects.isNull(users) || this.users.isEmpty()) {
            this.users = new HashSet<>();
        }

        this.users.add(user);
    }
}
