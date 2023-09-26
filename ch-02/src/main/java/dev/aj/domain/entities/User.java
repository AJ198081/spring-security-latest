package dev.aj.domain.entities;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
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
@Table(name = "spring_security_user")
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
@EqualsAndHashCode(exclude = {"authorities"})
public class User implements Serializable {

    @Serial
    private static final long serialVersionUID = 1;

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "spring_security_user_gen")
    @SequenceGenerator(name = "spring_security_user_gen", sequenceName = "spring_security_user_seq")
    @Column(name = "id", nullable = false)
    @JdbcTypeCode(SqlTypes.BIGINT)
    private Long id;

    private String username;

    private String password;

    @ManyToMany(cascade = CascadeType.PERSIST, fetch = FetchType.EAGER)
    @JoinTable(name = "users_authorities",
            joinColumns = @JoinColumn(name = "user_id"),
    inverseJoinColumns = @JoinColumn(name = "authority_id"))
    private Set<Authority> authorities;


    public void addAuthority(Authority authority) {

        if (Objects.isNull(authorities) || authorities.isEmpty()) {
            authorities = new HashSet<>();
        }

        authority.addUser(this);

        this.authorities.add(authority);
    }

}
