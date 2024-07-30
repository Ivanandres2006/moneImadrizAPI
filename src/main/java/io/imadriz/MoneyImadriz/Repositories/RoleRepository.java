package io.imadriz.MoneyImadriz.Repositories;

import io.imadriz.MoneyImadriz.Models.ERole;
import io.imadriz.MoneyImadriz.Models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);

}
