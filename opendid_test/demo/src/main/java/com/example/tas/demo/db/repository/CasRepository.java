package com.example.tas.demo.db.repository;

import com.example.tas.demo.db.domain.Cas;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories
public interface CasRepository extends JpaRepository<Cas, Long> {
//        Tas save(Tas tas);
//        Optional<Tas> findById(Long id);
//        Optional<Tas> findByName(String txId);
//        List<Tas> findAll();
}
