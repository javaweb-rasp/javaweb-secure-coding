package org.javaweb.code.repository;

import org.javaweb.code.entity.SysUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SysUserRepository extends JpaRepository<SysUser, String>,
		PagingAndSortingRepository<SysUser, String>, JpaSpecificationExecutor<SysUser>, SysUserCustomRepository {

	SysUser findByUsername(String username);

	List<SysUser> findByUsernameIn(List<String> username);

	List<SysUser> findByUsernameLike(String username);

	List<SysUser> findByUsernameLikeOrderByIdDesc(String username);

	@Query(value = "select * from sys_user where username = ?1 ", nativeQuery = true)
	SysUser usernameQueryTest(String username);

	@Query(value = "select * from sys_user where email = :email ", nativeQuery = true)
	SysUser emailQueryTest(String email);

	@Query("from SysUser where id = :id")
	SysUser idQueryTest(Long id);

}
