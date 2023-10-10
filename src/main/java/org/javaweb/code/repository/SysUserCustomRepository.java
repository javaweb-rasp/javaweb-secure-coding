package org.javaweb.code.repository;

public interface SysUserCustomRepository {

	Object jpqlQuery(String username);

	Object jpqlInjection(String username);

	Object nativeQuery(String username);

	Object nativeInjection(String username);

	Object namedQuery(String username);

	Object criteriaQuery(String username, String email);

}
