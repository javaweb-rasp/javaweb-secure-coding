package org.javaweb.code.repository.impl;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.StringUtils;
import org.javaweb.code.entity.SysUser;
import org.javaweb.code.repository.SysUserCustomRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class SysUserCustomRepositoryImpl implements SysUserCustomRepository {

	@PersistenceContext
	private EntityManager entityManager;

	@Override
	public Object jpqlQuery(String username) {
		// JPQL预编译查询
		String sql   = "from SysUser where username = :username";
		Query  query = entityManager.createQuery(sql, SysUser.class);
		query.setParameter("username", username);

		return query.getSingleResult();
	}

	@Override
	public Object jpqlInjection(String username) {
		// JPQL注入写法
		String sql = "from SysUser where username = '" + username + "'";
		return entityManager.createQuery(sql, SysUser.class).getSingleResult();
	}

	@Override
	public Object nativeQuery(String username) {
		// 原生SQL预编译查询
		String sql = "select * from sys_user where username = ?1 ";

		return entityManager.createNativeQuery(sql, SysUser.class).setParameter(1, username).getSingleResult();
	}

	@Override
	public Object nativeInjection(String username) {
		// SQL注入写法
		String sql = "select * from sys_user where username = '" + username + "'";

		return entityManager.createNativeQuery(sql, SysUser.class).getSingleResult();
	}

	@Override
	public Object namedQuery(String username) {
		String sql = "SysUser.findByUsername";
		return entityManager.createNamedQuery(sql, SysUser.class).setParameter(1, username).getSingleResult();
	}

	@Override
	public Object criteriaQuery(String username, String email) {
		CriteriaBuilder        criteriaBuilder = entityManager.getCriteriaBuilder();
		CriteriaQuery<SysUser> criteriaQuery   = criteriaBuilder.createQuery(SysUser.class);
		Root<SysUser>          root            = criteriaQuery.from(SysUser.class);

		// 创建一个 Predicate 列表来存储查询条件
		List<Predicate> predicates = new ArrayList<>();

		if (StringUtils.isNoneEmpty(username)) {
			predicates.add(criteriaBuilder.equal(root.get("username"), username));
		}

		if (StringUtils.isNoneEmpty(email)) {
			predicates.add(criteriaBuilder.equal(root.get("email"), email));
		}

		// 将所有的条件合并为一个总的查询条件（AND 连接）
		criteriaQuery.where(criteriaBuilder.and(predicates.toArray(new Predicate[0])));

		// 执行查询
		return entityManager.createQuery(criteriaQuery).getResultList();
	}

}