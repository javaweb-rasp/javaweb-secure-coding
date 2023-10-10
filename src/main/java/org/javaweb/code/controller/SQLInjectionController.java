package org.javaweb.code.controller;

import jakarta.annotation.Resource;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.javaweb.code.entity.SysUser;
import org.javaweb.code.mapper.SysUserMapper;
import org.javaweb.code.repository.SysUserRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/SQL")
public class SQLInjectionController {

	@Resource
	private SysUserMapper sysUserMapper;

	@Resource
	private JdbcTemplate jdbcTemplate;

	@Resource
	private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

	@Resource
	private DataSource dataSource;

	@Resource
	private SysUserRepository sysUserRepository;

	@GetMapping("/Mybatis/mybatisStringQuery.do")
	public SysUser mybatisStringQuery(String username) {
		return sysUserMapper.mybatisStringQuery(username);
	}

	@GetMapping("/Mybatis/mybatisStringInjection.do")
	public SysUser mybatisStringInjection(String username) {
		return sysUserMapper.mybatisStringInjection(username);
	}

	@GetMapping("/Mybatis/mybatisOrderByQuery.do")
	public List<SysUser> mybatisOrderByQuery(String order, String orderType) {
		return sysUserMapper.mybatisOrderByQuery(order, orderType);
	}

	@GetMapping("/Mybatis/mybatisOrderByInjection.do")
	public List<SysUser> mybatisOrderByInjection(String order, String orderType) {
		return sysUserMapper.mybatisOrderByInjection(order, orderType);
	}

	@GetMapping("/Mybatis/mybatisLikeQuery.do")
	public List<SysUser> mybatisLikeQuery(String username) {
		return sysUserMapper.mybatisLikeQuery(username);
	}

	@GetMapping("/Mybatis/mybatisLikeInjection.do")
	public List<SysUser> mybatisLikeInjection(String username) {
		return sysUserMapper.mybatisLikeInjection(username);
	}

	@GetMapping("/Mybatis/mybatisWhereInQuery.do")
	public List<SysUser> mybatisWhereInQuery(String ids) {
		List<String> idList = Arrays.asList(ids.split(","));

		return sysUserMapper.mybatisWhereInQuery(idList);
	}

	@GetMapping("/Mybatis/mybatisWhereInInjection.do")
	public List<SysUser> mybatisWhereInInjection(String ids) {
		return sysUserMapper.mybatisWhereInInjection(ids);
	}

	@GetMapping("/JDBC/jdbcStringInjection.do")
	public SysUser jdbcStringInjection(String id) throws SQLException {
		// 获取数据库连接对象
		Connection connection = dataSource.getConnection();

		String sql = "select * from sys_user where id = " + id;

		// 创建预编译对象
		PreparedStatement pstt = connection.prepareStatement(sql);

		// 提取查询结果集
		return extractResultSet(pstt);
	}

	@GetMapping("/JDBC/jdbcStringQuery.do")
	public SysUser jdbcStringQuery(String id) throws SQLException {
		// 获取数据库连接对象
		Connection connection = dataSource.getConnection();

		String sql = "select * from sys_user where id = ? ";

		// SQL参数编译对象
		PreparedStatement pstt = connection.prepareStatement(sql);
		pstt.setObject(1, id);

		// 提取查询结果集
		return extractResultSet(pstt);
	}

	private SysUser extractResultSet(PreparedStatement pstt) throws SQLException {
		// 执行SQL并返回结果集
		ResultSet rs = pstt.executeQuery();

		SysUser user = new SysUser();

		while (rs.next()) {
			user.setId(rs.getLong("id"));
			user.setUsername(rs.getString("username"));
			user.setPassword(rs.getString("password"));
			user.setEmail(rs.getString("email"));
			user.setUserAvatar(rs.getString("user_avatar"));
			user.setRegisterTime(rs.getString("register_time"));
			user.setNotes(rs.getString("notes"));
		}

		return user;
	}

	@GetMapping("/Spring/jdbcTemplateStringInjection.do")
	public Map<String, Object> jdbcTemplateStringInjection(String username) {
		String sql = "select * from sys_user where username = '" + username + "'";

		return jdbcTemplate.queryForMap(sql);
	}

	@GetMapping("/Spring/jdbcTemplateOrderByQuery.do")
	public List<Map<String, Object>> jdbcTemplateOrderByQuery(String order, String orderType) {
		// 限制order by拼接的字段
		final String[] cols  = "id,username,register_time".split(",");
		final String[] types = "desc,asc".split(",");
		StringBuilder  sql   = new StringBuilder("select * from sys_user");

		// 安全的拼接order by SQL
		if (StringUtils.isNoneEmpty(order) && StringUtils.isNoneEmpty(orderType)) {
			order = org.apache.commons.lang3.ArrayUtils.contains(cols, order) ? order : "id";
			orderType = org.apache.commons.lang3.ArrayUtils.contains(types, orderType) ? "desc" : "asc";

			sql.append(" order by ").append(order).append(" ").append(orderType);
		}

		return jdbcTemplate.queryForList(sql.toString());
	}

	@GetMapping("/Spring/jdbcTemplateOrderByAppendQuery.do")
	public List<Map<String, Object>> jdbcTemplateOrderByAppendQuery(String order, String orderType) {
		StringBuilder sql = new StringBuilder("select * from sys_user");

		if (StringUtils.isNoneEmpty(order)) {
			sql.append(" order by ");

			// 拼接排序规则
			if ("id".equalsIgnoreCase(order)) {
				sql.append("id");
			}

			// 排序方式
			if ("desc".equalsIgnoreCase(orderType)) {
				sql.append(" desc ");
			}
		}

		return jdbcTemplate.queryForList(sql.toString());
	}

	@GetMapping("/Spring/jdbcTemplateOrderByInjection.do")
	public List<Map<String, Object>> jdbcTemplateOrderByInjection(String order, String orderType) {
		String sql = "select * from sys_user order by " + order + " " + orderType;

		return jdbcTemplate.queryForList(sql);
	}

	@GetMapping("/Spring/jdbcTemplateLikeQuery.do")
	public List<Map<String, Object>> jdbcTemplateLikeQuery(String username) {
		String sql = "select * from sys_user where username like ? ";

		return jdbcTemplate.queryForList(sql, "%" + username + "%");
	}

	@GetMapping("/Spring/jdbcTemplateLikeInjection.do")
	public List<Map<String, Object>> jdbcTemplateLikeInjection(String username) {
		String sql = "select * from sys_user where username like '%" + username + "%'";

		return jdbcTemplate.queryForList(sql);
	}

	@GetMapping("/Spring/jdbcTemplateWhereInInjection.do")
	public List<Map<String, Object>> jdbcTemplateWhereInInjection(String ids) {
		String sql = "select * from sys_user where id in ( " + ids + " ) ";

		return jdbcTemplate.queryForList(sql);
	}

	@GetMapping("/Spring/jdbcTemplateWhereInQuery.do")
	public List<Map<String, Object>> jdbcTemplateWhereInQuery(String ids) {
		String sql = "select * from sys_user where id in ( :ids ) ";

		// ids可以直接接String[]也可以
		List<String> idList = Arrays.asList(ids.split(","));

		Map<String, Object> sqlParameter = new HashMap<>();
		sqlParameter.put("ids", idList);

		// 使用namedParameterJdbcTemplate而不是jdbcTemplate
		return namedParameterJdbcTemplate.queryForList(sql, sqlParameter);
	}

	@GetMapping("/JPA/jpaWhereInQuery.do")
	public List<SysUser> jpaWhereInQuery(String[] users) {
		return sysUserRepository.findByUsernameIn(Arrays.asList(users));
	}

	@GetMapping("/JPA/jpaLikeQuery.do")
	public List<SysUser> jpaLikeQuery(String username) {
		return sysUserRepository.findByUsernameLike("%" + username + "%");
	}

	@GetMapping("/JPA/jpaStringQuery.do")
	public SysUser jpaStringQuery(String username) {
		return sysUserRepository.findByUsername(username);
	}

	@GetMapping("/JPA/jpaLikeAndOrderByQuery.do")
	public List<SysUser> jpaLikeAndOrderByQuery(String username) {
		return sysUserRepository.findByUsernameLikeOrderByIdDesc("%" + username + "%");
	}

	@GetMapping("/JPA/jpaUsernameBindTest.do")
	public SysUser jpaUsernameBindTest(String username) {
		return sysUserRepository.usernameQueryTest(username);
	}

	@GetMapping("/JPA/jpaEmailBindTest.do")
	public SysUser jpaEmailBindTest(String username) {
		return sysUserRepository.emailQueryTest(username);
	}

	@GetMapping("/JPA/jpaIdBindTest.do")
	public SysUser jpaIdBindTest(Long id) {
		return sysUserRepository.idQueryTest(id);
	}

	@GetMapping("/JPA/jpqlQuery.do")
	public Object jpqlQuery(String username) {
		return sysUserRepository.jpqlQuery(username);
	}

	@GetMapping("/JPA/jpqlInjection.do")
	public Object jpqlInjection(String username) {
		return sysUserRepository.jpqlInjection(username);
	}

	@GetMapping("/JPA/nativeQuery.do")
	public Object nativeQuery(String username) {
		return sysUserRepository.nativeQuery(username);
	}

	@GetMapping("/JPA/nativeInjection.do")
	public Object nativeInjection(String username) {
		return sysUserRepository.nativeInjection(username);
	}

	@GetMapping("/JPA/namedQuery.do")
	public Object namedQuery(String username) {
		return sysUserRepository.namedQuery(username);
	}

	@GetMapping("/JPA/criteriaQuery.do")
	public Object criteriaQuery(String username, String email) {
		return sysUserRepository.criteriaQuery(username, email);
	}

	public static void main(String[] args) throws Exception {
//		File f = new File("d:/323.txt/");
//		FileUtils.writeStringToFile(f, "test5");

		File file = new File("D:\\Documents\\Servers\\apache-tomcat-8.5.83\\conf\\catalina.properties..././");
		System.out.println(FileUtils.readFileToString(file));
	}

}
