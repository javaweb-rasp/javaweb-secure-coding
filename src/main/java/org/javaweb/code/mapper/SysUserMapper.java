package org.javaweb.code.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.javaweb.code.entity.SysUser;

import java.util.List;

/**
 * <a href="https://mybatis.org/mybatis-3/zh/dynamic-sql.html">Mybatis动态SQL</a>
 */
@Mapper
public interface SysUserMapper {

	SysUser mybatisStringQuery(@Param("username") String username);

	SysUser mybatisStringInjection(@Param("username") String username);

//	@Select({"<script>" +
//			"select * from sys_user " +
//			"  <if test='order != null'>order by #{order} #{orderType}</if>" +
//			"</script>"
//	})

	@Select("<script>" +
			"select * from sys_user" +
			"<choose>" +
			"    <when  test='order == \"id\"'> " +
			"        order by id" +
			"    </when >" +
			"    <when  test='order == \"username\"'> " +
			"        order by username" +
			"    </when >" +
			"    <otherwise> " +
			"        order by register_time " +
			"    </otherwise>" +
			"</choose>" +
			"<choose>" +
			"    <when test='orderType == \"desc\"'> " +
			"        desc" +
			"    </when>" +
			"    <otherwise> " +
			"        asc" +
			"    </otherwise>" +
			"</choose>" +
			"</script>")
	List<SysUser> mybatisOrderByQuery(@Param("order") String order, @Param("orderType") String orderType);

	@Select({"<script>" +
			"select * from sys_user " +
			"  <if test='order != null'>order by ${order} ${orderType}</if>" +
			"</script>"
	})
	List<SysUser> mybatisOrderByInjection(@Param("order") String order, @Param("orderType") String orderType);

	@Select("select * from sys_user where username like '%' || #{username} || '%'")
// Select("select * from sys_user where username like concat('%', #{username}, '%')") // Mysql
	List<SysUser> mybatisLikeQuery(@Param("username") String username);

	@Select("select * from sys_user where username like '%${username}%'")
	List<SysUser> mybatisLikeInjection(@Param("username") String username);

	@Select({"<script>",
			"select * from sys_user where id in ",
			"<foreach item='id' collection='ids' open='(' separator=', ' close=')'>",
			"  #{id}",
			"</foreach>",
			"</script>"})
	List<SysUser> mybatisWhereInQuery(@Param("ids") List<String> ids);

	@Select("select * from sys_user where id in ( ${ids} )")
	List<SysUser> mybatisWhereInInjection(@Param("ids") String ids);


}
