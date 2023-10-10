package org.javaweb.code.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.GenericGenerator;

/**
 * Creator: yz
 * Date: 2020-05-05
 */
@Entity
@Table(name = "sys_user")
@NamedQuery(name = "SysUser.findByUsername", query = "select u from SysUser u where u.username = ?1")
@NamedQuery(name = "SysUser.findByEmail", query = "select u from SysUser u where u.email = ?1")
public class SysUser {

	@Id
	@GenericGenerator(name = "jpa-uuid")
	@GeneratedValue(generator = "jpa-uuid")
	@Column(name = "id", length = 32)
	private Long id;

	private String username;

	private String password;

	private String email;

	private String userAvatar;

	private String registerTime;

	private Object notes;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUserAvatar() {
		return userAvatar;
	}

	public void setUserAvatar(String userAvatar) {
		this.userAvatar = userAvatar;
	}

	public String getRegisterTime() {
		return registerTime;
	}

	public void setRegisterTime(String registerTime) {
		this.registerTime = registerTime;
	}

	public Object getNotes() {
		return notes;
	}

	public void setNotes(Object notes) {
		this.notes = notes;
	}

}
