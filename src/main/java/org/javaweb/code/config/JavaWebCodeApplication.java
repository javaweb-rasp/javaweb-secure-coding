package org.javaweb.code.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@MapperScan("org.javaweb.code.mapper")
@SpringBootApplication(scanBasePackages = "org.javaweb.code.*")
public class JavaWebCodeApplication {

	public static void main(String[] args) {
		SpringApplication.run(JavaWebCodeApplication.class, args);
	}

}
