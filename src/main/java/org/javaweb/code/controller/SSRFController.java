package org.javaweb.code.controller;

import org.apache.commons.io.IOUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URL;
import java.net.URLConnection;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping("/SSRF/")
public class SSRFController {

	@GetMapping("/urlConnection.do")
	public ResponseEntity<byte[]> urlConnection(String url) throws Exception {
		// 禁止url地址未经任何检测直接请求
		URLConnection connection = new URL(url).openConnection();

		return new ResponseEntity<>(IOUtils.toByteArray(connection.getInputStream()), OK);
	}

	@GetMapping("/urlFilterConnection.do")
	public ResponseEntity<byte[]> urlFilterConnection(String url) throws Exception {
		URL u = new URL(url);

		// URL地址的域名，发起Http请求之前需要先校验域名是否合法
		String domain = u.getHost();

		// 设置URL白名单（可在数据库、缓存、文件中配置）
		String[] hostWhitelist = "localhost,127.0.0.1".split(",");

		// URL的域名白名单检测（此处只校验了域名，有必要同时检测请求协议类型、请求端口）
		if (org.apache.commons.lang3.ArrayUtils.contains(hostWhitelist, domain)) {
			URLConnection connection = u.openConnection();

			// 输出Http请求结果
			return new ResponseEntity<>(IOUtils.toByteArray(connection.getInputStream()), OK);
		}

		// 输出403错误信息
		return new ResponseEntity<>("Forbidden".getBytes(), FORBIDDEN);
	}

}
