package org.javaweb.code.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/CMD/")
public class CMDController {

	@GetMapping("/ping.do")
	public String ping(String host) throws IOException {
		try {
			// DNS解析传入的host，如果无法访问将会抛出UnknownHostException
			InetAddress.getByName(host);

			boolean isWindows = System.getProperty("os.name").startsWith("Win");

			// ping 3次目标主机
			String cmd = (isWindows ? "cmd /c ping -n 3 " : "/bin/sh ping -c 3 ") + host;

			Process process = Runtime.getRuntime().exec(cmd);
			process.waitFor();

			// 输出命令执行结果
			return new String(process.getInputStream().readAllBytes(), isWindows ? "GBK" : "UTF-8");
		} catch (UnknownHostException | InterruptedException e) {
			return "主机无法访问！";
		}
	}

	@GetMapping("/pingRCE.do")
	public String pingRCE(String host) throws Exception {
		boolean isWindows = System.getProperty("os.name").startsWith("Win");

		// ping 3次目标主机
		String cmd = (isWindows ? "cmd /c ping -n 3 " : "/bin/sh ping -c 3 ") + host;

		Process process = Runtime.getRuntime().exec(cmd);
		process.waitFor();

		// 输出命令执行结果
		return new String(process.getInputStream().readAllBytes(), isWindows ? "GBK" : "UTF-8");
	}

	public static void main(String[] args) {
		System.out.println(Pattern.compile("test\\s?spring",Pattern.MULTILINE).matcher("test\nspring").find());
	}

}
