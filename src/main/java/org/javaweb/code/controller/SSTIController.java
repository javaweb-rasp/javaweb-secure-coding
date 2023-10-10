package org.javaweb.code.controller;

import freemarker.template.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/SSTI/")
public class SSTIController {

	@GetMapping("/velocity.do")
	public Map<String, Object> velocity(String tpl) {
		StringWriter sw = new StringWriter();
		Velocity.evaluate(new VelocityContext(), sw, "tag", tpl);

		return new HashMap<>() {{
			put("data", sw.toString());
		}};
	}

	@GetMapping("/freemarker.do")
	public Map<String, Object> freeMarker(String tpl) throws Exception {
		StringWriter sw = new StringWriter();
		new Template(null, new StringReader(tpl), null).process(null, sw);

		return new HashMap<>() {{
			put("data", sw.toString());
		}};
	}

}