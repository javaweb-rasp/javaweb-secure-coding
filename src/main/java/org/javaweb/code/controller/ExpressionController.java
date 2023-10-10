package org.javaweb.code.controller;

import ognl.OgnlContext;
import ognl.OgnlException;
import org.mvel2.MVEL;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.script.ScriptEngineManager;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/Expression/")
public class ExpressionController {

	@GetMapping(value = "/ognl.do")
	public Map<String, Object> ognl(String exp) throws OgnlException {
		Map<String, Object> data    = new LinkedHashMap<>();
		ognl.OgnlContext    context = new OgnlContext();

		// 执行Ognl表达式
		data.put("data", ognl.Ognl.getValue(exp, context, context.getRoot()));

		return data;
	}

	@GetMapping(value = "/spEL.do")
	public Map<String, Object> spel(String exp) {
		Map<String, Object> data = new LinkedHashMap<>();

		// 执行SpEL表达式
		data.put("data", new SpelExpressionParser().parseExpression(exp).getValue());

		return data;
	}

	@GetMapping("/mvel.do")
	public Map<String, Object> mvel(String exp) {
		Map<String, Object> data = new LinkedHashMap<>();

		// 执行MVEL2表达式
		data.put("data", MVEL.eval(exp));

		return data;
	}

	@GetMapping("/scriptEngine.do")
	public Map<String, Object> scriptEngine(String exp) throws Exception {
		Map<String, Object> data = new LinkedHashMap<>();

		// 执行Javascript
		Object eval = new ScriptEngineManager().getEngineByName("nashorn").eval(exp);
		data.put("data", eval.toString());

		return data;
	}

}
