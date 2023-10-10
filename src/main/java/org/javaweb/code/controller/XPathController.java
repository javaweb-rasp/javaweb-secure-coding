package org.javaweb.code.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.*;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/XPath/")
public class XPathController {

	private static final String USERS_XML = "<users>" +
			"    <user>" +
			"        <username>admin</username>" +
			"        <password>admin123</password>" +
			"    </user>" +
			"    <user>" +
			"        <username>user1</username>" +
			"        <password>pass123</password>" +
			"    </user>" +
			"</users>";

	@GetMapping("/xpathInjection.do")
	public Map<String, Object> xpathInjection(String username, String password) {
		Map<String, Object>    data    = new HashMap<>();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

		try {
			DocumentBuilder builder      = factory.newDocumentBuilder();
			InputSource     inputSource  = new InputSource(new StringReader(USERS_XML));
			Document        document     = builder.parse(inputSource);
			XPathFactory    xPathFactory = XPathFactory.newInstance();
			XPath           xpath        = xPathFactory.newXPath();
			String          query        = "/users/user[username='" + username + "' and password='" + password + "']";
			XPathExpression expression   = xpath.compile(query);

			// 执行XPath查询
			NodeList result = (NodeList) expression.evaluate(document, XPathConstants.NODESET);
			data.put("result", result.getLength() > 0 ? "Authentication successful." : "Authentication failed.");
		} catch (Exception e) {
			data.put("result", "Error");
		}

		return data;
	}

	@GetMapping("/xpathQuery.do")
	public Map<String, Object> xpathQuery(String username, String password) {
		Map<String, Object> data = new HashMap<>();

		try {
			DocumentBuilderFactory factory      = DocumentBuilderFactory.newInstance();
			DocumentBuilder        builder      = factory.newDocumentBuilder();
			Document               document     = builder.parse(new InputSource(new StringReader(USERS_XML)));
			XPathFactory           xPathFactory = XPathFactory.newInstance();
			XPath                  xpath        = xPathFactory.newXPath();

			// 使用参数化的XPath查询
			String xPathExpression = "/users/user[username=$username and password=$password]";

			xpath.setXPathVariableResolver(new XPathVariableResolver() {
				@Override
				public Object resolveVariable(QName variableName) {
					if ("username".equals(variableName.getLocalPart())) {
						return username;
					} else if ("password".equals(variableName.getLocalPart())) {
						return password;
					}
					return null;
				}
			});

			XPathExpression expression = xpath.compile(xPathExpression);

			// 执行XPath查询
			NodeList result = (NodeList) expression.evaluate(document, XPathConstants.NODESET);
			data.put("result", result.getLength() > 0 ? "Authentication successful." : "Authentication failed.");
		} catch (Exception e) {
			data.put("result", "Error");
		}

		return data;
	}

}
