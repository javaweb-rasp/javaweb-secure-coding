package org.javaweb.code.controller;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.input.SAXBuilder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.NodeList;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
 */
@RestController
@RequestMapping("/XXE/")
public class XXEController {

	@PostMapping("/dom4jSAXReaderXXE.do")
	public Map<String, Object> dom4jSAXReaderXXE(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			// 解析方式一，直接使用SAXReader解析，未禁用外部实体
			org.dom4j.io.SAXReader reader = new org.dom4j.io.SAXReader();
			org.dom4j.Document     doc    = reader.read(in);

			// 解析方式二，使用DocumentHelper解析，间接的调用SAXReader，未禁用外部实体
//			org.dom4j.Document doc = DocumentHelper.parseText(IOUtils.toString(in, StandardCharsets.UTF_8));

			org.dom4j.Element root = doc.getRootElement();

			// 输出title
			data.put("title", root.element("title").getText());
		}

		return data;
	}

	@PostMapping("/dom4jSAXReader.do")
	public Map<String, Object> dom4jSAXReader(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			// 解析方式一，直接使用SAXReader解析，未禁用外部实体
			org.dom4j.io.SAXReader reader = new org.dom4j.io.SAXReader();

			// 禁止DOCTYPE
			reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

			// 禁止外部ENTITY
			reader.setFeature("http://xml.org/sax/features/external-general-entities", false);

			// 禁止外部参数实体
			reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

			org.dom4j.Document doc  = reader.read(in);
			org.dom4j.Element  root = doc.getRootElement();

			// 输出title
			data.put("title", root.element("title").getText());
		}

		return data;
	}

	@PostMapping("/jaxpSAXParserFactoryXXE.do")
	public Map<String, Object> jaxpSAXParserFactoryXXE(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			SAXParserFactory factory = SAXParserFactory.newInstance();
			SAXParser        parser  = factory.newSAXParser();
			StringBuilder    title   = new StringBuilder();
			parser.parse(in, createDefaultHandler(title));

			// 输出title
			data.put("title", title);
		}

		return data;
	}

	@PostMapping("/jaxpSAXParserFactory.do")
	public Map<String, Object> jaxpSAXParserFactory(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			SAXParserFactory factory = SAXParserFactory.newInstance();

			// 禁止DOCTYPE
			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

			// 禁止外部ENTITY
			factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

			// 禁止外部参数实体
			factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

			SAXParser     parser = factory.newSAXParser();
			StringBuilder title  = new StringBuilder();
			parser.parse(in, createDefaultHandler(title));

			// 输出title
			data.put("title", title);
		}

		return data;
	}

	public DefaultHandler createDefaultHandler(StringBuilder title) {
		return new DefaultHandler() {

			private boolean inTitle = false;

			@Override
			public void startElement(String uri, String localName, String qName, Attributes attributes) {
				if (qName.equalsIgnoreCase("title")) {
					inTitle = true;
				}
			}

			@Override
			public void endElement(String uri, String localName, String qName) {
				if (qName.equalsIgnoreCase("title")) {
					inTitle = false;
				}
			}

			@Override
			public void characters(char[] ch, int start, int length) {
				if (inTitle) {
					title.append(new String(ch, start, length));
				}
			}
		};
	}

	@PostMapping("/saxBuilderXXE.do")
	public Map<String, Object> saxBuilderXXE(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			SAXBuilder         builder = new org.jdom2.input.SAXBuilder();
			org.jdom2.Document doc     = builder.build(in);

			// 输出title
			org.jdom2.Element root = doc.getRootElement();

			// 输出title
			data.put("title", root.getChild("title").getText());
		}

		return data;
	}

	@PostMapping("/saxBuilder.do")
	public Map<String, Object> saxBuilder(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			SAXBuilder builder = new SAXBuilder();

			// 禁止DOCTYPE
			builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

			// 禁止外部ENTITY
			builder.setFeature("http://xml.org/sax/features/external-general-entities", false);

			// 禁止外部参数实体
			builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

			Document doc = builder.build(in);

			// 输出title
			Element root = doc.getRootElement();

			// 输出title
			data.put("title", root.getChild("title").getText());
		}

		return data;
	}

	@PostMapping("/xmlReaderXXE.do")
	public Map<String, Object> xmlReaderXXE(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			XMLReader     xmlReader = XMLReaderFactory.createXMLReader();
			StringBuilder title     = new StringBuilder();
			xmlReader.setDTDHandler(createDefaultHandler(title));
			xmlReader.parse(new InputSource(in));

			// 输出title
			data.put("title", title);
		}

		return data;
	}

	@PostMapping("/xmlReader.do")
	public Map<String, Object> xmlReader(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			XMLReader xmlReader = XMLReaderFactory.createXMLReader();

			// 禁止DOCTYPE
			xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

			// 禁止外部ENTITY
			xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);

			// 禁止外部参数实体
			xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

			StringBuilder title = new StringBuilder();
			xmlReader.setDTDHandler(createDefaultHandler(title));
			xmlReader.parse(new InputSource(in));

			// 输出title
			data.put("title", title);
		}

		return data;
	}

	@PostMapping("/documentBuilderFactoryXXE.do")
	public Map<String, Object> documentBuilderFactoryXXE(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

			// 创建DocumentBuilder
			DocumentBuilder builder = factory.newDocumentBuilder();

			// 从输入流中解析XML
			org.w3c.dom.Document document = builder.parse(in);

			// 获取根元素
			org.w3c.dom.Element rootElement = document.getDocumentElement();

			// 获取<title>元素
			NodeList titleElements = rootElement.getElementsByTagName("title");

			// 输出title
			data.put("title", titleElements.item(0).getTextContent());
		}

		return data;
	}

	@PostMapping("/documentBuilderFactory.do")
	public Map<String, Object> documentBuilderFactory(InputStream in) throws Exception {
		Map<String, Object> data = new HashMap<>();

		if (in != null) {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

			// 禁止DOCTYPE
			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

			// 禁止外部ENTITY
			factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

			// 禁止外部参数实体
			factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

			// 创建DocumentBuilder
			DocumentBuilder builder = factory.newDocumentBuilder();

			// 从输入流中解析XML
			org.w3c.dom.Document document = builder.parse(in);

			// 获取根元素
			org.w3c.dom.Element rootElement = document.getDocumentElement();

			// 获取<title>元素
			NodeList titleElements = rootElement.getElementsByTagName("title");

			// 输出title
			data.put("title", titleElements.item(0).getTextContent());
		}

		return data;
	}

}
