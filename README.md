# Java安全开发规范

随着数字化时代的到来，我们的生活日益依赖Web服务和Web应用，它们为我们提供了便捷的办公、交易和生活方式。然而，Web服务在为人们提供着更加便捷的生活方式的同时也面临着网络安全风险的巨大威胁，Web应用成为了黑客攻击的首要目标。

根据中国国家互联网应急中心（CNCERT/CC）和国际权威安全监测机构Gartner的数据，75%以上的攻击针对Web应用，而约2/3的Web站点存在着相当严重的安全漏洞。这些数据清晰地展示了网络安全问题的紧迫性和严重性。

为了保护数据免受窃取、网站免受篡改等安全威胁，程序开发者在开发便捷、强大的Web应用的同时，还要确保程序自身的安全性。其中尤为重要的是开发者需密切关注Web安全、遵循安全编码规范。

Github：[javaweb-secure-coding](https://github.com/javaweb-rasp/javaweb-secure-coding)

PostMan：[JavaWeb-Secure-Coding.postman_collection.json](https://github.com/javaweb-rasp/javaweb-secure-coding/blob/master/JavaWeb-Secure-Coding.postman_collection.json)



## 1. 防御性编程

防御性编程（Defensive Programming）是一种软件开发方法，旨在最大程度地减少软件缺陷、漏洞和安全风险的产生。防御性编程的核心思想是通过编码和设计技巧来防止和减轻错误和异常，编写代码时要进行输入验证、数据验证和错误处理，以减少漏洞的可能性。

防御性编程要求开发者应当始终假定攻击者会尝试利用漏洞来攻击应用程序，也不能因为网络隔离、登录验证登限制而忽视安全，因为攻击者通常会使用非常规手段入侵到内部系统。



### 1.1 输入验证

一切来源于外部请求的参数都可能是恶意的，服务端应当谨慎处理所有来自于请求中的数据，包括但不限于：

1. HTTP的请求消息体（表单请求、JSON、XML等）；
2. HTTP的请求参数（GET/POST/DELETE/UPDATE等）；
3. HTTP请求的URL（URL传参，如：RESTful、Matrix请求）；
4. HTTP请求中的Header信息（Cookie、X-Forwarded-For、Referer等）；
5. 文件上传请求中的文件名、文件内容、表单域；
6. RPC/RESTful请求中的JSON/XML、反序列化对象等；
7. 客户端传入的加密消息（如：Android、JavaScript加密算法可逆或可构造参数）；
8. 不可信的外部资源文件（如：HTML加载了不安全的外部JS或图片）；



### 1.2 最小权限原则

最小权限原则（Principle of Least Privilege，简称PoLP）是计算机安全和信息安全领域的一项核心原则。该原则强调只为执行任务所需的最低权限赋予用户、程序或系统组件。这有助于减少潜在的风险和攻击面，提高系统的安全性。以下是最小权限原则的关键概念和原则：

1. **最小权限原则核心观点：** 用户、程序或系统组件应该仅在执行其任务所需的最低权限下运行。这意味着不应授予超出必需权限的额外权限。
2. **权限分类：** 最小权限原则涉及到对不同类型的权限进行分类。通常包括读取权限、写入权限、执行权限和管理权限等。
3. **降低攻击面：** 通过限制权限，可以减少潜在攻击者利用的机会。攻击者可能会试图滥用赋予的权限来入侵系统或获取敏感信息。
4. **最小化数据访问：** 在数据库和应用程序中，最小权限原则还包括限制对数据的访问。用户只应能够访问其需要的数据，而不是整个数据库。
5. **安全角色和分隔：** 为不同的任务和角色创建安全角色，并授予这些角色所需的最低权限。这有助于将权限管理简化为角色管理。
6. **特权分离：** 将系统的特权分离，确保只有经过授权的管理员才能执行敏感操作，如系统配置、用户管理等。
7. **授权控制：** 使用访问控制机制（如访问控制列表（ACL）或基于角色的访问控制（RBAC））来管理和强制权限。
8. **日志和监控：** 监控和记录权限的使用，以便检测异常行为和未经授权的访问尝试。
9. **敏感数据保护：** 特别关注对敏感数据的权限控制。确保只有经过授权的用户能够访问和处理敏感数据。
10. **持续评估：** 定期评估和审查权限，以确保其仍然符合实际需求，并根据需要进行调整。

最小权限原则是一项关键的安全实践，有助于减轻内部和外部威胁，并提高系统的安全性。它应该在设计和实施系统、应用程序和网络时得到广泛应用，以确保敏感信息和资源受到适当的保护。同时，最小权限原则也有助于降低人为错误和不当操作的风险，提高系统的可靠性和可维护性。



### 1.3 单元测试规范

单元测试规范是确保代码质量和可维护性的关键组成部分，因此强烈建议启用单元测试，以下是部分单元测试的开发规范：

1. 测试用例（Test Case）和测试类（Test Class）应当使用明确的、描述性的名称，以便于理解测试的目的。可以使用约定俗成的命名方式，如在被测试的类名后加上"Test"；
2. 单一职责原则，每个测试用例应该专注于测试一个特定的行为、方法或函数。不要在一个测试用例中尝试覆盖太多功能；
3. 代码覆盖率测试，确保测试覆盖代码的不同路径和分支，以尽可能提高代码覆盖率；
4. 安全测试，某些可能存在安全风险的业务需编写安全测试用例，以确保代码没有潜在的安全漏洞；
5. 使用断言（Assertions）来检查预期结果和实际结果是否匹配，断言应该是清晰和有意义的，以便在测试失败时快速定位问题；
6. 性能测试，对于一些有性能要求的业务应当编写性能测试用例，以确保代码在高负载情况下仍然具有良好的性能；



### 1.4 异常处理规范

1. 使用自定义的错误页面，在Web应用程序中，使用自定义错误页面来代替默认的错误消息，从而减少信息泄露风险，同时提供更友好的用户体验；
2. 使用全局异常处理方案，禁止直接将服务端的异常直接输出到客户端；
3. 使用合适的日志工具记录异常信息，如：Log4j、Logback等，需要特别注意不要使用存在漏洞的Log4j版本（<=2.14.1）；
4. 使用准确的异常类型，以便能够更精确地识别问题和处理异常；
5. 准确描述自定义类异常信息，在抛出和捕获异常时，必须提供有意义的异常消息，以便在日志中记录或在错误页面上显示；
6. 合理记录异常信息，以便在出现问题时能够进行故障排除；
7. 明确的异常声明，在方法签名和JavaDoc中清晰地说明可能抛出的异常，以便他人能够正确地处理；
8. 禁止滥用异常机制，避免在正常业务控制流中使用异常来进行流程控制。异常应该用于处理异常情况，而不是预期的业务逻辑；
9. 合理的忽略异常，不要随意的忽略异常（例如，使用空的catch块），这会导致问题被忽略或难以调试；
10. 合理的异常日志归类，按照业务或异常类型单独记录异常信息；
11. 在处理用户输入时，进行恶意输入检查，以防止攻击，如：跨站脚本或SQL注入；



### 1.5 日志存储规范

按照信息安全等级保护（等保）的要求，日志存储应遵循一系列规范和最佳实践，以确保敏感信息的保密性、完整性和可用性。以下是针对日志存储的等保部分要求：

1. **保密性（C）：**
   - 加密：对存储的日志数据进行加密，以防止未经授权的访问。
   - 访问控制：实施适当的访问控制措施，只有授权用户能够访问和查看日志文件。
   - 脱敏：对于包含敏感信息的日志，进行脱敏处理，以隐藏真实的敏感信息。
   - 安全传输：确保在日志数据从源传输到存储位置的过程中也是加密的，以避免窃听。
2. **完整性（I）：**
   - 整体性保护：使用哈希值或数字签名等技术来验证日志文件的完整性，确保文件在存储过程中未被篡改。
   - 访问审计：记录和监控对日志存储的访问，包括读取、写入和修改操作。
3. **可用性（A）：**
   - 容灾备份：实施容灾备份策略，确保即使在系统故障或灾难发生时，日志数据仍然可用。
   - 定期备份：定期备份日志数据，以防止数据丢失，并确保数据可以恢复。
   - 存储容量管理：确保足够的存储容量，以满足日志数据的增长需求，防止因存储不足而丢失日志。
4. **可追溯性（T）：**
   - 记录详细信息：在日志中记录详细的事件信息，包括时间戳、事件类型、事件源等，以便进行调查和审计。
   - 安全审计：建立安全审计日志，记录关键事件和安全违规行为。
   - 有效期：采取监测、记录网络运行状态、网络安全事件的技术措施，并按照规定留存相关的网络日志不少于六个月；



## 2. C/S交互规范

### 2.1 服务端请求处理规范

1. 优先启动HTTPS访问，防止`中间人劫持攻击`；
2. 明确请求方式，原则上禁用`@RequestMapping`，改为具体的请求方式，如：`@GetMapping、@PostMapping`，防止`参数污染和请求方式不当风险`；
3. 合理的权限访问控制，API接口访问应做好严格的权限校验，防止`越权攻击`；
4. 重要业务需访问频率、次数限制，防止`数据泄露和密码爆破`；
5. 核心业务需限制访问IP；
6. 重要数据访问必须加密，如：账号、密码、手机号，防止`数据泄露`；
7. API请求参数应当添加CRC校验，保护数据完整性、防止`中间人劫持和请求重放攻击`；
8. 减少使用弱加密算法：`DES、RC4、MD5、SHA-1`，如：`MD5`加密时必须加上随机的`SALT`；推荐：`RSA、AES、SM（国密）`，请勿将：`Hex、URL、Base64`等编码方式当做加密算法；
9. 良好的数据格式校验，使用内置的验证框架（如：`Hibernate Validator`）来验证输入数据；
10. 正确使用`正则表达式`，防止`检测绕过回溯攻击`；
11. 生产环境应做好敏感信息保护减少暴露面，如：禁用`Swagger-UI、ElasticSearch、Weblogic/WebSphere/Tomcat/TongWeb控制台`等对外访问；
12. 启用自定义的`404、500`页面，禁止直接输出堆栈信息，防止`敏感信息泄露`；
13. 慎用或不用高风险组件解析请求参数，如：`Fastjson、XMLDecoder、XStream`；
14. 解析XML参数时务必禁用外部实体解析，防止XXE攻击；
15. 请求参数禁止当做`SpEL、Ognl、MVEL2、EL、JavaScript、Groovy、SQL`表达式或脚本执行；
16. 原则上禁止对请求参数进行Java对象反序列化，防止`Shiro、Apereo-CAS`之类的`Java反序列化漏洞`；
17. 文件上传请求中应严格检测文件名、文件内容是否合法，防止`文件上传漏洞`；
18. 文件上传的文件建议按照时间或者UUID的生成规则重命名，禁止原样存储，防止`文件上传漏洞`；
19. Session有效期不宜过长，尽量保持在30分钟以内，防止`会话固定攻击`；
20. 图形验证码每次校验完成后不管是否正确都必须清除与之对应的缓存，防止`验证码绕过漏洞`；
21. 慎用Spring MVC的请求参数对象绑定，防止参数污染；



### 2.2 HTTP响应头

响应中必须包含的响应头：

```yaml
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

**建议添加的响应头：**

1. **Content-Security-Policy (CSP)**：指定哪些内容可以加载到页面中，以防止跨站点脚本攻击（XSS）和其他恶意内容的注入。CSP 可以根据应用程序的需求进行定制。
2. **Strict-Transport-Security (HSTS)**：启用 HTTP 严格传输安全，强制使用 HTTPS 连接，并防止中间人攻击。
3. **X-Content-Security-Policy**：与 CSP 类似，但在较旧的浏览器中使用。不过，现代浏览器更倾向于使用 CSP。
4. **Referrer-Policy**：控制浏览器如何在请求头中包含 Referer（来源）信息。可以设置为 `strict-origin-when-cross-origin`或`no-referrer-when-downgrade`，以减少跨站点信息泄露。
5. **Server**：隐藏服务器信息，以减少攻击者获取有关服务器的信息的机会。
6. **Content-Type**：确保正确设置响应的 `Content-Type` 头，以避免浏览器执行不安全的默认操作，例如将 text文件当作可执行 html执行。
7. **Access-Control-Allow-Origin**：这是最常见的跨域响应头，用于指定允许访问资源的域名。可以设置为具体的域名或使用通配符 `*` 表示允许任何域名访问。



### 2.3 HTTP响应规范

1. 禁止未经过滤直接输出任何请求头，防止XSS攻击；
2. 禁止未经过滤直接输出任何请求参数，防止XSS攻击；
3. 响应头中包含`Location`时应当检查重定向的地址是否由用户输入，防止XSS攻击；
4. 响应头的值中应禁止换行符，防止CRLF攻击；
5. 明确MIME 类型，响应主体应指定正确的 MIME 类型（媒体类型），以告知客户端如何解释和处理响应内容。例如，HTML 内容应使用 `text/html`，JSON 数据应使用 `application/json`，图像应使用适当的图像 MIME 类型，防止XSS攻击；
6. 敏感信息应做好脱敏处理；



## 2.4 Session/Cookie规范

### 2.4.1 Session安全

1. Session必须设置有效期，建议保持30分钟以内，原则上最长不得超过1小时；
2. Session数据应该做到安全存储，如：内存、数据库或加密的持久性存储中，禁止将会话Session存储在客户端，以减少被窃取的风险；



### 2.4.2 Cookie安全

1. Cookie存储重要凭证相关的Cookie，建议开启`HttpOnly`和`Secure`机制；

```java
Cookie myCookie = new Cookie("key", "value");

// 设置 HttpOnly 标志
myCookie.setHttpOnly(true);

// 设置 Secure 标志（仅在HTTPS连接中传输）
myCookie.setSecure(true);
```

2. 请勿滥用Cookie，存储于Cookie中的数据在客户端都有可能被恶意篡改，因此误将Cookie当Session使用，例如：
   - 某业务将找回密码步骤中是否通过邮件验证的标识存储于Cookie当中，服务端没有做二次校验，从而导致了攻击者只需修改Cookie中的标识即可绕过邮件认证；
   - 将用户密码、图形验证码存储在Cookie中导致敏感信息泄露和验证码校验绕过漏洞；
3. 合理设置Cookie的`Domain`、`Path`，防止Cookie信息泄露；
4. 做好客户端和服务端的XSS防御；
   - 服务端任何来源于请求参数的值输出到客户端并明确将用于HTML渲染时都应当使对输出内容进行HTML实体化；
   - 客户端应减少拼接HTML片段，或对拼接部分转义、过滤；
5. 如将Cookie用于广告、商品营销或其他涉及到Cookie追踪的场景时应遵循隐私政策，声明Cookie业务范围并需用户授权；



## 3. 编码/加密规范

### 3.1 加密算法强度

1. 少用或不用弱加密算法：`DES、RC4、MD5、SHA-1`；
2. `Hex、URLEncoder、Base64`是编码，不是加密算法，请勿滥用！
3. 选择强加密算法，如：RSA、AES、SM（国密）；
4. 密钥长度需符合安全规范，例如，使用RSA 2048而不是RSA1024；



### 3.2 密钥存储规范

1. 禁止硬编码，避免将密钥硬编码到应用程序代码中，因为容易攻击者发现；
2. 严格控制密钥访问权限，避免直接存储于缓存服务中，可使用访问控制列表（ACLs）或身份验证和授权来限制访问；
3. 强密码保护，如果密钥需要密码，确保使用足够强的密码，并定期更改密码；
4. 定期轮换密钥，以减少密钥泄露或滥用的风险；
5. 定期备份存储的密钥，以防止丢失或损坏，备份应存储在安全的位置；
6. 禁止将密钥直接存储于Git或其他版本管理工具中，尤其是Github、Gitee等开源平台；
7. 使用密钥管理服务， 如果可能的话，使用专门的密钥管理服务（Key Management Service，KMS）来生成、存储和管理密钥。云服务提供商通常提供了这样的服务，例如AWS Key Management Service（KMS）或Google Cloud Key Management Service；



## 4. SQL查询规范

SQL注入（`SQL injection`）是因为`应用程序`在执行SQL语句的时候没有正确的处理用户输入字符串，将用户输入的恶意字符串拼接到了SQL语句中执行，从而导致了SQL注入。



### 4.1 Spring JdbcTemplate

#### 4.1.1 字符型

原则上禁止在SQL语句中直接拼接外部传入的字符串，因为攻击者可以通过SQL攻击闭合原始的SQL语义从而产生新的SQL查询，可导致数据库信息泄露、服务器被非法入侵等高危风险！

**反例 - Spring  JdbcTemplate SQL注入**

```java
public Map<String, Object> getSysUserByUsername(String username) {
    String sql = "select * from sys_user where username = '" + username + "'";

    return jdbcTemplate.queryForMap(sql);
}
```

**示例 - Spring   JdbcTemplate 预编译查询**

```java
public Map<String, Object> findByUsername(String username) {
    String sql = "select * from sys_user where username = ? ";

    return jdbcTemplate.queryForMap(sql, username);
}
```

**示例 - SQL注入攻击**

```sql
http://localhost:8080/SQL/Spring/jdbcTemplateStringInjection.do?username=admin' and 1=2 union select 1,2,sqlite_version(),4,5,6,'7
```

SQL注入攻击执行结果：

```json
{
    "id": 1,
    "username": 2,
    "password": "3.34.0",
    "email": 4,
    "user_avatar": 5,
    "register_time": 6,
    "notes": "7"
}
```

攻击者使用前后的单引号闭合了原始SQL语句，并通过添加 `and 1=2` 让原SQL语句查询空数据。然后在UNION子查询中，攻击者使用了 `sqlite_version()` 函数来探测SQLite数据库引擎的版本号（其中`3.34.0`就是服务器端使用的Sqlite的版本号）。这个过程是一种信息搜集攻击，目的是帮助攻击者更好地了解目标系统的配置和弱点。

此外，攻击者也可能构建其他类型的SQL语句，以获取服务器中的敏感信息。例如，使用数据库提供的文件读写函数（如：Mysql的`load_file、into outfile`）或执行系统命令的函数（如：SQLServer的`xp_cmdshell`，MySQL的UDF）来直接获取数据库服务器的权限。



#### 4.1.2 模糊查询

**反例 - Spring  JdbcTemplate 模糊查询SQL注入**

```java
@GetMapping("/Spring/jdbcTemplateLikeInjection.do")
public List<Map<String, Object>> jdbcTemplateLikeInjection(String username) {
    String sql = "select * from sys_user where username like '%" + username + "%'";

    return jdbcTemplate.queryForList(sql);
}
```



**示例 - Spring   JdbcTemplate 预编译模糊查询**

```java
@GetMapping("/Spring/jdbcTemplateLikeQuery.do")
public List<Map<String, Object>> jdbcTemplateLikeQuery(String username) {
    String sql = "select * from sys_user where username like ? ";

    return jdbcTemplate.queryForList(sql, "%" + username + "%");
}
```



#### 4.1.3 order by/group by查询

order by 和 group by有着相近的语法，因此这里仅以order by 为例，JDBC中无法对`表、函数、列名`预编译，因此在开发对应的业务功能时候需要特别注意防止SQL注入。

**反例 - Spring  JdbcTemplate order by查询SQL注入**

```java
@GetMapping("/Spring/jdbcTemplateOrderByInjection.do")
public List<Map<String, Object>> jdbcTemplateOrderByInjection(String order, String orderType) {
    String sql = "select * from sys_user order by " + order + " " + orderType;

    return jdbcTemplate.queryForList(sql);
}
```

动态的order by查询可使用列名和排序方式白名单的方式拼接，例如下列示例程序限制了列名必须是特定的某些值：

**示例 - Spring  JdbcTemplate order by查询**

```java
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
```

如果排序条件较少的情况可以直接用程序写`if/else`或者`switch/case`的方式拼接：

```java
@GetMapping("/Spring/jdbcTemplateOrderByAppendQuery.do")
public List<Map<String, Object>> jdbcTemplateOrderByAppendQuery(String order, String orderType) {
    StringBuilder sql = new StringBuilder("select * from sys_user");

    if (StringUtils.isNoneBlank(order)) {
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
```



#### 4.1.4 where...in查询

禁止在`where...in`查询中直接拼接SQL语句，可使用NamedParameterJdbcTemplate参数绑定的方式查询。

**反例 - Spring  JdbcTemplate where...in查询SQL注入**

```java
@GetMapping("/Spring/jdbcTemplateWhereInInjection.do")
public List<Map<String, Object>> jdbcTemplateWhereInInjection(String ids) {
    String sql = "select * from sys_user where id in ( " + ids + " ) ";

    return jdbcTemplate.queryForList(sql);
}
```

**示例 - Spring   NamedParameterJdbcTemplate where...in预编译查询**

```java
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
```



### 4.2 MyBatis

修复方案：在Mybatis中禁止使用`${}`（字符拼接），改为`#{}`（预编译）即可，基于注解和基于XML配置同理，基本原则就是不能用`${}`。

#### 4.2.1 字符型

**反例 - MyBatis 基于配置字符型SQL注入**

```xml
<select id="findByUsername" parameterType="string" resultMap="sysUserResultMap">
    SELECT * FROM sys_user WHERE username = '${username}'
</select>
```

**示例 - MyBatis 基于配置字符型SQL查询**

```xml
<select id="mybatisStringInjection" parameterType="string" resultMap="sysUserResultMap">
    SELECT * FROM sys_user WHERE username = #{username}
</select>
```



#### 4.2.2 模糊查询

**反例 - MyBatis 基于注解模糊查询SQL注入**

```java
@Select("select * from sys_user where username like '%${username}%'")
List<SysUser> mybatisLikeInjection(@Param("username") String username);
```

需要注意的是like预编译查询需要用到数据库字符串拼接，例如：mysql的拼接是使用`concat(XX, XX)`而示例中使用的是sqlite的字符拼接（sqlite是`||`拼接），所以这里请根据实际使用的数据库修改查询语句：

**示例 - MyBatis 基于注解模糊查询**

```java
@Select("select * from sys_user where username like '%' || #{username} || '%'") // Sqlite
// Select("select * from sys_user where username like concat('%', #{username}, '%')") // Mysql
List<SysUser> mybatisLikeQuery(@Param("username") String username);
```



#### 4.2.3 order by/group by查询

**反例 - MyBatis order by SQL注入**

```java
@Select({"<script>" +
        "select * from sys_user " +
        "  <if test='order != null'>order by ${order} ${orderType}</if>" +
        "</script>"
})
List<SysUser> mybatisOrderByInjection(@Param("order") String order, @Param("orderType") String orderType);
```

**示例 - MyBatis order by预编译查询**

```java
@Select("<script>" +
        "select * from sys_user " +
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
```

如果查询条件不多的情况下可以使用上述的`choose/when`方式，反之建议参考本文中的Spring JdbcTemplate的`order by` 查询方式。



#### 4.2.4 where...in查询

禁止在`where...in`查询中使用`${}`拼接SQL语句。

**反例 - Mybatis where...in查询SQL注入**

```java
@GetMapping("/Mybatis/mybatisWhereInInjection.do")
public List<SysUser> mybatisWhereInInjection(String ids) {
    return sysUserMapper.mybatisWhereInInjection(ids);
}
```



Mybatis的SQL语句支持通过循环的方式预编译，可使用如下方式实现`where...in`查询：

**示例 - Mybatis where...in预编译查询**

```java
@Select({"<script>",
       "SELECT * FROM sys_user WHERE id IN ",
       "<foreach item='id' collection='ids' open='(' separator=', ' close=')'>",
       "  #{id}",
       "</foreach>",
       "</script>"})
List<SysUser> mybatisWhereInQuery(@Param("ids") List<String> ids);
```



### 4.3 JDBC

JDBC提供了PreparedStatement和Statement，其中PreparedStatement提供了预编译查询能力，因此需要使用PreparedStatement查询。需要特别注意的是PreparedStatement中的查询语句原则上应当禁止出现任何字符串相关的拼接，否则可能会导致SQL注入攻击。

**反例 - JDBC SQL注入**

```java
String sql = "select * from sys_user where id = " + id;

// 创建预编译对象
PreparedStatement pstt = connection.prepareStatement(sql);

// 执行SQL并返回结果集
ResultSet rs = pstt.executeQuery();
```

**示例 - JDBC SQL正确的预编译查询**

```java
String sql = "select * from sys_user where id = ? ";

// 创建预编译对象
PreparedStatement pstt = connection.prepareStatement(sql);
pstt.setObject(1, id);

// 执行SQL并返回结果集
ResultSet rs = pstt.executeQuery();
```



### 4.4 JPA/Hibernate

注：JPA和Hibernate实现差异较小，本文以JPA为例，Hibernate不做单独讲述。

`JpaRepository`是通过命名约定和自动生成查询方法来简化JPA数据访问的操作，因此使用JPA不仅代码量少，而且不会存在SQL注入（用户自定义Repository除外）。

#### 4.4.1 JpaRepository

以下是`JpaRepository`使用示例：

```java
@Repository
public interface SysUserRepository extends JpaRepository<SysUser, String>,
		PagingAndSortingRepository<SysUser, String>, JpaSpecificationExecutor<SysUser>, SysUserCustomRepository {

	SysUser findByUsername(String username);

	List<SysUser> findByUsernameIn(List<String> username);

	List<SysUser> findByUsernameLike(String username);

	List<SysUser> findByUsernameLikeOrderByIdDesc(String username);

	@Query(value = "select * from sys_user where username = ?1 ", nativeQuery = true)
	SysUser usernameQueryTest(String username);

	@Query(value = "select * from sys_user where email = :email ", nativeQuery = true)
	SysUser emailQueryTest(String email);

	@Query("from SysUser where id = :id")
	SysUser idQueryTest(Long id);

}
```



#### 4.4.2 自定义JpaRepository

在使用JPA提供的自定义Repository的时为了保证数据安全，原则上禁止拼接SQL语句，如有必须拼接的场景需严格校验数据的安全性。

**SysUserCustomRepository.java**

```java
package org.javaweb.code.repository;

public interface SysUserCustomRepository {

	Object jpqlQuery(String username);

	Object jpqlInjection(String username);

	Object nativeQuery(String username);

	Object nativeInjection(String username);

	Object namedQuery(String username);

	Object criteriaQuery(String username, String email);

}
```

**SysUserCustomRepositoryImpl.java**

```java
package org.javaweb.code.repository.impl;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.commons.lang3.StringUtils;
import org.javaweb.code.entity.SysUser;
import org.javaweb.code.repository.SysUserCustomRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class SysUserCustomRepositoryImpl implements SysUserCustomRepository {

	@PersistenceContext
	private EntityManager entityManager;

	@Override
	public Object jpqlQuery(String username) {
		// JPQL预编译查询
		String sql   = "from SysUser where username = :username";
		Query  query = entityManager.createQuery(sql, SysUser.class);
		query.setParameter("username", username);

		return query.getSingleResult();
	}

	@Override
	public Object jpqlInjection(String username) {
		// JPQL注入写法
		String sql = "from SysUser where username = '" + username + "'";
		return entityManager.createQuery(sql, SysUser.class).getSingleResult();
	}

	@Override
	public Object nativeQuery(String username) {
		// 原生SQL预编译查询
		String sql = "select * from sys_user where username = ?1 ";

		return entityManager.createNativeQuery(sql, SysUser.class).setParameter(1, username).getSingleResult();
	}

	@Override
	public Object nativeInjection(String username) {
		// SQL注入写法
		String sql = "select * from sys_user where username = '" + username + "'";

		return entityManager.createNativeQuery(sql, SysUser.class).getSingleResult();
	}

	@Override
	public Object namedQuery(String username) {
		String sql = "SysUser.findByUsername";
		return entityManager.createNamedQuery(sql, SysUser.class).setParameter(1, username).getSingleResult();
	}

	@Override
	public Object criteriaQuery(String username, String email) {
		CriteriaBuilder        criteriaBuilder = entityManager.getCriteriaBuilder();
		CriteriaQuery<SysUser> criteriaQuery   = criteriaBuilder.createQuery(SysUser.class);
		Root<SysUser>          root            = criteriaQuery.from(SysUser.class);

		// 创建一个 Predicate 列表来存储查询条件
		List<Predicate> predicates = new ArrayList<>();

		if (StringUtils.isNoneEmpty(username)) {
			predicates.add(criteriaBuilder.equal(root.get("username"), username));
		}

		if (StringUtils.isNoneEmpty(email)) {
			predicates.add(criteriaBuilder.equal(root.get("email"), email));
		}

		// 将所有的条件合并为一个总的查询条件（AND 连接）
		criteriaQuery.where(criteriaBuilder.and(predicates.toArray(new Predicate[0])));

		// 执行查询
		return entityManager.createQuery(criteriaQuery).getResultList();
	}

}
```



## 5. URL/Socket请求规范

在编写服务端HTTP请求时应禁止在服务端直接访问外部传入的URL、Socket地址，所有的URL地址都必须配置访问规则（原则上是设置URL白名单），从而有效的防止SSRF攻击。

SSRF（Server-Side Request Forgery，服务端请求伪造）是一种Web安全漏洞，它允许攻击者在受害服务器上执行未经授权的网络请求。这种漏洞可能会导致严重的安全问题，包括数据泄露、攻击内部系统、滥用应用程序的功能等。

**反例 - 服务端直接访问外部传入的URL地址**

```java
@GetMapping("/urlConnection.do")
public ResponseEntity<byte[]> urlConnection(String url) throws Exception {
    // 禁止url地址未经任何检测直接请求
    URLConnection connection = new URL(url).openConnection();

    return new ResponseEntity<>(IOUtils.toByteArray(connection.getInputStream()), OK);
}
```

**示例 - 服务器访问URL前域名白名单检测**

```java
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
```

上述程序使用了`java.net.URLConnection`类，该规范同样适用于其他Http请求框架，包括但不限于：`HttpClient、HttpComponents、OkHttp、Jsoup`。



## 6. 文件读写开发规范

Java文件读写应当遵循最为严格的编码规范，如若程序编码不当可直接导致服务器被非法入侵和数据泄露等，以下是文件读写编码的强制性要求：

### 6.1 文件路径和文件名规范

1. 文件名中禁止出现空字节（`Unicode字符：\u0000`）、禁止`;`（英文分号）；
   - `if (fileName.contains('\u0000') != -1 || fileName.contains(";")){...}`，防止`文件名空字节截断`和`文件路径截断`漏洞；
   - Windows系统应当禁止文件名以`.`（英文点）和` `(英文空格)，因为会被自动系统忽略，例如：在Windows下写入的文件名为`1.jsp.`、`1.jsp/.`，最终写入到磁盘的文件是`1.jsp`；
2. 请求参数中禁止传递绝对路径，如：`dir=/data/&file=app.conf`或`dir=/data/app.conf`，防止`目录穿越/任意文件读写类漏洞`；
3. 相对路径的中禁止出现`WEB-INF`，如：`WEB-INF/web.xml`，防止`源码/配置文件泄露`；
4. 相对路径中禁止出现超过两次`../`或`..\`，如：`../../webapps/ROOT/index.jsp`，防止`目录穿越漏洞`；
5. 文件上传请求中的文件名必须须重命名，可保留原始的文件后缀，但后缀名必须符合文件名写入规则，防止`目录穿越漏洞`；
6. 文件路径检测时必须先对文件路径进行URL标准化后才能进行进一步判断，
   - 例如程序本身希望限制读取`images/`目录下的图片文件，程序代码判断逻辑：`fileName.StartWith("images/")`，攻击者实际上可以传入：`images/../config/db.config`；
   - 文件路径的URL标准化禁止使用：`java.net.URI#normalize()`、`java.nio.file.Path#normalize`，因为无法处理URL地址，例如：`./data/../../resource`，标准化后得到的URL`../resource`；
   - 文件路径比较推荐使用：`java.io.File#getCanonicalFile/getCanonicalPath()`，该方法会使用当前的文件系统创建一个标准化的`绝对路径`，如：`if(file.getCanonicalFile().equals(file2.getCanonicalFile())){...}`；
7. 文件目录拼接请使用：`java.io.File#separatorChar`，如：`"data" + java.io.File.separatorChar + "images"`，或者：`new File("data", "images")`；
8. `Windows的盘符`（如：`C:`）和`Linux/macOS`的区别；
9. 跨平台部署应注意文件名规范：`Windows NTFS`、`FAT文件系统`不区分文件名大小写，`Linux文件系统`严格区分文件名大小写、`macOS文件系统`分区时可选择是否区分大小写；
10. Windows系统用NTFS存储时文件名不允许包含：`:`（英文冒号），防止文件名因为NTFS交换数据流（`Alternate Data Streams`，简称ADS）而导致文件类型检测绕过。例如，在Windows+NTFS中：`new File("d:/test.jsp::$DATA")`等价于`new File("d:/test.jsp")`，参考：[Microsoft 本地文件系统 - 文件流](https://learn.microsoft.com/zh-cn/windows/win32/fileio/file-streams)；



### 6.2 文件系统操作规范

1. **文件读取**：原则上不允许跨目录读取，例如：`file=../images/1.jpg`，建议读取文件时指定父级目录：`new File("images", file)`，传入参数：`file=1.jpg`，使用相对路径应当遵循本文中的`文件路径和文件名规范`；
2. **文件写入：**
   - 如果文件写入到了服务器本地必须限制写入的文件类型，禁止写入：`jsp/jspx/jspa/jspf/php/aspx/asp`脚本类型，强烈建议使用文件名白名单，如：`jpg/png/gif/bmp`等；
   - 获取文件后缀名时请使用`lastIndexOf(".")`，而不是`indexOf(".")`，防止攻击者使用`1.jpg.jsp`绕过检测；
   - 写入文件时应当做好必要的文件长度限制；
3. **文件删除：**文件删除时禁止使用根目录，防止误删，如：`C:`、`/`，禁止跨目录删除文件，如：`../images/`；
4. **文件复制/重命名：**
   - 文件复制时需要严格检查文件后缀名，例如：将`1.jpg`复制或重命名为`1.jsp`；
   - 文件复制时严格控制目标文件路径，禁止从请求参数中或文件名中指定目录，例如，攻击者复制带有恶意后门的war到webapps目录自动部署后门程序，从而间接的获取服务器权限：`source=1.war&dest=../webapps/1.war`；
5. **文件遍历：**文件遍历时必须指定根目录，如：`new File("images", file)`，`file`路径禁止跨目录：`../`或`..\`，同时该路径应当遵循本文中的`文件路径和文件名规范`；
6. **文件权限和安全性**：了解文件系统的权限和安全性要求，确保只有授权用户可以读取或写入文件。在安全敏感的应用程序中，遵循最小特权原则，仅赋予应用程序所需的文件系统权限；
7. **异常处理：**
   - 使用try-catch块来捕获和处理文件读写可能引发的异常，如：IOException；
   - 在方法签名中声明可能抛出的异常，以便调用者知道需要处理的异常类型，不要捕获异常后不进行任何处理，应该至少记录错误信息或者向上层抛出；
8. **关闭资源：**使用`try-with-resources`（JDK7+）自动关闭或显式关闭文件资源（例如，使用finally块关闭引用的资源）以确保在完成后释放资源；
9. 文件编码：在读取或写入文本文件时，指定正确的字符编码，以确保数据正确解释和保存；
10. NIO优先：对于大文件或需要更高性能的情况，可以考虑使用Java的NIO（New I/O）库，如：ByteBuffer和Channel，以提供更快的文件读写操作；
11. 对象存储：优先使用对象存储方式，如：`阿里云OSS`、`百度云BOS`、`腾讯云COS`，也可使用静态服务器或FTP存储文件；



## 7. JSON解析规范

JSON库禁止使用存在重大安全问题的JSON库或版本，例如`FastJSON1.X`，使用主流的JSON库，如：[Jackson](https://github.com/FasterXML/jackson)、[DSL-Json](https://github.com/ngs-doo/dsl-json)，[FastJSON2](https://github.com/alibaba/fastjson2)、[Gson](https://github.com/google/gson)。



### 7.1 JSON序列化规范

JSON解析应当遵循以下规范：

1. 避免循环引用：当序列化对象包含循环引用时，会导致无限递归，因此需要特别小心处理循环引用情况；
2. 避免使用JSON值`'`（英文单引号），默认使用：`"`（英文双引号）；
3. 正确的序列化空对象，如：List类型为空输出`[]`、String类型为空输出`""`、Number类型为空输出`0`、Boolean类型为空时输出`false`；
4. 统一JSON输出的字段风格，禁止驼峰和下划线混用、允许key为中文，但不推荐；
5. 允许使用Unicode，禁用Hex、Octal编码，因为目前就只有FastJson支持；
6. 禁用注释符：`//、#、/**/`，保证兼容性；
7. JSON字符串大小原则上不允许超过128M；
8. 正确使用基础类型，不建议使用以下值作为基础类型：`1B、1S、1L、1.0F、1.0D、+1、01、.0、-.0、+.0、+-0.1、TRUE`；
9. 不推荐使用`NULL、null、NaN`作为JSON的key或者value；



### 7.2 JSON反序列化规范

1. 禁用FastJSON的`autoType`或禁用`FastJSON1.X`；
2. 验证数据来源，谨慎处理不可信任的数据；
3. 对象反序列化时合理限制类使用黑名单；
4. 使用安全的 JSON 解析库，定期更新和维护使用的 JSON 解析库，以确保它们不受已知的漏洞或安全问题的影响；
5. 限制反序列化操作的递归深度，以防止 JSON 数据中的嵌套结构导致堆栈溢出；
6. 对象反序列化时，JSON对象中的key必须实体类中声明的一致，而不是依赖于JSON库的自动匹配；以JackSon为例，假设JSON中的`user_type`使用了下划线命名：`{"user_type": 1}`那么Java对象中就必须使用JSON的映射：`@JsonProperty("user_type") private int userType;`；



## 7.3 XML解析规范

XML一种主流的数据传输和存储的文件格式，JDK自带的XML解析API默认解析XML的时候就存在XXE漏洞，因此在解析XML时必须禁用外部实体解析，从而防止XXE漏洞。



### 7.3.1 SAXReader/DocumentHelper

**反例 - Dom4J XML SAX解析**

```java
// 解析方式一，直接使用SAXReader解析，未禁用外部实体
org.dom4j.io.SAXReader reader = new org.dom4j.io.SAXReader();
org.dom4j.Document     doc    = reader.read(in);

// 解析方式二，使用DocumentHelper解析，间接的调用SAXReader，未禁用外部实体
// org.dom4j.Document doc = DocumentHelper.parseText(IOUtils.toString(in, StandardCharsets.UTF_8));

org.dom4j.Element root = doc.getRootElement();
```

**示例 - Dom4J SAXReader解析**

```java
SAXReader reader = new org.dom4j.io.SAXReader();

// 禁止DOCTYPE
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁止外部ENTITY
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);

// 禁止外部参数实体
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

org.dom4j.Document doc  = reader.read(in);
```

除此之外，其他的XML解析库、类同理，解析外部输入的XML时应当禁止外部的DOCTYPE，即设置Feature：`http://apache.org/xml/features/disallow-doctype-decl`设置为`true`。



### 7.3.2 SAXParserFactory/XMLReader 

XMLReader  API在Java9中已过，同SAXParserFactory，创建XMLReader后设置setFeature即可。

```java
SAXParserFactory factory = SAXParserFactory.newInstance();

// 禁止DOCTYPE
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁止外部ENTITY
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

// 禁止外部参数实体
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

SAXParser parser  = factory.newSAXParser();
```



### 7.3.3 SAXBuilder

```java
SAXBuilder builder = new SAXBuilder();

// 禁止DOCTYPE
builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁止外部ENTITY
builder.setFeature("http://xml.org/sax/features/external-general-entities", false);

// 禁止外部参数实体
builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

Document doc = builder.build(in);
```



### 7.3.4 DocumentBuilderFactory

```java
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
```

除了上述XML示例，在使用一些第三方库的时候也应当审计程序逻辑是否有禁用外部实体解析，例如：`Hutool v5.8.19`的`cn.hutool.core.util.XmlUtil.java#readBySax`存在XXE漏洞。



## 8. XPath规范

XPath（XML Path Language）是一种用于在XML文档中定位和选择元素和数据的查询语言。XPath可用于检索和操作XML文档的内容，以及在XML文档中执行各种搜索和筛选操作。

XPath注入是一种安全漏洞，类似于SQL注入，它发生在不正确处理用户提供的XPath查询字符串时。攻击者可以通过恶意构造的XPath查询来执行未授权的操作或访问敏感数据。以下是XPath注入的示例：

```xml
<users>
    <user>
        <username>admin</username>
        <password>admin123</password>
    </user>
    <user>
        <username>user1</username>
        <password>pass123</password>
    </user>
</users>
```

如果一个应用程序使用用户提供的输入来构建XPath查询，而没有适当的过滤或转义，攻击者可以通过输入 `username=admin' or '` 来构造恶意查询，绕过身份验证。

**反例 - XPath注入**

```java
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
```

为了解决XPath注入攻击，禁止直接拼接XPath查询语句，需要使用参数化的方式查询。

**示例 - XPath参数化查询**

```java
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
```

**XPath编码建议：**

1. 避免手动将用户输入直接插入XPath查询中。相反，使用参数化查询或预编译的查询；
2. 在接受用户输入之前，对其进行严格的输入验证和过滤。只接受有效的输入，拒绝不符合预期格式的输入。



## 9. 表达式规范

禁止在服务端执行任何用户传入的表达式（例如：`Ognl、SpEL、MVEL2、Javascript`），包括拼接的表达式在内。

**反例 - 表达式注入漏洞**

```java
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
```

表达式注入的直观的危害就是可以在服务端间接的执行攻击者构建的恶意Java代码，例如：调用`java.lang.ProcessBuilder`执行系统命令、调用`java.io.FileOutputStream`写入后门程序，从而达到控制服务器的目的。

**示例 - scriptEngine#eval执行JavaScript脚本**

```java
http://localhost:8080/Expression/scriptEngine.do?exp=new java.lang.String(new java.lang.ProcessBuilder('whoami').start().getInputStream().readAllBytes())
```

**JS执行结果：**

```json
{
    "data": "yzmm\\yzmm\r\n"
}
```



## 10. 本地命令执行规范

本地命令执行（`Local Command Execution`）是一种安全漏洞，它允许攻击者在受害者的计算机上执行任意命令。这种漏洞的危害非常严重，因为攻击者可以利用它来获取操作系统级别的控制权（例如：`RCE利用漏洞`或者`WebShell`），执行恶意操作，窃取敏感数据，或者对系统进行破坏。

对于程序开发者来说执行本地命令来实现某些程序功能（如：ps 进程管理、top内存管理等）是一个正常的需求，但是在执行本地系统命令时应当严格遵守安全开发规范。

**本地命令执行应当遵循以下规范：**

1. 禁止直接从参数中接收并执行系统命令；
2. 原则上禁止执行系统命令，可以考虑使用JNI或者API接口等方式调用外部程序；因此，建议禁用`java.lang.Runtime#exec、java.lang.ProcessBuilder#start`类；
3. 如必须执行系统命令，且必须拼接系统命令，那么务必严格校验传入输入的合法性，例如，调用ping命令检测网络连接时需要传入域名或者IP：`ping baidu.com`，那么传入的就必须是一个合法的主机名、IP、域名，可使用合理的正则表达式、`java.net.InetAddress#getByName`验证；
4. 避免使用`/bin/bash -c、/bin/sh -c、/bin/zsh -c、cmd /c `的方式拼接系统命令，防止命令注入漏洞；



**反例 - 拼接并执行系统命令**

```java
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
```

攻击者传入：`http://localhost:8080/CMD/pingRCE.do?host=baidu.com %26%26 whoami`，拼接后最终执行的系统命令：`cmd /c ping -n 3 baidu.com && whoami`，攻击者使用管道符`&&`实现了系统命令注入，即，在执行完ping命令成功后还执行了`whoami`，程序执行结果如下：

```bash
正在 Ping baidu.com [110.242.68.66] 具有 32 字节的数据:
来自 110.242.68.66 的回复: 字节=32 时间=11ms TTL=54
来自 110.242.68.66 的回复: 字节=32 时间=11ms TTL=54
来自 110.242.68.66 的回复: 字节=32 时间=11ms TTL=54

110.242.68.66 的 Ping 统计信息:
    数据包: 已发送 = 3，已接收 = 3，丢失 = 0 (0% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 11ms，最长 = 11ms，平均 = 11ms
yzmm\yzmm
```

末尾的`yzmm\yzmm`是攻击者注入的`whoami`命令执行的结果，攻击者可以替换成任何其他恶意的系统命令。

**示例 - 验证传入的host**

```java
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
```

这里除了可以使用DNS解析的方式验证传入的host是否合法意外，还可以通过正则表达式的方式，但由于正则表达式容易出现绕过和其他安全问题不推荐；



## 11. 模板引擎规范

SSTI（`Server-Side Template Injection`）漏洞是一种常见的Web应用程序漏洞，发生在服务器端模板引擎处理用户输入时。这种漏洞允许攻击者在服务器上执行恶意模板代码，从而间接的控制Web应用服务器。

谨慎处理任何来源于请求的模板（例如：邮件、短信模板），禁止直接使用模板引擎渲染。

**反例 - 模板注入漏洞**

```java
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
```

**示例 - Velocity模板注入**

```java
http://localhost:8080/SSTI/velocity.do?tpl=%23set($e='e')%23set($c=$e.getClass().forName('org.apache.commons.io.IOUtils'))$c.getMethod('toString',$e.getClass().forName('java.io.InputStream')).invoke(null, $e.getClass().forName('java.lang.Runtime').getMethod('exec', $e.getClass().forName('java.lang.String')).invoke($e.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'whoami').getInputStream())
```

**Velocity执行结果：**

```json
{
    "data": "yzmm\\yzmm\r\n"
}
```



## 12. 验证码规范

强烈建议使用验证目的业务场景：

1. 用户登录、注册、找回密码、账号注销；
2. 修改密码、修改安全设备、修改安全手机/邮件地址；
3. 交易/支付、查看、删除、重置重要数据；



### 12.1 图形验证码

1. 验证码有效期不宜过长，必须设置有效时间；
2. 图形验证码应考虑字符长度、字符扭曲、图像噪音、干扰线等必要因素，防止攻击者采用OCR技术识别；
3. 确保验证码不重复使用，校验一次不管是否正确都必须清除缓存，以防止攻击者多次尝试相同的验证码；
4. 禁止通过API接口返回验证码明文字符串，包括但不限于：Header、Cookie、JSON等；



### 12.2 短信/邮件验证码

1. 验证码有效期不宜过长（建议5分钟以内），必须设置有效时间；
2. 验证码校验次数必须限制（原则上不得超过10次），防止攻击者通过API接口穷举验证码；
3. 建议加密存储验证码，防止因为缓存泄露导致验证机制失效；
4. 严格限制验证码发送频率，防止短信、邮件轰炸漏洞，可自行根据IP地址、用户ID、业务类型等条件限制；
5. 验证码中应包含必要的安全提示，声明此验证码具体业务类型，防止钓鱼攻击；
6. 选择可信赖的短信和邮件服务提供商，防止中间人劫持；
7. 妥善保存短信、邮件平台的安全密钥信息；



## 13. Token机制

敏感操作都必须添加Token/Referer校验，防止CSRF攻击。

这里以CSRF修改用户密码为例，假设修改密码接口没有添加Token校验，并没有验证旧密码的场景，攻击者可以构建一个用于修改用户密码的URL，诱骗用户访问该URL地址，从而悄无声息的修改用户密码。

**攻击路线如下：**

1. 找到修改密码的URL地址，例如：https://xx.com/user/changePassWord.do?password=A123456；
2. 诱骗用户访问此URL地址，或者使用中间人劫持的方式迫使用户访问该URL，例如，某个论坛存在此类漏洞，那么攻击者可以在论坛发帖，图片的URL地址指向这个恶意修改密码的接口地址，用户打开帖子的时候会自动加载图片，从而间接的带着有效的Cookie访问了此接口最终实现修改了用户密码；
3. 服务器端校验用户身份信息并修改密码，攻击者重置了目标用户的密码；

当然，此类攻击行为可以应用于非常多的业务场景，例如：转账、修改安全设备、重置密码、删除文章等。因此，访问敏感的业务时必须校验Token或图形验证码，参考流程如下：

1. 访问重要业务时服务端生成并缓存Token，返回Token到客户端；
2. 客户端访问接口时带上Token；
3. 服务器校验Token、Referer，并移除Token；



## 14. 正则表达式规范

正则表达式是一种强大的文本处理工具，但在使用时需要小心谨慎，因为正则表达式在处理输入数据时非常容易出现规则绕过或其他安全问题。

在编写正则表达式时应当注意以下安全问题：

1. 大小写绕过，`Pattern.compile("test", Pattern.CASE_INSENSITIVE)`；
2. 多行绕过，`Pattern.DOTALL、Pattern.MULTILINE`；
3. 匹配单词时切勿使用忘记`\b`，如：`\btest\b`；
4. 单行匹配时应明确匹配的范围，例如，完整匹配文本为：`test`，那么应该加上`^test$`，防止匹配范围绕过；
5. 空白符、换行符和空格绕过，合理利用`\s`，例如，匹配文本：`id=123`，可能`id`或者`=`号后边可以有换行符或者空格；
6. ReDOS正则回溯攻击；



### 14.1 ReDOS

ReDoS（`Regular Expression Denial of Service`）正则表达式拒绝服务攻击，攻击者试图利用正则表达式引擎的特性来导致性能下降或拒绝服务攻击。ReDoS攻击的本质是通过构造恶意的正则表达式模式和输入数据，来使正则表达式引擎在匹配时执行大量回溯操作，从而耗尽计算资源或导致服务器不可用。



**攻击原理：**

ReDoS攻击的核心原理是正则表达式引擎的回溯机制。正则表达式通常使用回溯算法来寻找匹配的子串，而恶意构造的正则表达式模式和输入可以导致引擎在搜索匹配时不断回溯和尝试不同的路径。如果正则表达式模式允许大量的回溯，攻击者可以构造输入，使引擎在匹配时需要执行指数级别的回溯操作，导致性能下降或拒绝服务攻击。

**示例 - ReDoS攻击**

正则表达式：`^(a+)+$` ，攻击者输入：`aaaaaaaaaa!`

**匹配的过程如下：**

1. `(a+)` 匹配 `a`（1 次尝试）；
2. `(a+)` 匹配 `aa`（2 次尝试）；
3. `(a+)` 匹配 `aaa`（3 次尝试；
4. ...
5. `(a+)` 匹配 `aaaaaaaaaa`（10 次尝试）；

对于正则表达式 `^(a+)+$` 和输入字符串 "aaaaaaaaaa!"，匹配的次数应该是`2^10`次方次（即 1024 次尝试），而不是只匹配一次。这是因为正则表达式中的 `(a+)+` 允许多次回溯，以尝试不同的匹配路径，如果攻击者填充的数据过长就能实现拒绝服务攻击。

**示例 - 存在ReDOS的正则表达式**

```js
– 英文名
  正则表达式: ^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])? [a-zA-Z]*)*$
  Payload: aaaaaaaaaaaaaaaaaaa!
– Java 类名
  正则表达式: ^(([a-z])+.)+[A-Z]([a-z])+$
  Payload: aaaaaaaaaaaaaaaaaaa!
– 邮箱
  正则表达式: ^([a-zA-Z0-9]+)([\._-]?[a-zA-Z0-9]+)*@([a-zA-Z0-
9]+)([\._-]?[a-zA-Z0-9]+)*([\.]{1}[a-zA-Z0-9]{2,})+$
  Payload: a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!

```



## 15. 多线程开发规范

在开发多线程、分布式业务时应当注意以下问题：

1. 竞态条件，多个线程同时访问共享资源或对象时可能导致条件竞争，破坏数据的一致性，因此需要使用锁、同步块或使用线程安全的数据结构等机制规避此类问题；
2. 死锁， 当多个线程相互等待对方释放资源时可能导致死锁，需要设计合理的资源释放方案，如：避免循环等待条件、使用超时机制、按顺序获取锁等；
3. 合理限制线程数、CPU、内存资源， 多线程应用程序可能耗尽系统资源，如：内存、CPU 和文件句柄等，因此需要限制线程数量；
4. 使用线程安全的数据结构， 尽量使用线程安全的`Java.util.concurrent（JUC）`提供的对象，如：`java.util.concurrent.ConcurrentHashMap`，以避免在多线程环境中出现数据竞争和不一致性；
5. 合理使用线程池，应当优先使用线程池管理线程而不是Thread类，JUC 提供了 `java.util.concurrent.ThreadPoolExecutor`类，用于创建和管理线程池。线程池可以有效地管理线程的生命周期，提高线程的复用，以及限制并发线程数量，从而提高应用程序的性能；
6. 正确理解`Synchronized、ReentrantLock、ReadWriteLock、StampedLock、Condition`机制，搞清楚锁的类型、范围、使用场景等；



## 16. 开源框架/组件/中间件使用规范

开源产品在为程序开发提供便利的同时也带来了一些潜在的安全风险，早年的Struts2框架是最为流行的MVC框架，曾一度因为安全问题严重的影响了整个互联网安全。

除此之外，JBoss、Weblogic、FastJson、Log4j2等诸多漏洞犹如洪水猛兽疯狂的威胁着业务系统安全。为了避免因使用第三方的产品和技术带来的安全问题，在技术选型时应当优先选择安全性高、易用性强的技术或产品。

以下列举一些技术选型方案：

1. 所选择的任何框架、中间件、组件都需严格确认没有已知的安全问题，例如`Maven/Gradle`依赖可使用`MurphySec Code Scan、Checkmarx`等检测后不存在安全风险方可使用，可借助CNVD、CVE的漏洞库确认所使用的版本是否存在安全问题；
2. 慎用或不用高风险组件解析请求参数，如：`Fastjson、XMLDecoder、XStream、Shiro`，全面禁用`Fastjson1`；
3. 中间件需修改默认口令、有默认密钥的必须重置，有未授权访问的服务应当修改绑定地址到`127.0.0.1`，禁止在内网或公网提供服务，例如：`ElasticSearch、Apache Solr、Spring Actuator、Redis`；
4. 禁止在生产环境中使用Swagger、Tomcat/Java等远程调试模式，防止信息泄露和远程代码执行漏洞；
5. 新项目禁用或不用一些已过时或存在非常多安全问题的技术，如：`Struts2、JDK<=1.6、Apache Axis、JSP、JSF、DWR、Java Applets`等；
6. 禁用有开源协议风险的组件，如：GPL（`GNU General Public License`，GNU通用公共许可证）、LGPL（`GNU Lesser General Public License`，GNU较宽松通用公共许可证）等；
7. 禁用盗版、破解类或其他侵害他人著作权的产品；
8. 禁用活跃度过低的开源产品；



## 17. 版本管理规范

版本管理规范是一个重要的开发实践，可以确保团队在代码的版本控制和协作方面具有一致性。以下是一些关于版本管理规范的最佳实践：

1. 严厉禁止将涉密或内部产品源码提交到Github或者其他开源平台；
2. 妥善保管版本管理工具的Key或密码，严禁以任何形式公开访问权限；
3. 禁止外借个人凭证、窃取他人账号；
4. 版本库应当采取严格的权限控制，遵循最小权限原则；
5. Git尽可能使用SSH Key而不是使用密码访问；
6. 原则上禁止强制推送（`Force Push`）操作，因为会破坏Git仓库的历史记录，应该限制其使用，或者只允许管理员执行；
7. 如果使用Gitlab应当强制开启2FA验证；
8. 提交代码时应当清楚的记录修改信息；
9. 主分支保护机制，禁止低权限的开发者将Dev分支的代码合并到Master；
10. 禁止提交敏感信息，例如：API密钥、个人密码等，可使用`.gitignore`来排除敏感文件；
11. 定期更新版本管理工具，建议启用版本库自动更新、安全检查和代码审计插件；
12. 版本库应当定期全量备份，备份文件必须加密存储并将文件同步到专用的备份服务器；
13. 代码提交时务必自行审计，建议项目组内交叉审计，尤其是合并他人代码时应当谨慎操作；



## 18. Java反序列化规范

Java序列化对象因其可以方便的将对象转换成字节数组，又可以方便快速的将字节数组反序列化成Java对象而被非常频繁的被用于`Socket`传输。 在`RMI(Java远程方法调用-Java Remote Method Invocation)`和`JMX(Java管理扩展-Java Management Extensions)`服务中对象反序列化机制被强制性使用。在Http请求中也时常会被用到反序列化机制，如：直接接收序列化请求的后端服务、使用Base编码序列化字节字符串的方式传递等。

自从2015年[Apache Commons Collections反序列化漏洞](https://issues.apache.org/jira/browse/COLLECTIONS-580)利用方式被公开后无数的使用了反序列化机制的Java应用系统惨遭黑客疯狂的攻击，为企业安全甚至是国家安全带来了沉重的打击！

Java反序列化应当遵循以下规范：

1. 原则上禁止使用RMI技术；
2. 建议禁用JNDI中的：`iiop://、iiopname://、corbaname://、ldap://、rmi://`协议；
3. 原则上禁止使用Java对象反序列化（`java.io.ObjectInputStream#readObject`），如必须使用应当自行重写`java.io.ObjectInputStream#resolveClass/resolveProxyClass`添加禁止反序列化的类黑名单，或使用RASP防御Web业务系统；
4. 使用高版本的JDK，JDK 8u191以上；
5. 限制外部网络访问，原则上生产环境禁止访问外网服务，防止外部JNDI注入攻击；
6. 慎用使用了Java对象反序列化的框架或服务，例如：`Weblogic、Shiro、Hessian`等；



## 19. 安全工具链

在开发阶段应当借助一些安全开发工具链来完善Web安全，合理的使用安全开发工具可以将安全问题扼杀于编码阶段。

**SAST**

SAST（`Static Application Security Testing`，静态应用程序安全测试），SAST工具通过扫描并分析程序源代码或编译后的代码，检查潜在的安全问题，如漏洞、弱点和缺陷。



**DAST**

DAST（`Dynamic Application Security Testing`，动态应用程序安全测试）是一种应用程序安全测试技术，用于检测和评估正在运行的应用程序的安全性。DAST与SAST不同，它不关注应用程序的源代码，而是专注于应用程序的运行时行为。



**RASP**

运行时应用程序自我保护（`Runtime application self-protection`，简称`RASP`）使用Java Agent技术在应用程序运行时候动态编辑类字节码，将自身防御逻辑注入到Java底层API和Web应用程序当中，从而与应用程序融为一体，能实时分析和检测Web攻击，使应用程序具备自我保护能力。

RASP技术作为新兴的WEB防御方案，不但能够有效的防御传统WAF无法实现的攻击类型，更能够大幅提升对攻击者攻击行为的检测精准度。RASP是传统WAF的坚实后盾，能够弥补WAF无法获取Web应用`运行时`环境的缺陷，同时也是传统Web应用服务最重要的不可或缺的一道安全防线。



**IAST**

IAST（`Interactive Application Security Testing`，交互式应用程序安全测试）结合了SAST和DAST的特点技术原理同RASP，它在应用程序运行时监控应用程序的行为，同时也分析应用程序的源代码和配置。IAST能够在实际执行应用程序时检测漏洞，提供更精确的漏洞报告。



**SCA**

SCA（`Software Composition Analysis`，软件构成分析），SCA工具通过分析应用程序的依赖关系，特别是开源库和组件，来检测已知的漏洞和安全问题。它们会扫描项目中使用的各种依赖项，并与已知漏洞数据库进行比对，以识别潜在的风险。

SCA解决了使用开源库和组件时的安全风险。它们有助于防止已知漏洞的利用，确保依赖项的版本是最新且没有已知的安全问题。这可以降低应用程序受到依赖项漏洞攻击的风险，提高应用程序的整体安全性。

[MurphySec Code Scan](https://plugins.jetbrains.com/plugin/18274-murphysec-code-scan)是墨菲安全推出的一款免费的JetBrains IDE插件，让开发者在 IDE 中即可检测代码依赖的安全问题，轻松识别代码中使用了哪些存在安全缺陷的开源组件，通过准确的修复方案和一键修复功能，快速解决安全问题；





