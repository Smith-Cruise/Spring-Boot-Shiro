# Shiro+JWT+Spring Boot Restful简易教程
> 之前有一个写过一个老版本教程，如果需要查看请前往`old`分支。本次教程添加了注解支持，完善了JWT的机制，并且添加过期时间的校验等。

### 序言

我也是半路出家的人，如果大家有什么好的意见或批评，请务必`issue`下。

项目地址：https://github.com/Smith-Cruise/Spring-Boot-Shiro 。

如果想要体验下，从 [release](https://github.com/Smith-Cruise/Spring-Boot-Shiro/releases) 处下载运行`java -jar file_name.jar `即可。网址规则自行看教程后面。

### 准备工作

在开始本教程之前，请保证已经熟悉以下几点。

- Spring Boot 基本语法，至少要懂得`Controller`、`RestController`、`Autowired`等这些基本注释。其实看看官方的Getting-Start教程就差不多了。
- [JWT](https://jwt.io/) （Json Web Token）的基本概念，并且会简单操作JWT的 [JAVA SDK](https://github.com/auth0/java-jwt)。
- Shiro的基本操作，看下官方的 [10 Minute Tutorial](http://shiro.apache.org/10-minute-tutorial.html) 即可。
- 模拟HTTP请求工具，我使用的是PostMan。

简要的说明下我们为什么要用JWT，因为我们要实现完全的前后端分离，所以不可能使用`session`，`cookie`的方式进行鉴权，所以JWT就被派上了用场，你可以通过一个加密密钥来进行前后端的鉴权。

### 程序逻辑

1. 我们POST用户名与密码到`/login`进行登入，如果成功返回一个加密token，失败的话直接返回401错误。
2. 之后用户访问每一个需要权限的网址请求必须在`header`中添加`Authorization`字段，例如`Authorization: token`，`token`为密钥。
3. 后台会进行`token`的校验，如果有误会直接返回401。

### Token加密说明

- 携带了`username`信息在token中。
- 设定了过期时间。
- 使用用户登入密码对`token`进行加密。

### Token校验流程

1. 获得`token`中携带的`username`信息。
2. 进入数据库搜索这个用户，得到他的密码。
3. 使用用户的密码来检验`token`是否正确。

### 准备Maven文件

新建一个Maven工程，添加相关的dependencies。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.inlighting</groupId>
    <artifactId>shiro-study</artifactId>
    <version>1.0-SNAPSHOT</version>

    <dependencies>

        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring</artifactId>
            <version>1.3.2</version>
        </dependency>
        <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>3.2.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>1.5.8.RELEASE</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
        	<!-- Srping Boot 打包工具 -->
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <version>1.5.7.RELEASE</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>repackage</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
            <!-- 指定JDK编译版本 -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <configuration>
                    <source>1.8</source>
                    <target>1.8</target>
                    <encoding>UTF-8</encoding>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

注意指定JDK版本和编码

### 构建简易的数据源

为了缩减教程的代码，我使用`HashMap`本地模拟了一个数据库，结构如下

| username | password | role  | permission |
| -------- | -------- | ----- | ---------- |
| smith    | smith123 | user  | view       |
| danny    | danny123 | admin | view,edit  |

这是一个最简单的用户权限表，如果想更加进一步了解，自行百度RABC。

之后再构建一个`Service`来模拟数据库查询，并且把结果放到`UserBean`之中。

###### Service.java

```java
@Component
public class Service {

    public UserBean getUser(String username) {
        // 没有此用户直接返回null
        if (! DataSource.getData().containsKey(username))
            return null;

        UserBean user = new UserBean();
        Map<String, String> detail = DataSource.getData().get(username);

        user.setUsername(username);
        user.setPassword(detail.get("password"));
        user.setRole(detail.get("role"));
        user.setPermission(detail.get("permission"));
        return user;
    }
}
```

###### UserBean.java

```java
public class UserBean {
    private String username;

    private String password;

    private String role;

    private String permission;

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

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }
}
```

### 配置JWT

我们写一个简单的JWT加密，校验工具，并且使用用户自己的密码充当加密密钥，这样保证了token 即使被他人截获也无法破解。并且我们在`token`中附带了`username`信息，并且设置密钥5分钟就会过期。

```java
public class JWTUtil {

    // 过期时间5分钟
    private static final long EXPIRE_TIME = 5*60*1000;

    /**
     * 校验token是否正确
     * @param token 密钥
     * @param secret 用户的密码
     * @return 是否正确
     */
    public static boolean verify(String token, String username, String secret) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username", username)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    /**
     * 获得token中的信息无需secret解密也能获得
     * @return token中包含的用户名
     */
    public static String getUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 生成签名,5min后过期
     * @param username 用户名
     * @param secret 用户的密码
     * @return 加密的token
     */
    public static String sign(String username, String secret) {
        try {
            Date date = new Date(System.currentTimeMillis()+EXPIRE_TIME);
            Algorithm algorithm = Algorithm.HMAC256(secret);
            // 附带username信息
            return JWT.create()
                    .withClaim("username", username)
                    .withExpiresAt(date)
                    .sign(algorithm);
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }
}
```

### 构建URL

###### ResponseBean.java

既然想要实现restful，那我们要保证每次返回的格式都是相同的，因此我建立了一个`ResponseBean`来统一返回的格式。

```java
public class ResponseBean {
    
    // http 状态码
    private int code;

    // 返回信息
    private String msg;

    // 返回的数据
    private Object data;

    public ResponseBean(int code, String msg, Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }
}
```

###### 自定义异常

为了实现我自己能够手动抛出异常，我自己写了一个`UnauthorizedException.java`

```java
public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(String msg) {
        super(msg);
    }

    public UnauthorizedException() {
        super();
    }
}
```

###### URL结构

| URL          | 作用            |
| ------------ | ------------- |
| /login       | 登入            |
| /edit        | 拥有edit权限的才能访问 |
| /admin/hello | admin角色用户才能访问 |
| /401         | 用于显示401       |

###### Controller

```java
@RestController
public class UserController {

    private static final Logger LOGGER = LogManager.getLogger(UserController.class);

    private Service service;

    @Autowired
    public void setService(Service service) {
        this.service = service;
    }

    @PostMapping("/login")
    public ResponseBean login(@RequestParam("username") String username,
                              @RequestParam("password") String password) {
        UserBean userBean = service.getUser(username);
        if (userBean.getPassword().equals(password)) {
            return new ResponseBean(200, "Login success", JWTUtil.sign(username, password));
        } else {
            throw new UnauthorizedException();
        }
    }

    @GetMapping("/edit")
    public ResponseBean edit() {
        return new ResponseBean(200, "You are editing now", null);
    }

    @GetMapping("/admin/hello")
    public ResponseBean adminView() {
        return new ResponseBean(200, "You are visiting admin content", null);
    }

    @GetMapping("/annotation/require_auth")
    @RequiresAuthentication
    public ResponseBean annotationView1() {
        return new ResponseBean(200, "You are visiting require_auth", null);
    }

    @GetMapping("/annotation/require_role")
    @RequiresRoles("admin")
    public ResponseBean annotationView2() {
        return new ResponseBean(200, "You are visiting require_role", null);
    }

    @GetMapping("/annotation/require_permission")
    @RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})
    public ResponseBean annotationView3() {
        return new ResponseBean(200, "You are visiting permission require edit,view", null);
    }


    @RequestMapping(path = "/401")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseBean unauthorized() {
        return new ResponseBean(401, "Unauthorized", null);
    }
}
```

###### 处理框架异常

之前说过restful要统一返回的格式，所以我们也要全局处理`Spring Boot`的抛出异常。利用`@RestControllerAdvice`能很好的实现。

```java
@RestControllerAdvice
public class ExceptionController {

    // 捕捉shiro的异常
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(ShiroException.class)
    public ResponseBean handle401(ShiroException e) {
        return new ResponseBean(401, e.getMessage(), null);
    }

    // 捕捉UnauthorizedException
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseBean handle401() {
        return new ResponseBean(401, "Unauthorized", null);
    }

    // 捕捉其他所有异常
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseBean globalException(HttpServletRequest request, Throwable ex) {
        return new ResponseBean(getStatus(request).value(), ex.getMessage(), null);
    }

    private HttpStatus getStatus(HttpServletRequest request) {
        Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
        if (statusCode == null) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
        return HttpStatus.valueOf(statusCode);
    }
}

```

### 配置Shiro

大家可以先看下官方的 [Spring-Shiro](http://shiro.apache.org/spring.html) 整合教程，有个初步的了解。不过既然我们用了`Spring-Boot`，那我们肯定要争取零配置文件。

###### 实现JWTToken

`JWTToken`差不多就是`Shiro`用户名密码的载体。因为我们是前后端分离，服务器无需保存用户状态，所以不需要`RememberMe`这类功能，我们简单的实现下`AuthenticationToken`接口即可。因为`token`自己已经包含了用户名等信息，所以这里我就弄了一个字段。如果你喜欢钻研，可以看看官方的`UsernamePasswordToken`是如何实现的。

```java
public class JWTToken implements AuthenticationToken {

    // 密钥
    private String token;

    public JWTToken(String token) {
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
```

###### 实现Realm

`realm`的用于处理用户是否合法的这一块，需要我们自己实现。

```java
public class MyRealm extends AuthorizingRealm {

    private static final Logger LOGGER = LogManager.getLogger(MyRealm.class);

    private Service service;

    MyRealm() {
        service = new Service();
    }

    /**
     * 大坑！，必须重写此方法，不然Shiro会报错
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JWTToken;
    }

    /**
     * 只有当需要检测用户权限的时候才会调用此方法，例如checkRole,checkPermission之类的
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = JWTUtil.getUsername(principals.toString());
        UserBean user = service.getUser(username);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addRole(user.getRole());
        Set<String> permission = new HashSet<>(Arrays.asList(user.getPermission().split(",")));
        simpleAuthorizationInfo.addStringPermissions(permission);
        return simpleAuthorizationInfo;
    }

    /**
     * 默认使用此方法进行用户名正确与否验证，错误抛出异常即可。
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken auth) throws AuthenticationException {
        String token = (String) auth.getCredentials();
        // 解密获得username，用于和数据库进行对比
        String username = JWTUtil.getUsername(token);
        if (username == null) {
            throw new AuthenticationException("token invalid");
        }

        UserBean userBean = service.getUser(username);
        if (userBean == null) {
            throw new AuthenticationException("User didn't existed!");
        }

        if (! JWTUtil.verify(token, username, userBean.getPassword())) {
            throw new AuthenticationException("Username or password error");
        }

        return new SimpleAuthenticationInfo(token, token, "my_realm");
    }
}
```

在`doGetAuthenticationInfo`中用户可以自定义抛出很多异常，详情见文档。

###### 重写Filter

所有的请求都会先经过`Filter`，所以我们继承官方的`BasicHttpAuthenticationFilter`，并且重写鉴权的方法。

```java
public class JWTFilter extends BasicHttpAuthenticationFilter {

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        // 获取Authorization字段
        String authorization = httpServletRequest.getHeader("Authorization");
        if (authorization!=null) {
            try {
                JWTToken token = new JWTToken(authorization);
                // 提交给realm进行登入，如果错误他会抛出异常并被捕获
                getSubject(request, response).login(token);
                return true;
            } catch (Exception e) {
                response401(request, response);
                return false;
            }
        } else {
            response401(request, response);
            return false;
        }
    }

    /**
     * 将请求返回到 /401
     */
    private void response401(ServletRequest req, ServletResponse resp) throws Exception {
        HttpServletResponse httpServletResponse = (HttpServletResponse) resp;
        httpServletResponse.sendRedirect("/401");
    }
}
```

`getSubject(request, response).login(token);`这一步就是提交给了`realm`进行处理

###### 配置Shiro

```java
@Configuration
public class ShiroConfig {

    @Bean("securityManager")
    public DefaultWebSecurityManager getManager() {
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        // 使用自己的realm
        manager.setRealm(new MyRealm());

        /*
         * 关闭shiro自带的session，详情见文档
         * http://shiro.apache.org/session-management.html#SessionManagement-StatelessApplications%28Sessionless%29
         */
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
        subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
        manager.setSubjectDAO(subjectDAO);

        return manager;
    }

    @Bean("shiroFilter")
    public ShiroFilterFactoryBean factory(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();

        // 添加自己的过滤器并且取名为jwt
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("jwt", new JWTFilter());
        factoryBean.setFilters(filterMap);

        factoryBean.setSecurityManager(securityManager);
        factoryBean.setUnauthorizedUrl("/401");

        /*
         * 自定义url规则
         * http://shiro.apache.org/web.html#urls-
         */
        Map<String, String> filterRuleMap = new HashMap<>();
        filterRuleMap.put("/edit", "jwt, perms[edit]");
        filterRuleMap.put("/admin/**", "jwt, roles[admin]");
        filterRuleMap.put("/annotation/**", "jwt");
        filterRuleMap.put("/**", "anon");
        factoryBean.setFilterChainDefinitionMap(filterRuleMap);
        return factoryBean;
    }

    /**
     * 下面的代码是添加注解支持
     */
    @Bean
    @DependsOn("lifecycleBeanPostProcessor")
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        return new DefaultAdvisorAutoProxyCreator();
    }

    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }
}
```

里面URL规则自己参考文档即可http://shiro.apache.org/web.html 。

### 总结

我就说下代码还有哪些可以进步的地方吧

- 没有实现Shiro的`Cache`功能。
- Shiro中鉴权失败时不能够直接返回401信息，而是通过跳转到`/401`地址实现。