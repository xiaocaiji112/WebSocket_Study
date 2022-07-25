### 1.引入依赖

```yaml
    <parent>
        <artifactId>spring-boot-starter-parent</artifactId>
        <groupId>org.springframework.boot</groupId>
        <version>2.6.6</version>
    </parent>
    
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-websocket</artifactId>
        </dependency>

        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.79</version>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
    </dependencies>
```

### 2.SocketServer

```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.PathParam;
import javax.websocket.server.ServerEndpoint;


import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;

@ServerEndpoint(value = "/javatest/ws/{sid}")
@Component
public class WebSocketServer {

    private  final static Logger log = LoggerFactory.getLogger(WebSocketServer.class);
    //静态变量，用来记录当前在线连接数。应该把它设计成线程安全的。

    private static int onlineCount = 0;
    //与某个客户端的连接会话，需要通过它来给客户端发送数据
    private Session session;
    //旧：concurrent包的线程安全Set，用来存放每个客户端对应的MyWebSocket对象。由于遍历set费时，改用map优化
    //private static CopyOnWriteArraySet<WebSocketServer> webSocketSet = new CopyOnWriteArraySet<WebSocketServer>();
    //新：使用map对象优化，便于根据sid来获取对应的WebSocket
    private static final ConcurrentHashMap<String,WebSocketServer> websocketMap = new ConcurrentHashMap<>();
    //接收用户的sid，指定需要推送的用户
    private String sid;


    /**
     * 连接成功后调用的方法
     */
    @OnOpen
    public void onOpen(Session session,@PathParam("sid") String sid) {
        this.session = session;
        WebSocketServer webSocketServer = websocketMap.get(sid);
        if (webSocketServer == null){
            websocketMap.put(sid,this); //加入map中
            addOnlineCount();           //在线数加1
            log.info("有新窗口开始监听:"+sid+",当前在线人数为" + getOnlineCount());
            this.sid=sid;
            try {
                sendMessage("连接成功");
            } catch (IOException e) {
                log.error("websocket IO异常");
            }
        }else {
            try {
                webSocketServer.sendMessage("你被顶了");
            } catch (IOException e) {
                e.printStackTrace();
            }
            webSocketServer.onClose();
            websocketMap.put(sid,this); //加入map中
            addOnlineCount();           //在线数加1
            log.info("有新窗口开始监听:"+sid+",当前在线人数为" + getOnlineCount());
            this.sid=sid;
            try {
                sendMessage("连接成功");
            } catch (IOException e) {
                log.error("websocket IO异常");
            }
        }

    }

    /**
     * 连接关闭调用的方法
     */
    @OnClose
    public void onClose() {
        if(websocketMap.get(this.sid)!=null){
            //webSocketSet.remove(this);  //从set中删除
            websocketMap.remove(this.sid);  //从map中删除
            subOnlineCount();           //在线数减1
            log.info("有一连接关闭！当前在线人数为" + getOnlineCount());
        }
    }

    /**
     * 收到客户端消息后调用的方法，根据业务要求进行处理，这里就简单地将收到的消息直接群发推送出去
     * @param message 客户端发送过来的消息
     */
    @OnMessage
    public void onMessage(String message, Session session) throws IOException {
        log.info("收到来自窗口"+sid+"的信息:"+message);
        message = message.substring(1,message.length() - 1);
        JSONObject jsonObject = JSONObject.parseObject(message);
        if(!message.isEmpty()){
            log.info("6666");
            WebSocketServer server = websocketMap.get(jsonObject.get("toUserId").toString());
            if(server != null){
                try {
                    server.sendMessage(message);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }else {
                this.sendMessage("不存在哦");
            }


        }
    }

    /**
     * 发生错误时的回调函数
     * @param session
     * @param error
     */
    @OnError
    public void onError(Session session, Throwable error) {
        log.error("发生错误");
        error.printStackTrace();
    }

    /**
     * 实现服务器主动推送消息
     */
    public void sendMessage(String message) throws IOException {
        this.session.getBasicRemote().sendText(message);
    }


    /**
     * 群发自定义消息（用set会方便些）
     * */
    public static void sendInfo(String message,@PathParam("sid") String sid) throws IOException {
        log.info("推送消息到窗口"+sid+"，推送内容:"+message);
        /*for (WebSocketServer item : webSocketSet) {
            try {
                //这里可以设定只推送给这个sid的，为null则全部推送
                if(sid==null) {
                    item.sendMessage(message);
                }else if(item.sid.equals(sid)){
                    item.sendMessage(message);
                }
            } catch (IOException e) {
                continue;
            }
        }*/
        if(!message.isEmpty()){
            for(WebSocketServer server:websocketMap.values()) {
                try {
                    // sid为null时群发，不为null则只发一个
                    if (sid == null) {
                        server.sendMessage(message);
                    } else if (server.sid.equals(sid)) {
                        server.sendMessage(message);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    continue;
                }
            }
        }
    }

    public static synchronized int getOnlineCount() {
        return onlineCount;
    }
    public static synchronized void addOnlineCount() {
        WebSocketServer.onlineCount++;
    }
    public static synchronized void subOnlineCount() {
        WebSocketServer.onlineCount--;
    }

}

```

### 3.配置WebSocketConfig

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.server.standard.ServerEndpointExporter;

@Configuration
public class WebSocketConfig {


    /**
     * 如果使用Springboot默认内置的tomcat容器，则必须注入ServerEndpoint的bean；
     * 如果使用外置的web容器，则不需要提供ServerEndpointExporter，下面的注入可以注解掉
     */
    @Bean
    public ServerEndpointExporter serverEndpointExporter(){
        return new ServerEndpointExporter();
    }


}
```

### 4.UserDetails

```java

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class User implements UserDetails {
    private String username;
    private String password;
    private ArrayList<String> permissions;


    private List<SimpleGrantedAuthority> permissionsList ;

    public User(String username, String password, ArrayList<String> permissions) {
        this.username = username;
        this.password = password;
        this.permissions = permissions;
    }


    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public User() {
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", permissions=" + permissions +
                '}';
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //将permissions中的string类型的权限封装成她的实现类SimpleGrantedAuthority
        if (this.permissionsList != null){
            return this.permissionsList;
        }
        List<SimpleGrantedAuthority> list = new ArrayList<>();

        for (String permission : permissions) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(permission);
            list.add(authority);
        }
        this.permissionsList = list;
        return permissionsList;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override

    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override

    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override

    public boolean isEnabled() {
        return true;
    }

    public ArrayList<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(ArrayList<String> permissions) {
        this.permissions = permissions;
    }
}
```

### 5.SecuriyConfig

```java
import com.ws.fillter.FIllterT;
import com.ws.fillter.JwtAuthenticationTokenFilter;

import com.ws.handl.AuthenticationEntryPointImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    JwtAuthenticationTokenFilter authenticationTokenFilter;
    @Autowired
    FIllterT fIllterT;
    @Bean
    public PasswordEncoder passwordEncoder (){
        return  new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    AuthenticationEntryPointImpl authenticationEntryPoint;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable().
                //不通过Session获取SecurityContext
                        sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口允许匿名访问
                //这里的路径一定前面要加/ 不然不好使
                .antMatchers("/user/login","/javatest/ws/**","/websocket/test").anonymous()

                //出上面以外的所有请求全部需要鉴全认证
                .anyRequest().authenticated();
        //添加过滤器
         http.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
         http.addFilterBefore(fIllterT,UsernamePasswordAuthenticationFilter.class);

        http.exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint);

    }
    @Override
    public void configure(WebSecurity web) throws Exception {
/*        web.ignoring().antMatchers(
                "/javatest/ws/**"
        );*/
    }
}

```

### 6.filter

```java

import com.ws.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Objects;

@Component
@Order(1)
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {



        //获取token
        String token = request.getHeader("token");
        System.out.println("token=="+token);
        if(token == null){
            System.out.println("未携带 token 首部");
            //放行 进去其他的过滤器
            filterChain.doFilter(request,response);
            //调用会回来的 不可以让他执行下面的 代码哦
            return;
        }
        User user = new User();
        //解析token
        System.out.println("让进");
        //完事从redis中取出来LoginUser 这里要比对的
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken //这个传进去的是从redis中取出来的对象哦
                = new UsernamePasswordAuthenticationToken(
                user
                ,null, null);
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        //放行
        filterChain.doFilter(request,response);
    }
}

```

```java

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(2)
public class FIllterT  extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("request.getRequestURI() = " + request.getRequestURI());
        String token = request.getParameter("token");
        if(token != null){
            System.out.println("执行");
            filterChain.doFilter(request,response);
        }else {
            System.out.println("不执行");
            filterChain.doFilter(request,response);
        }

    }
}

```

文件路径



![image-20220725134758260](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20220725134758260.png)