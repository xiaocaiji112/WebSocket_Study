package com.ws.server;


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
