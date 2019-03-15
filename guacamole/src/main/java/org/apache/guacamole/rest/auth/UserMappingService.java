package org.apache.guacamole.rest.auth;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.file.Authorization;
import org.apache.guacamole.auth.file.FileAuthenticationProvider;
import org.apache.guacamole.auth.file.UserMapping;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleUserContext;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author yangmh
 * @Description TODO
 * @data 2019/3/6
 */
@Path("/userMapping")
public class UserMappingService {

    public static final String USERNAME = "cloudsino";
    public static final String PASSWORD = "cloudsino";


    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(UserMappingService.class);

    @Path("/set/{protocol}/{hostname}/{port}/{serverNodeIP}/{serverNodePort}")
    @Produces(MediaType.TEXT_PLAIN)
    @POST
    public String setConfig(
            @PathParam("protocol") String protocol,
            @PathParam("hostname") String hostname,
            @PathParam("port") String port,
            @PathParam("serverNodeIP") String serverNodeIP,
            @PathParam("serverNodePort") String serverNodePort,
            @Context HttpServletResponse response
    ) throws GuacamoleException {
//        protocol="ssh";
//        hostname="192.168.100.184";
//        serverNodeIP="172.16.1.19";
//        port="22";
        if (protocol == null || hostname == null || serverNodeIP == null || port == null) {
            return "传入参数 protocol hostname port serverNodeIP 不能为null";
        }

        if(serverNodePort == null || serverNodePort.trim().length() == 0){
            //后台服务默认端口
            serverNodePort = "4822";
        }

        String configKey = protocol + "-" + hostname+"-"+port;

        Map<String,String> serverConfigMap  = new HashMap<String,String>(2);
        serverConfigMap.put(SimpleConnection.SERVERNODEIP,serverNodeIP);
        serverConfigMap.put(SimpleConnection.SERVERNODEPORT,serverNodePort);
        SimpleConnection.serverNodeMap.put(configKey , serverConfigMap);


        init();
//         容许跨域请求
//        response.addHeader("Access-Control-Allow-Origin", "*");
//        response.setHeader("Access-Control-Allow-Methods", "*");


        Authorization authorization = FileAuthenticationProvider.cachedUserMapping.getAuthorization(USERNAME);
        GuacamoleConfiguration configuration =authorization.getConfiguration(configKey);
        if (configuration==null){
            configuration=new GuacamoleConfiguration();
            configuration.setParameter("font-name", "宋体");
            configuration.setParameter("font-size", "14");
            //协议
            if ("ssh".equalsIgnoreCase(protocol)) {
                configuration.setProtocol("ssh");
                configuration.setParameter("hostname", hostname);
                configuration.setParameter("port", port);
                configuration.setParameter("enable-sftp", "true");
                configuration.setParameter("sftp-hostname", hostname);
                configuration.setParameter("sftp-root-directory", "/");
            } else if ("telnet".equalsIgnoreCase(protocol)) {
                configuration.setProtocol("telnet");
                configuration.setParameter("hostname", hostname);
                configuration.setParameter("port", port);
            }
            authorization.addConfiguration(configKey, configuration);
        }
        Connection connection = new SimpleConnection(configKey, configKey, configuration, false);
        connection.setParentIdentifier(SimpleUserContext.DEFAULT_ROOT_CONNECTION_GROUP);
        if (SimpleUserContext.connectionDirectory==null){
            Map<String, Connection> connections = new ConcurrentHashMap<String, Connection>(1);
            connections.put(configKey,connection);
            SimpleUserContext.connectionDirectory=new SimpleDirectory<>(connections);
        }
        if (SimpleUserContext.connectionDirectory.get(configKey)==null){
            ((SimpleDirectory)SimpleUserContext.connectionDirectory).add(connection,configKey);
        }
        return "true";

    }


    /**
     * 初始化 用户缓存
     */
    private void init() {
        if (FileAuthenticationProvider.cachedUserMapping == null) {
            FileAuthenticationProvider.cachedUserMapping = new UserMapping();
        }

        if (FileAuthenticationProvider.cachedUserMapping.getAuthorization(USERNAME) == null) {
            Authorization authorization = new Authorization();
            authorization.setUsername(USERNAME);
            authorization.setPassword(PASSWORD);
            FileAuthenticationProvider.cachedUserMapping.addAuthorization(authorization);
        }
    }
}
