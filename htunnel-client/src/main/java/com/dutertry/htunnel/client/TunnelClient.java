/*
 * htunnel - A simple HTTP tunnel 
 * https://github.com/nicolas-dutertry/htunnel
 * 
 * Written by Nicolas Dutertry.
 * 
 * This file is provided under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
package com.dutertry.htunnel.client;

import static com.dutertry.htunnel.common.Constants.HEADER_CONNECTION_ID;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.dutertry.htunnel.common.Constants;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dutertry.htunnel.common.ConnectionConfig;
import com.dutertry.htunnel.common.ConnectionRequest;
import com.dutertry.htunnel.common.crypto.CryptoUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import sun.security.ssl.SSLSocketFactoryImpl;

import javax.net.ssl.*;

/**
 * @author Nicolas Dutertry
 *
 */
public class TunnelClient implements Runnable {
    private static final Logger LOGGER = LoggerFactory.getLogger(TunnelClient.class);
    
    private final SocketChannel socketChannel;
    private final String host;
    private final int port;
    private final String tunnel;
    private final String proxy;
    private final int bufferSize;
    private final boolean base64Encoding;
    private final PrivateKey privateKey;

    private final String publicKeyDigest;
    
    private String connectionId;
    
    public TunnelClient(SocketChannel socketChannel, String host, int port, String tunnel, String proxy, int bufferSize,
                        boolean base64Encoding, PrivateKey privateKey, String publicKeyDigest) {
        this.socketChannel = socketChannel;
        this.host = host;
        this.port = port;
        this.tunnel = tunnel;
        this.proxy = proxy;
        this.bufferSize = bufferSize;
        this.base64Encoding = base64Encoding;
        this.privateKey = privateKey;
        this.publicKeyDigest = publicKeyDigest;
    }
    
    public CloseableHttpClient createHttpCLient() throws URISyntaxException, NoSuchAlgorithmException,
            KeyStoreException, KeyManagementException {
        HttpClientBuilder builder = HttpClients.custom();
        if(StringUtils.isNotBlank(proxy)) {
            URI proxyUri = new URI(proxy);
            
            HttpHost proxy = new HttpHost(proxyUri.getHost(), proxyUri.getPort(), proxyUri.getScheme());
            DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);
            builder.setRoutePlanner(routePlanner);

            // Proxy authentication
            String userInfo = proxyUri.getUserInfo();
            if(StringUtils.isNotBlank(userInfo)) {
                String user = StringUtils.substringBefore(userInfo, ":");
                String password = StringUtils.substringAfter(userInfo, ":");
                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                    new AuthScope(proxyUri.getHost(), proxyUri.getPort()), 
                    new UsernamePasswordCredentials(user, password));
                builder.setDefaultCredentialsProvider(credentialsProvider);
            }
        }
        SSLContext sslContext =
                SSLContextBuilder.create().loadTrustMaterial(new TrustAllStrategy()).build();
        HostnameVerifier allowAllHosts = new NoopHostnameVerifier();
        SSLConnectionSocketFactory connectionFactory = new SSLConnectionSocketFactory(
                sslContext, allowAllHosts);
        builder.setSSLSocketFactory(connectionFactory);
        return  builder.build();
    }

    @Override
    public void run() {
        LOGGER.info("Connecting to tunnel {}", tunnel);
        try(CloseableHttpClient httpclient = createHttpCLient()) {
            // Hello
            URIBuilder helloBuilder = new URIBuilder(tunnel);
            List<String> pathList = new ArrayList<>(helloBuilder.getPathSegments());
            pathList.add("hello");
            URI helloUri = helloBuilder
                    .setPathSegments(pathList)
                    .build();
            LOGGER.info("url: {}", helloUri.toString());
            String helloResult;
            try(CloseableHttpResponse response = httpclient.execute(new HttpGet(helloUri))) {
                if(response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.error("Error while connecting tunnel: {}", response.getStatusLine());
                    return;
                }
                helloResult = EntityUtils.toString(response.getEntity());
            }
            
            // Connect
            URIBuilder connectBuilder = new URIBuilder(tunnel);
            pathList = new ArrayList<>(connectBuilder.getPathSegments());
            pathList.add("begin");
            URI connectUri = connectBuilder
                    .setPathSegments(pathList)
                    .build();
            
            ConnectionConfig connectionConfig = new ConnectionConfig();
            connectionConfig.setHost(host);
            connectionConfig.setPort(port);
            connectionConfig.setBufferSize(bufferSize);
            connectionConfig.setBase64Encoding(base64Encoding);
            
            ConnectionRequest connectionRequest = new ConnectionRequest();
            connectionRequest.setHelloResult(helloResult);
            connectionRequest.setConnectionConfig(connectionConfig);            
            
            ObjectMapper mapper = new ObjectMapper();
            byte[] connectionRequestBytes = mapper.writeValueAsBytes(connectionRequest);
            byte[] sendBytes = connectionRequestBytes;
            if(privateKey != null) {
                sendBytes = CryptoUtils.encryptRSA(connectionRequestBytes, privateKey);
            }
            
            HttpPost httppost = new HttpPost(connectUri);
            if (StringUtils.isNotBlank(publicKeyDigest)) {
                httppost.addHeader(Constants.HEADER_CLIENT_ID, publicKeyDigest);
            }
            httppost.setEntity(new ByteArrayEntity(sendBytes));
            
            try(CloseableHttpResponse response = httpclient.execute(httppost)) {
                if(response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.error("Error while connecting tunnel: {}", response.getStatusLine());
                    return;
                }
                connectionId = EntityUtils.toString(response.getEntity());
            }
            
            LOGGER.info("Connection established with id {}", connectionId);
        } catch(Exception e) {
            LOGGER.error("Error while connecting to tunnel", e);
            return;
        } finally {
            if(connectionId == null) {
                try {
                    socketChannel.close();
                } catch (IOException e) {
                }
            }
        }
            
        Thread writeThread = new Thread(this::writeLoop);
        writeThread.setDaemon(true);
        writeThread.start();
        
        readLoop();
    }
    
    private void readLoop() {
        try(CloseableHttpClient httpclient = createHttpCLient()) {
            URIBuilder readBuilder = new URIBuilder(tunnel);
            List<String> pathList = new ArrayList<>(readBuilder.getPathSegments());
            pathList.add("download");
            URI readUri = readBuilder
                    .setPathSegments(pathList)
                    .build();
            while(!Thread.currentThread().isInterrupted()) {
                HttpGet httpget = new HttpGet(readUri);
                httpget.addHeader(HEADER_CONNECTION_ID, connectionId);
                try(CloseableHttpResponse response = httpclient.execute(httpget)) {
                    int status = response.getStatusLine().getStatusCode();
                    if(status == HttpStatus.SC_GONE) {
                        LOGGER.info("Connection closed by server");
                        break;
                    }
                    
                    if(status != HttpStatus.SC_OK) {
                        LOGGER.error("Error while reading: {}", response.getStatusLine());
                        break;
                    }
                    
                    byte[] bytes = EntityUtils.toByteArray(response.getEntity());
                    if(bytes.length > 0) {
                        if(base64Encoding) {
                            bytes = Base64.getDecoder().decode(bytes);
                        }
                        
                        LOGGER.debug("{} byte(s) received", bytes.length); 
                        
                        ByteBuffer bb = ByteBuffer.wrap(bytes);
                        while(bb.hasRemaining()) {
                            socketChannel.write(bb);
                        }
                    }
                }
            }
        } catch(Exception e) {
            LOGGER.error("Error in read loop", e);
        }
        
        try {
            socketChannel.close();
        } catch (IOException e) {
        }
        LOGGER.info("Read loop terminated for {}", connectionId);
    }
    
    private void writeLoop() {
        try(CloseableHttpClient httpclient = createHttpCLient()) {
            
            ByteBuffer bb = ByteBuffer.allocate(bufferSize);
            
            while(!Thread.currentThread().isInterrupted()) {
                int read = socketChannel.read(bb);
                
                if(!bb.hasRemaining() || read <= 0) {
                    if(bb.position() > 0) {
                        URIBuilder writeBuilder = new URIBuilder(tunnel);
                        List<String> pathList = new ArrayList<>(writeBuilder.getPathSegments());
                        pathList.add("upload");
                        URI writeUri = writeBuilder
                                .setPathSegments(pathList)
                                .build();
                        
                        HttpPost httppost = new HttpPost(writeUri);
                        httppost.addHeader(HEADER_CONNECTION_ID, connectionId);
                        
                        bb.flip();
                        
                        LOGGER.debug("{} byte(s) to send", bb.limit());
                        
                        if(base64Encoding) {
                            ByteBuffer encodedBuffer = Base64.getEncoder().encode(bb);
                            String body = StandardCharsets.UTF_8.decode(encodedBuffer).toString();
                            httppost.setEntity(new StringEntity(body, "UTF-8"));
                        } else {
                            httppost.setEntity(new ByteArrayEntity(bb.array(), 0, bb.limit()));
                        }
                        
                        bb.clear();
                        
                        try(CloseableHttpResponse response = httpclient.execute(httppost)) {
                            if(response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                                LOGGER.error("Error while writing: {}", response.getStatusLine());
                                return;
                            }
                            
                            EntityUtils.consume(response.getEntity());
                        }
                    }
                }
                
                if(read == -1) {                    
                    break;
                }
            }
            
        } catch(Exception e) {
            LOGGER.error("Error in write loop", e);
        }
        
        try(CloseableHttpClient httpclient = createHttpCLient()) {
            URI closeUri = new URIBuilder(tunnel)
                    .setPath("/finish")
                    .build();
            
            HttpGet httpget = new HttpGet(closeUri);
            httpget.addHeader(HEADER_CONNECTION_ID, connectionId);
            try(CloseableHttpResponse response = httpclient.execute(httpget)) {
                EntityUtils.consume(response.getEntity());
            }
        } catch(Exception e) {
            LOGGER.error("Error while closing connection", e);
        }
        
        try {
            socketChannel.close();
        } catch (IOException e) {
        }
        
        LOGGER.info("Write loop terminated for {}", connectionId);
        
    }

}
