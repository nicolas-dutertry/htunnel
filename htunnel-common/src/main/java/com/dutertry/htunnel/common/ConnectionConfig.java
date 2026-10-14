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
package com.dutertry.htunnel.common;

import java.util.Objects;

/**
 * @author Nicolas Dutertry
 *
 */
public class ConnectionConfig {
    
    private String host;
    
    private int port;
    
    private int bufferSize;
    
    private boolean base64Encoding;

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public int getBufferSize() {
        return bufferSize;
    }

    public void setBufferSize(int bufferSize) {
        this.bufferSize = bufferSize;
    }

    public boolean isBase64Encoding() {
        return base64Encoding;
    }

    public void setBase64Encoding(boolean base64Encoding) {
        this.base64Encoding = base64Encoding;
    }

    @Override
    public int hashCode() {
        return Objects.hash(host, port, bufferSize, base64Encoding);
    }

    @Override
    public boolean equals(Object obj) {
        if(this == obj) {
            return true;
        }
        if(!(obj instanceof ConnectionConfig)) {
            return false;
        }
        ConnectionConfig other = (ConnectionConfig) obj;
        return port == other.port
                && bufferSize == other.bufferSize
                && base64Encoding == other.base64Encoding
                && Objects.equals(host, other.host);
    }

    @Override
    public String toString() {
        return "ConnectionConfig(host=" + host + ", port=" + port + ", bufferSize=" + bufferSize
                + ", base64Encoding=" + base64Encoding + ")";
    }
}
