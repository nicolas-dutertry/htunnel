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
public class ConnectionRequest {
    private String helloResult;
    
    private ConnectionConfig connectionConfig;

    public String getHelloResult() {
        return helloResult;
    }

    public void setHelloResult(String helloResult) {
        this.helloResult = helloResult;
    }

    public ConnectionConfig getConnectionConfig() {
        return connectionConfig;
    }

    public void setConnectionConfig(ConnectionConfig connectionConfig) {
        this.connectionConfig = connectionConfig;
    }

    @Override
    public int hashCode() {
        return Objects.hash(helloResult, connectionConfig);
    }

    @Override
    public boolean equals(Object obj) {
        if(this == obj) {
            return true;
        }
        if(!(obj instanceof ConnectionRequest)) {
            return false;
        }
        ConnectionRequest other = (ConnectionRequest) obj;
        return Objects.equals(helloResult, other.helloResult)
                && Objects.equals(connectionConfig, other.connectionConfig);
    }

    @Override
    public String toString() {
        return "ConnectionRequest(helloResult=" + helloResult + ", connectionConfig=" + connectionConfig + ")";
    }
}
