/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.biz.session;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;

/**
 * 
 * @className	： MySessionListener1
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月12日 下午11:28:11
 * @version 	V1.0
 */
public class MySessionListener1 implements SessionListener {
    @Override
    public void onStart(Session session) {//会话创建时触发
        System.out.println("会话创建：" + session.getId());
    }
    @Override
    public void onExpiration(Session session) {//会话过期时触发
        System.out.println("会话过期：" + session.getId());
    }
    @Override
    public void onStop(Session session) {//退出/会话过期时触发
        System.out.println("会话停止：" + session.getId());
    }  
}

