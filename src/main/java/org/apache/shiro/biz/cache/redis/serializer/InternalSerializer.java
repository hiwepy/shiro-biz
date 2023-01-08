/*
 * Copyright (c) 2018 (https://github.com/hiwepy).
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
package org.apache.shiro.biz.cache.redis.serializer;

import org.apache.commons.lang3.SerializationUtils;
import org.crazycake.shiro.exception.SerializationException;
import org.crazycake.shiro.serializer.RedisSerializer;

import java.io.Serializable;

public class InternalSerializer<T> implements RedisSerializer<T> {
	
	@Override
	public byte[] serialize(T source) throws SerializationException {
		return SerializationUtils.serialize((Serializable) source);
	}

	@Override
	public T deserialize(byte[] bytes) throws SerializationException {
		return SerializationUtils.deserialize(bytes);
	}

}
