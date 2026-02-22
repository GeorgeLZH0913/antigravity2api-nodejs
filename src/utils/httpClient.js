import axios from 'axios';
import dns from 'dns';
import http from 'http';
import https from 'https';
import net from 'net';
import tls from 'tls';
import { Readable } from 'stream';
import config from '../config/config.js';

// ==================== DNS 与代理统一配置 ====================

// 自定义 DNS 解析：优先 IPv4，失败后回退 IPv6
function customLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, family: 4 }, (err4, address4, family4) => {
    if (!err4 && address4) {
      return callback(null, address4, family4);
    }
    dns.lookup(hostname, { ...options, family: 6 }, (err6, address6, family6) => {
      if (!err6 && address6) {
        return callback(null, address6, family6);
      }
      callback(err4 || err6);
    });
  });
}

function isSocksProxy(proxyUrl) {
  if (!proxyUrl) return false;
  return /^socks5h?:\/\//i.test(proxyUrl) || /^socks:\/\//i.test(proxyUrl);
}

function parseProxyUrl(proxyUrl) {
  try {
    const parsed = new URL(proxyUrl);
    return {
      protocol: parsed.protocol.replace(':', '').toLowerCase(),
      hostname: parsed.hostname,
      port: Number(parsed.port || 1080),
      username: parsed.username ? decodeURIComponent(parsed.username) : '',
      password: parsed.password ? decodeURIComponent(parsed.password) : ''
    };
  } catch {
    return null;
  }
}

function readExactly(socket, size, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let total = 0;
    let timer = null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('end', onEnd);
      socket.off('close', onClose);
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onEnd = () => {
      cleanup();
      reject(new Error('SOCKS5 连接被远端关闭'));
    };

    const onClose = () => {
      cleanup();
      reject(new Error('SOCKS5 连接已关闭'));
    };

    const onData = (chunk) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total < size) return;

      const buffer = Buffer.concat(chunks, total);
      const exact = buffer.subarray(0, size);
      const remain = buffer.subarray(size);
      if (remain.length > 0) {
        socket.unshift(remain);
      }
      cleanup();
      resolve(exact);
    };

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        cleanup();
        reject(new Error('SOCKS5 握手超时'));
      }, timeoutMs);
    }

    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('end', onEnd);
    socket.once('close', onClose);
  });
}

async function performSocks5Handshake(socket, targetHost, targetPort, proxyAuth, timeoutMs = 10000) {
  const methods = [0x00];
  const hasAuth = Boolean(proxyAuth.username || proxyAuth.password);
  if (hasAuth) methods.push(0x02);

  socket.write(Buffer.from([0x05, methods.length, ...methods]));

  const methodResp = await readExactly(socket, 2, timeoutMs);
  if (methodResp[0] !== 0x05) {
    throw new Error('SOCKS5 协议版本不匹配');
  }
  if (methodResp[1] === 0xff) {
    throw new Error('SOCKS5 代理不支持当前认证方式');
  }

  if (methodResp[1] === 0x02) {
    const username = Buffer.from(proxyAuth.username || '', 'utf8');
    const password = Buffer.from(proxyAuth.password || '', 'utf8');
    if (username.length > 255 || password.length > 255) {
      throw new Error('SOCKS5 用户名或密码长度超过 255 字节');
    }

    socket.write(Buffer.concat([
      Buffer.from([0x01, username.length]),
      username,
      Buffer.from([password.length]),
      password
    ]));

    const authResp = await readExactly(socket, 2, timeoutMs);
    if (authResp[1] !== 0x00) {
      throw new Error('SOCKS5 用户名密码认证失败');
    }
  }

  const host = targetHost || '';
  const hostType = net.isIP(host);
  let atyp = 0x03;
  let addrBuf = null;

  if (hostType === 4) {
    atyp = 0x01;
    addrBuf = Buffer.from(host.split('.').map((v) => Number(v)));
  } else if (hostType === 6) {
    const [leftRaw, rightRaw] = host.split('::');
    const left = leftRaw ? leftRaw.split(':').filter(Boolean) : [];
    const right = rightRaw ? rightRaw.split(':').filter(Boolean) : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 0) {
      throw new Error(`SOCKS5 IPv6 地址非法: ${host}`);
    }
    const parts = [...left, ...Array(missing).fill('0'), ...right];
    if (parts.length !== 8) {
      throw new Error(`SOCKS5 IPv6 地址非法: ${host}`);
    }

    atyp = 0x04;
    addrBuf = Buffer.from(parts.flatMap((part) => {
      const num = parseInt(part || '0', 16);
      if (!Number.isFinite(num) || num < 0 || num > 0xffff) {
        throw new Error(`SOCKS5 IPv6 地址非法: ${host}`);
      }
      return [(num >> 8) & 0xff, num & 0xff];
    }));
  } else {
    const hostBytes = Buffer.from(host, 'utf8');
    if (hostBytes.length > 255) {
      throw new Error('SOCKS5 目标域名长度超过 255 字节');
    }
    addrBuf = Buffer.concat([Buffer.from([hostBytes.length]), hostBytes]);
  }

  const port = Number(targetPort);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`SOCKS5 目标端口非法: ${targetPort}`);
  }

  const reqHead = Buffer.from([0x05, 0x01, 0x00, atyp]);
  const portBuf = Buffer.from([(port >> 8) & 0xff, port & 0xff]);
  socket.write(Buffer.concat([reqHead, addrBuf, portBuf]));

  const respHead = await readExactly(socket, 4, timeoutMs);
  if (respHead[0] !== 0x05) {
    throw new Error('SOCKS5 CONNECT 响应版本异常');
  }
  if (respHead[1] !== 0x00) {
    const errMap = {
      0x01: '一般性 SOCKS 服务器故障',
      0x02: '连接被规则集禁止',
      0x03: '网络不可达',
      0x04: '主机不可达',
      0x05: '连接被拒绝',
      0x06: 'TTL 超时',
      0x07: '命令不支持',
      0x08: '地址类型不支持'
    };
    throw new Error(`SOCKS5 CONNECT 失败: ${errMap[respHead[1]] || `错误码 ${respHead[1]}`}`);
  }

  let remainLen = 0;
  if (respHead[3] === 0x01) remainLen = 4 + 2;
  else if (respHead[3] === 0x04) remainLen = 16 + 2;
  else if (respHead[3] === 0x03) {
    const len = await readExactly(socket, 1, timeoutMs);
    remainLen = len[0] + 2;
  } else {
    throw new Error('SOCKS5 CONNECT 响应地址类型异常');
  }

  if (remainLen > 0) {
    await readExactly(socket, remainLen, timeoutMs);
  }
}

function createSocksAgents(proxyUrl) {
  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed || !/^socks5h?$|^socks$/i.test(parsed.protocol)) {
    return null;
  }

  const connectViaSocks = ({ options, isTls }, callback) => {
    const targetHost = options.hostname || options.host;
    const targetPort = Number(options.port || (isTls ? 443 : 80));

    const proxySocket = net.connect({
      host: parsed.hostname,
      port: parsed.port,
      lookup: customLookup
    });

    let callbackCalled = false;
    const done = (err, socket) => {
      if (callbackCalled) return;
      callbackCalled = true;
      callback(err, socket);
    };

    const onSocketError = (err) => {
      done(err);
    };

    proxySocket.once('error', onSocketError);
    proxySocket.once('connect', async () => {
      try {
        await performSocks5Handshake(
          proxySocket,
          targetHost,
          targetPort,
          { username: parsed.username, password: parsed.password },
          10000
        );

        proxySocket.off('error', onSocketError);
        if (!isTls) {
          done(null, proxySocket);
          return;
        }

        const tlsSocket = tls.connect({
          socket: proxySocket,
          servername: options.servername || targetHost
        });
        tlsSocket.once('secureConnect', () => done(null, tlsSocket));
        tlsSocket.once('error', done);
      } catch (err) {
        proxySocket.destroy();
        done(err);
      }
    });
  };

  return {
    httpAgent: new http.Agent({
      keepAlive: true,
      createConnection: (options, callback) => connectViaSocks({ options, isTls: false }, callback)
    }),
    httpsAgent: new https.Agent({
      keepAlive: true,
      createConnection: (options, callback) => connectViaSocks({ options, isTls: true }, callback)
    })
  };
}

const socksAgents = isSocksProxy(config.proxy) ? createSocksAgents(config.proxy) : null;

const httpAgent = socksAgents?.httpAgent || new http.Agent({
  lookup: customLookup,
  keepAlive: true
});

const httpsAgent = socksAgents?.httpsAgent || new https.Agent({
  lookup: customLookup,
  keepAlive: true
});

function buildProxyConfig() {
  if (!config.proxy) return false;
  try {
    const proxyUrl = new URL(config.proxy);
    const protocol = proxyUrl.protocol.replace(':', '').toLowerCase();

    if (protocol.startsWith('socks')) {
      // SOCKS 由自定义 Agent 处理，axios 内置 proxy 不支持
      return false;
    }

    return {
      protocol,
      host: proxyUrl.hostname,
      port: parseInt(proxyUrl.port, 10)
    };
  } catch {
    return false;
  }
}

function createChunkedStream(data) {
  const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
  return Readable.from([jsonStr]);
}

export function buildAxiosRequestConfig({
  method = 'POST',
  url,
  headers,
  data = null,
  timeout = config.timeout,
  responseType,
  useChunked = false
}) {
  const axiosConfig = {
    method,
    url,
    headers: { ...headers },
    timeout,
    httpAgent,
    httpsAgent,
    proxy: buildProxyConfig(),
    // 禁用自动设置 Content-Length，让 axios 使用 Transfer-Encoding: chunked
    maxContentLength: Infinity,
    maxBodyLength: Infinity
  };

  if (responseType) axiosConfig.responseType = responseType;

  if (data !== null) {
    if (useChunked) {
      axiosConfig.data = createChunkedStream(data);
      delete axiosConfig.headers['Content-Length'];
    } else {
      axiosConfig.data = data;
    }
  }
  return axiosConfig;
}

export async function httpRequest(configOverrides) {
  const axiosConfig = buildAxiosRequestConfig({ ...configOverrides, useChunked: true });
  return axios(axiosConfig);
}

export async function httpStreamRequest(configOverrides) {
  const axiosConfig = buildAxiosRequestConfig({ ...configOverrides, useChunked: true });
  axiosConfig.responseType = 'stream';
  return axios(axiosConfig);
}