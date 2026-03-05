import tokenManager from '../src/auth/token_manager.js';
import { sendLog } from '../src/api/client.js';
import { readFileSync } from 'fs';
import { randomUUID } from 'crypto';

async function testSendLog() {
  try {
    // 获取token
    const token = await tokenManager.getToken();
    if (!token) {
      console.error('无可用token');
      return;
    }
    console.log('获取token成功');

    // 读取data.bin文件
    const buffer = readFileSync('data-reserialized.bin');
    console.log(`读取data.bin成功，大小: ${buffer.length} 字节`);

    // 生成随机参数
    const num = Math.floor(Math.random() * 100);
    const trajectoryId = randomUUID();

    // 调用sendLog
    await sendLog(token, num, trajectoryId, buffer);
    console.log('sendLog调用成功');
  } catch (error) {
    console.error('测试失败:', error.message);
  }
}

testSendLog();
