import fs from 'fs';
import path from 'path';
import { log } from '../utils/logger.js';
import { getDataDir } from '../utils/paths.js';
import { getGroupKey, MODEL_GROUPS } from '../utils/modelGroups.js';

/**
 * Token 模型系列冷却管理器
 * 当某个 token 的某个模型系列额度耗尽且恢复时间很长时，暂时禁用该 token 对该模型系列的访问
 *
 * 数据结构：
 * {
 *   "meta": { "version": 1 },
 *   "cooldowns": {
 *     "tokenId1": {
 *       "claude": { "until": 1737500000000 },
 *       "gemini": null,
 *       "banana": { "until": 1737600000000 }
 *     }
 *   }
 * }
 */

class TokenCooldownManager {
  constructor(filePath = path.join(getDataDir(), 'token_cooldowns.json')) {
    this.filePath = filePath;
    /** @type {Map<string, Object>} tokenId -> { groupKey: { until: timestamp } } */
    this.cooldowns = new Map();
    this.ensureFileExists();
    this.loadFromFile();
  }

  ensureFileExists() {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    if (!fs.existsSync(this.filePath)) {
      const initialData = {
        meta: { version: 1 },
        cooldowns: {}
      };
      fs.writeFileSync(this.filePath, JSON.stringify(initialData, null, 2), 'utf8');
    }
  }

  loadFromFile() {
    try {
      const data = fs.readFileSync(this.filePath, 'utf8');
      const parsed = JSON.parse(data);
      const cooldowns = parsed.cooldowns || {};

      Object.entries(cooldowns).forEach(([tokenId, groups]) => {
        if (groups && typeof groups === 'object') {
          this.cooldowns.set(tokenId, groups);
        }
      });

      // 启动时清理过期的冷却状态
      this._cleanupExpired();
    } catch (error) {
      log.error('[CooldownManager] 加载冷却状态文件失败:', error.message);
    }
  }

  saveToFile() {
    try {
      const cooldownsObj = {};
      this.cooldowns.forEach((groups, tokenId) => {
        // 只保存有实际冷却的条目
        const validGroups = {};
        let hasValid = false;
        for (const [group, data] of Object.entries(groups)) {
          if (data && data.until && data.until > Date.now()) {
            validGroups[group] = data;
            hasValid = true;
          }
        }
        if (hasValid) {
          cooldownsObj[tokenId] = validGroups;
        }
      });

      const data = {
        meta: { version: 1 },
        cooldowns: cooldownsObj
      };
      fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
      log.error('[CooldownManager] 保存冷却状态文件失败:', error.message);
    }
  }

  /**
   * 清理过期的冷却状态
   * @private
   */
  _cleanupExpired() {
    const now = Date.now();
    let cleaned = 0;

    this.cooldowns.forEach((groups, tokenId) => {
      for (const [group, data] of Object.entries(groups)) {
        if (data && data.until && data.until <= now) {
          groups[group] = null;
          cleaned++;
        }
      }
    });

    if (cleaned > 0) {
      log.info(`[CooldownManager] 清理了 ${cleaned} 个过期的冷却状态`);
      this.saveToFile();
    }
  }

  /**
   * 禁用指定 token 的指定模型系列，直到指定时间
   * @param {string} tokenId - Token ID
   * @param {string} modelId - 模型 ID（用于确定模型系列）
   * @param {number} untilTimestamp - 禁用截止时间戳（毫秒）
   */
  setCooldown(tokenId, modelId, untilTimestamp) {
    if (!tokenId || !untilTimestamp) return;

    const groupKey = getGroupKey(modelId);
    let groups = this.cooldowns.get(tokenId);

    if (!groups) {
      groups = {};
      this.cooldowns.set(tokenId, groups);
    }

    // 幂等检查：如果已经存在相同或更晚的冷却时间，跳过重复设置
    const existing = groups[groupKey];
    if (existing && existing.until && existing.until >= untilTimestamp) {
      return; // 已有更严格的冷却，无需重复设置
    }

    groups[groupKey] = { until: untilTimestamp };

    const resetDate = new Date(untilTimestamp);
    log.warn(`[CooldownManager] Token ${tokenId} 的 ${groupKey} 系列已禁用，将在 ${resetDate.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })} 恢复`);

    this.saveToFile();
  }

  /**
   * 检查指定 token 对指定模型是否可用（未在冷却中）
   * @param {string} tokenId - Token ID
   * @param {string} modelId - 模型 ID
   * @returns {boolean} true = 可用，false = 在冷却中
   */
  isAvailable(tokenId, modelId) {
    if (!tokenId) return true;

    const groups = this.cooldowns.get(tokenId);
    if (!groups) return true;

    const groupKey = getGroupKey(modelId);
    const cooldown = groups[groupKey];

    if (!cooldown || !cooldown.until) return true;

    const now = Date.now();
    if (cooldown.until <= now) {
      // 冷却已过期，清除状态
      groups[groupKey] = null;
      this.saveToFile();
      log.info(`[CooldownManager] Token ${tokenId} 的 ${groupKey} 系列冷却已结束`);
      return true;
    }

    return false;
  }

  /**
   * 获取指定 token 对指定模型的冷却结束时间
   * @param {string} tokenId - Token ID
   * @param {string} modelId - 模型 ID
   * @returns {number|null} 冷却结束时间戳，如果未在冷却中返回 null
   */
  getCooldownUntil(tokenId, modelId) {
    if (!tokenId) return null;

    const groups = this.cooldowns.get(tokenId);
    if (!groups) return null;

    const groupKey = getGroupKey(modelId);
    const cooldown = groups[groupKey];

    if (!cooldown || !cooldown.until) return null;

    const now = Date.now();
    if (cooldown.until <= now) {
      return null;
    }

    return cooldown.until;
  }

  /**
   * 清除指定 token 的指定模型系列的冷却状态
   * @param {string} tokenId - Token ID
   * @param {string} modelId - 模型 ID
   */
  clearCooldown(tokenId, modelId) {
    if (!tokenId) return;

    const groups = this.cooldowns.get(tokenId);
    if (!groups) return;

    const groupKey = getGroupKey(modelId);
    if (groups[groupKey]) {
      groups[groupKey] = null;
      log.info(`[CooldownManager] 已清除 Token ${tokenId} 的 ${groupKey} 系列冷却状态`);
      this.saveToFile();
    }
  }

  /**
   * 清除指定 token 的所有冷却状态
   * @param {string} tokenId - Token ID
   */
  clearAllCooldowns(tokenId) {
    if (!tokenId) return;

    if (this.cooldowns.has(tokenId)) {
      this.cooldowns.delete(tokenId);
      log.info(`[CooldownManager] 已清除 Token ${tokenId} 的所有冷却状态`);
      this.saveToFile();
    }
  }

  /**
   * 获取所有冷却状态（用于管理界面显示）
   * @returns {Object} 所有冷却状态
   */
  getAllCooldowns() {
    const result = {};
    const now = Date.now();

    this.cooldowns.forEach((groups, tokenId) => {
      const validGroups = {};
      for (const [group, data] of Object.entries(groups)) {
        if (data && data.until && data.until > now) {
          validGroups[group] = {
            until: data.until,
            untilFormatted: new Date(data.until).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
          };
        }
      }
      if (Object.keys(validGroups).length > 0) {
        result[tokenId] = validGroups;
      }
    });

    return result;
  }
}

const tokenCooldownManager = new TokenCooldownManager();
export default tokenCooldownManager;
