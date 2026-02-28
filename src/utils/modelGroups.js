/**
 * 模型分组工具模块
 * 统一管理模型到组的映射逻辑，供 quota_manager 和 token_cooldown_manager 共用
 */

/**
 * 支持的模型组列表
 * - claude: Claude 系列模型
 * - gemini: Gemini 系列模型
 * - banana: gemini-3.1-flash-image 图片生成模型
 * - other: 其他模型
 */
export const MODEL_GROUPS = ['claude', 'gemini', 'banana', 'other'];

/**
 * 获取模型所属的组 key
 * @param {string} modelId - 模型 ID
 * @returns {string} 组 key (claude | gemini | banana | other)
 */
export function getGroupKey(modelId) {
  if (!modelId) return 'other';
  const lower = modelId.toLowerCase();

  if (lower.includes('claude')) return 'claude';
  // banana 必须在 gemini 之前检查，因为它包含 'gemini' 字符串
  if (lower.includes('gemini-3.1-flash-image')) return 'banana';
  if (lower.includes('gemini') || lower.includes('publishers/google/')) return 'gemini';

  return 'other';
}
