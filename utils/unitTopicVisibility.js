// utils/unitTopicVisibility.js

const topicAccessMap =
  require('../config/topicAccessMap');

/**
 * Extract topic names from a unit.
 *
 * This supports several possible field shapes until the
 * unit schemas are reviewed and standardized.
 */
function getUnitTopicNames(unit = {}) {
  const topics = [];

  const possibleValues = [
    unit.topic,
    unit.topicName,
    unit.primaryTopic,
    unit.secondaryTopic,
    unit.topics
  ];

  for (const value of possibleValues) {
    if (!value) continue;

    if (typeof value === 'string') {
      topics.push(value);
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string') {
          topics.push(item);
        } else if (item?.name) {
          topics.push(item.name);
        } else if (item?.title) {
          topics.push(item.title);
        }
      }

      continue;
    }

    if (typeof value === 'object') {
      for (const item of Object.values(value)) {
        if (typeof item === 'string') {
          topics.push(item);
        }
      }
    }
  }

  return [...new Set(
    topics
      .map(topic => topic.trim())
      .filter(Boolean)
  )];
}

/**
 * Temporary fail-open rule:
 *
 * - Units with no recognized mapped topics remain visible.
 * - A unit is hidden only when all recognized topic categories
 *   attached to it are disabled.
 * - If at least one recognized topic category is enabled,
 *   the unit remains visible.
 */
function isUnitVisibleByTopic(
  unit,
  topicVisibility = {}
) {
  const topicNames =
    getUnitTopicNames(unit);

  const accessKeys = [
    ...new Set(
      topicNames
        .map(topicName => topicAccessMap[topicName])
        .filter(Boolean)
    )
  ];

  if (accessKeys.length === 0) {
    return true;
  }

  return accessKeys.some(
    key => topicVisibility[key] !== false
  );
}

module.exports = {
  getUnitTopicNames,
  isUnitVisibleByTopic
};