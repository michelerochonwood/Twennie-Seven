// utils/unitTopicVisibility.js

const topicAccessMap =
  require('../config/topicAccessMap');

/**
 * Extract topic names from a unit.
 *
 * Current Twennie unit records primarily use:
 * - main_topic
 * - secondary_topics
 *
 * Some older or future records may use other field names,
 * so those are supported as fallbacks.
 */
function getUnitTopicNames(unit = {}) {
  const topicNames = [];

  function addTopic(value) {
    if (!value) return;

    if (typeof value === 'string') {
      const trimmed = value.trim();

      if (trimmed) {
        topicNames.push(trimmed);
      }

      return;
    }

    if (Array.isArray(value)) {
      value.forEach(addTopic);
      return;
    }

    if (typeof value === 'object') {
      if (typeof value.name === 'string') {
        addTopic(value.name);
        return;
      }

      if (typeof value.title === 'string') {
        addTopic(value.title);
        return;
      }

      Object.values(value).forEach(addTopic);
    }
  }

  // Current Twennie fields
  addTopic(unit.main_topic);
  addTopic(unit.secondary_topics);

  // Fallback fields for older or differing schemas
  addTopic(unit.topic);
  addTopic(unit.topicName);
  addTopic(unit.primaryTopic);
  addTopic(unit.secondaryTopic);
  addTopic(unit.topics);

  return [
    ...new Set(topicNames)
  ];
}

/**
 * Determine whether a unit should appear for the organization.
 *
 * Temporary fail-open rules:
 * - no recognized topic = visible
 * - unmapped topic = visible
 * - multi-topic unit remains visible when at least one mapped
 *   topic belongs to an enabled category
 * - unit is hidden only when all mapped topics belong to
 *   disabled categories
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
        .map(topicName =>
          topicAccessMap[topicName]
        )
        .filter(Boolean)
    )
  ];

  if (accessKeys.length === 0) {
    return true;
  }

  return accessKeys.some(
    accessKey =>
      topicVisibility[accessKey] !== false
  );
}

module.exports = {
  getUnitTopicNames,
  isUnitVisibleByTopic
};