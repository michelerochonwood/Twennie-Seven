// utils/validateGroupMember.js
module.exports.validateGroupMemberData = (data) => {
  const errors = [];

  const isBlank = (v) => !v || String(v).trim() === "";

  // Required basics
  if (isBlank(data.groupId)) {
    errors.push("Group ID is required.");
  }
  if (isBlank(data.groupName)) {
    errors.push("Group name is required.");
  }
  if (isBlank(data.name)) {
    errors.push("Member name is required.");
  }

  // Email
  if (isBlank(data.email)) {
    errors.push("Email is required.");
  } else if (!/^\S+@\S+\.\S+$/.test(String(data.email))) {
    errors.push("Please enter a valid email address.");
  }

  // Username (optional; only if provided)
  if (data.username !== undefined) {
    const u = String(data.username).trim();
    if (u.length > 0 && u.length < 4) {
      errors.push("Username must be at least 4 characters, if provided.");
    }
  }

  // Password (optional; only if provided)
  if (data.password !== undefined) {
    const p = String(data.password);
    if (p.trim() === "") {
      errors.push("Password cannot be empty if provided.");
    } else if (p.length < 6) {
      errors.push("Password must be at least 6 characters.");
    }
  }

  // ----- Topics are OPTIONAL -----
  // Accept either:
  //   - legacy: { topics: { topic1, topic2, topic3 } }
  //   - modern: { topics: [ "Leadership...", "..." ] }
  // No requirement to include any topics.

  if (data.topics !== undefined) {
    const t = data.topics;

    // Array form
    if (Array.isArray(t)) {
      // Allow 0..3 topics; ensure any provided are non-empty strings
      if (t.length > 3) {
        errors.push("Up to 3 topics allowed.");
      }
      const bad = t.filter(v => isBlank(v));
      if (bad.length > 0) {
        errors.push("Topics cannot contain empty values.");
      }
    }
    // Object form (topic1/2/3) — optional, only validate if provided AND non-empty
    else if (t && typeof t === "object") {
      const { topic1, topic2, topic3 } = t;
      const vals = [topic1, topic2, topic3].filter(v => v !== undefined);
      const empties = vals.filter(v => isBlank(v));
      if (empties.length > 0) {
        errors.push("Provided topic fields cannot be empty.");
      }
      // no requirement that any of topic1/2/3 exist
    }
    // Any other type = ignore silently (or you could warn)
  }

  return errors;
};

