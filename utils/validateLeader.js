// utils/validateLeader.js
module.exports.validateLeaderData = (data) => {
  const errors = [];

  // ------------------------------------------------------------
  // Required text fields
  // ------------------------------------------------------------
  if (!data.groupName || data.groupName.trim() === "") {
    errors.push("Group name is required.");
  }

  if (!data.groupLeaderName || data.groupLeaderName.trim() === "") {
    errors.push("Group leader name is required.");
  }

  if (!data.professionalTitle || data.professionalTitle.trim() === "") {
    errors.push("Professional title is required.");
  }

  // ------------------------------------------------------------
  // Organization
  // ------------------------------------------------------------
  // IMPORTANT:
  // Organization is OPTIONAL at leader signup.
  // Leaders may create or join an organization later from the dashboard.
  //
  // If organization is provided (future-proofing), validate it lightly.
  if (data.organization) {
    const orgVal = String(data.organization).trim();
    if (!orgVal) {
      errors.push("Organization value is invalid.");
    }
  }

  // ------------------------------------------------------------
  // Industry (still required; mirror enum for early feedback)
  // ------------------------------------------------------------
  const allowedIndustries = new Set([
    'Engineering',
    'Architecture',
    'Project Management',
    'Information Technology(IT)',
    'Web Design',
    'Construction',
    'Social Media/Digital Advertising',
    'Community Planning/Landscape Architecture',
    'Land Development',
    'Fintech',
    'Edtech',
    'Energy and Utilities',
    'Other'
  ]);

  if (!data.industry || data.industry.trim() === "") {
    errors.push("Industry is required.");
  } else if (!allowedIndustries.has(data.industry)) {
    errors.push("Please select a valid industry.");
  }

  // ------------------------------------------------------------
  // Username / email / password
  // ------------------------------------------------------------
  if (!data.username || data.username.trim() === "") {
    errors.push("Username is required.");
  }

  if (!data.groupLeaderEmail || data.groupLeaderEmail.trim() === "") {
    errors.push("Email is required.");
  } else if (!/^\S+@\S+\.\S+$/.test(data.groupLeaderEmail)) {
    errors.push("Please enter a valid email address.");
  }

  if (!data.password || data.password.trim() === "") {
    errors.push("Password is required.");
  } else if (data.password.length < 6) {
    errors.push("Password must be at least 6 characters.");
  }

  // ------------------------------------------------------------
  // Group size (2–10)
  // ------------------------------------------------------------
  const size = Number(data.groupSize);
  if (!Number.isFinite(size) || size < 2 || size > 10) {
    errors.push("Group size must be between 2 and 10 members.");
  }

  // ------------------------------------------------------------
  // Topics are OPTIONAL (do nothing)
  // ------------------------------------------------------------

  // ------------------------------------------------------------
  // Registration code
  // ------------------------------------------------------------
  if (!data.registration_code || data.registration_code.trim() === "") {
    errors.push("Registration code is required.");
  } else if (data.registration_code.length < 8) {
    errors.push("Registration code must be at least 8 characters long.");
  }

  return errors;
};
