// utils/validateLeader.js
module.exports.validateLeaderData = (data) => {
  const errors = [];

  // Required text fields
  if (!data.groupName || data.groupName.trim() === "") errors.push("Group name is required.");
  if (!data.groupLeaderName || data.groupLeaderName.trim() === "") errors.push("Group leader name is required.");
  if (!data.professionalTitle || data.professionalTitle.trim() === "") errors.push("Professional title is required.");
  if (!data.organization || data.organization.trim() === "") errors.push("Organization is required.");

  // Industry (schema-required; mirror enum for early feedback)
  const allowedIndustries = new Set([
    'Engineering',
    'Architecture',
    'Project Management',
    'Information Technology(IT)',
    'Web Design',
    'Construction',
    'Technology',
    'AI and Robotics',
    'Social Media/Digital Advertising',
    'Community Planning/Landscape Architecture',
    'Land Development',
    'Telecommunications',
    'E-Commerce',
    'Cybersecurity',
    'Fintech',
    'Edtech',
    'Energy and Utilities',
    'Manufacturing',
    'Other'
  ]);
  if (!data.industry || data.industry.trim() === "") {
    errors.push("Industry is required.");
  } else if (!allowedIndustries.has(data.industry)) {
    errors.push("Please select a valid industry.");
  }

  // Username / email / password
  if (!data.username || data.username.trim() === "") errors.push("Username is required.");

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

  // Group size (2–10)
  const size = Number(data.groupSize);
  if (!Number.isFinite(size) || size < 2 || size > 10) {
    errors.push("Group size must be between 2 and 10 members.");
  }

  // Topics are now OPTIONAL — do NOT require topic1/2/3.
  // If your frontend still sends empty strings, it’s harmless.

  // Registration code
  if (!data.registration_code || data.registration_code.trim() === "") {
    errors.push("Registration code is required.");
  } else if (data.registration_code.length < 8) {
    errors.push("Registration code must be at least 8 characters long.");
  }

  return errors;
};

