module.exports.validateMemberData = (data) => {
  const errors = [];

  const isBlank = (v) => !v || String(v).trim() === "";

  // Name
  if (isBlank(data.name)) {
    errors.push("Name is required.");
  }

  // Email
  if (isBlank(data.email)) {
    errors.push("Email is required.");
  } else if (!/^\S+@\S+\.\S+$/.test(String(data.email))) {
    errors.push("Please enter a valid email address.");
  }

  // Password
  if (isBlank(data.password)) {
    errors.push("Password is required.");
  } else {
    const p = String(data.password);

    if (p.length < 12) {
      errors.push("Password must be at least 12 characters.");
    }

    if (!/[a-z]/.test(p)) {
      errors.push("Password must include at least one lowercase letter.");
    }

    if (!/[A-Z]/.test(p)) {
      errors.push("Password must include at least one uppercase letter.");
    }

    if (!/[0-9]/.test(p)) {
      errors.push("Password must include at least one number.");
    }

    if (!/[^A-Za-z0-9]/.test(p)) {
      errors.push("Password must include at least one special character.");
    }

    const weakPasswords = new Set([
      "password",
      "password123",
      "12345678",
      "qwerty123",
      "admin123"
    ]);

    if (weakPasswords.has(p.toLowerCase())) {
      errors.push("Please choose a stronger password.");
    }
  }

  // Confirm password check (if present)
  if (data.confirmPassword !== undefined && data.password !== data.confirmPassword) {
    errors.push("Passwords do not match.");
  }

  return errors;
};