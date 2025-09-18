module.exports.validateMemberData = (data) => {
  const errors = [];

  if (!data.name || data.name.trim() === "") {
    errors.push("Name is required.");
  }

  if (!data.email || data.email.trim() === "") {
    errors.push("Email is required.");
  }

  if (!data.password || data.password.trim() === "") {
    errors.push("Password is required.");
  }

  return errors;
};