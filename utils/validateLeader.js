module.exports.validateLeaderData = (data) => {
    const errors = [];

    if (!data.groupName || data.groupName.trim() === "") errors.push("Group name is required.");
    if (!data.groupLeaderName || data.groupLeaderName.trim() === "") errors.push("Group leader name is required.");
    if (!data.professionalTitle || data.professionalTitle.trim() === "") errors.push("Professional title is required.");
    if (!data.organization || data.organization.trim() === "") errors.push("Organization is required.");
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
    if (!data.groupSize || isNaN(data.groupSize) || data.groupSize < 2 || data.groupSize > 10) {
        errors.push("Group size must be between 2 and 10 members.");
    }
    if (!data.topic1 || data.topic1.trim() === "") errors.push("Topic 1 is required.");
    if (!data.topic2 || data.topic2.trim() === "") errors.push("Topic 2 is required.");
    if (!data.topic3 || data.topic3.trim() === "") errors.push("Topic 3 is required.");
    if (!data.registration_code || data.registration_code.trim() === "") {
        errors.push("Registration code is required.");
    } else if (data.registration_code.length < 8) {
        errors.push("Registration code must be at least 8 characters long.");
    }

    return errors;
};
