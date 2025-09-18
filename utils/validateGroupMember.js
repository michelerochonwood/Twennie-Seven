module.exports.validateGroupMemberData = (data) => {
    const errors = [];

    // Check required fields
    if (!data.groupId || data.groupId.trim() === "") {
        errors.push("Group ID is required.");
    }

    if (!data.groupName || data.groupName.trim() === "") {
        errors.push("Group name is required.");
    }

    if (!data.name || data.name.trim() === "") {
        errors.push("Member name is required.");
    }

    if (!data.email || data.email.trim() === "") {
        errors.push("Email is required.");
    } else if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(data.email)) {
        errors.push("Please enter a valid email address.");
    }

    // Username validation: Only for group members added via the leader dashboard
    if (data.username !== undefined && (data.username.trim() === "" || data.username.length < 4)) {
        errors.push("Username must be at least 4 characters, if provided.");
    }

    // Password validation: Only when passwords are explicitly provided
    if (data.password !== undefined) {
        if (data.password.trim() === "") {
            errors.push("Password cannot be empty if provided.");
        } else if (data.password.length < 6) {
            errors.push("Password must be at least 6 characters.");
        }
    }

    // Optional topics validation (if required by the app logic)
    if (data.topics) {
        const { topic1, topic2, topic3 } = data.topics;
        if (!topic1 || topic1.trim() === "") {
            errors.push("Topic 1 is required.");
        }
        if (!topic2 || topic2.trim() === "") {
            errors.push("Topic 2 is required.");
        }
        if (!topic3 || topic3.trim() === "") {
            errors.push("Topic 3 is required.");
        }
    }

    return errors;
};
