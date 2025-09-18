// JavaScript Validate Unit Forms
module.exports = {
    // Validate Article Data
    validateArticleData: (data) => {
        const errors = [];

        const minChar = 5000; // Minimum characters for article content
        const maxChar = 8000; // Maximum characters for article content

        if (!data.article_title || data.article_title.trim() === "") errors.push("Article title is required.");
        if (!data.main_topic || data.main_topic.trim() === "") errors.push("Main topic is required.");
        if (!data.article_content || data.article_content.trim() === "") errors.push("Article content is required.");
        if (data.article_content && data.article_content.length < minChar) {
            errors.push(`Article content must be at least ${minChar} characters.`);
        }
        if (data.article_content && data.article_content.length > maxChar) {
            errors.push(`Article content must not exceed ${maxChar} characters.`);
        }
        if (!data.short_summary || data.short_summary.trim() === "") errors.push("Short summary is required.");
        if (!data.full_summary || data.full_summary.trim() === "") errors.push("Full summary is required.");

        return errors;
    },

    // Validate Video Data
    validateVideoData: (data) => {
        const errors = [];
        if (!data.video_title || data.video_title.trim() === "") errors.push("Video title is required.");
        if (!data.main_topic || data.main_topic.trim() === "") errors.push("Main topic is required.");
        if (!data.video_content || data.video_content.trim() === "") errors.push("Video content is required.");
        return errors;
    },

    // Validate Interview Data
    validateInterviewData: (data) => {
        const errors = [];
        if (!data.interview_title || data.interview_title.trim() === "") errors.push("Interview title is required.");
        if (!data.main_topic || data.main_topic.trim() === "") errors.push("Main topic is required.");
        if (!data.interview_content || data.interview_content.trim() === "") errors.push("Interview content is required.");
        return errors;
    },

    // Validate PromptSet Data
    validatePromptSetData: (data) => {
        const errors = [];
      
        if (!data.promptset_title || data.promptset_title.trim() === "") {
          errors.push("Prompt-set title is required.");
        }
        if (!data.main_topic || data.main_topic.trim() === "") {
          errors.push("Main topic is required.");
        }
        if (!data.short_summary || data.short_summary.trim() === "") {
          errors.push("Short summary is required.");
        }
        if (!data.full_summary || data.full_summary.trim() === "") {
          errors.push("Full summary is required.");
        }
        if (!data.suggested_frequency || !['daily', 'weekly', 'monthly', 'quarterly'].includes(data.suggested_frequency)) {
          errors.push("Suggested frequency is required and must be one of: daily, weekly, monthly, quarterly.");
        }
      
        // Validate badge subdocument, if present.
        if (data.badge) {
          // If either badge.image or badge.name is provided, both must be non-empty.
          const image = data.badge.image || "";
          const name = data.badge.name || "";
          if ((image.trim() !== "" || name.trim() !== "") && (image.trim() === "" || name.trim() === "")) {
            errors.push("Both badge image and badge name must be provided together.");
          }
        }

        // Prompts validation
        const prompt1 = data.Prompt1;
        if (!prompt1 || prompt1.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt1.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }
    
        const prompt2 = data.Prompt2;
        if (!prompt2 || prompt2.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt2.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }
    
        const prompt3 = data.Prompt3;
        if (!prompt3 || prompt3.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt3.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }
    
        const prompt4 = data.Prompt4;
        if (!prompt4 || prompt4.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt4.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }
    
        const prompt5 = data.Prompt5;
        if (!prompt5 || prompt5.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt5.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt6 = data.Prompt6;
        if (!prompt6 || prompt6.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt6.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt7 = data.Prompt7;
        if (!prompt7 || prompt7.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt7.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt8 = data.Prompt8;
        if (!prompt8 || prompt8.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt8.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt9 = data.Prompt9;
        if (!prompt9 || prompt9.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt9.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt10 = data.Prompt10;
        if (!prompt10 || prompt10.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt10.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt11 = data.Prompt11;
        if (!prompt11 || prompt11.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt11.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt12 = data.Prompt12;
        if (!prompt12 || prompt12.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt12.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt13 = data.Prompt13;
        if (!prompt13 || prompt13.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt13.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt14 = data.Prompt14;
        if (!prompt14 || prompt14.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt14.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt15 = data.Prompt15;
        if (!prompt15 || prompt15.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt15.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt16 = data.Prompt16;
        if (!prompt16 || prompt16.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt16.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt17 = data.Prompt17;
        if (!prompt17 || prompt17.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt17.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt18 = data.Prompt18;
        if (!prompt18 || prompt18.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt18.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt19 = data.Prompt19;
        if (!prompt19 || prompt19.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt19.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }

        const prompt20 = data.Prompt20;
        if (!prompt20 || prompt20.trim() === "") {
            errors.push("Prompt must be between 1 and 1000 characters.");
        } else if (prompt20.length > 1000) {
            errors.push("Prompt must not exceed 1000 characters.");
        }
    

        // Optional fields validation
        if (!data.target_audience || !['individual', 'group', 'mixed'].includes(data.target_audience)) {
            errors.push("Target audience is required and must be one of: individual, group, mixed.");
        }

        if (data.characteristics && !Array.isArray(data.characteristics)) {
            errors.push("Characteristics must be an array.");
        }

    // Suggested frequency validation
    if (!data.suggested_frequency || !['daily', 'weekly', 'monthly', 'quarterly'].includes(data.suggested_frequency)) {
        errors.push("Suggested frequency is required and must be one of: daily, weekly, monthly, quarterly.");
    }

        return errors;
    },

    // Validate Template Data
    validateTemplateData: (data) => {
        const errors = [];
    
        // Required fields validation
        if (!data.template_title || data.template_title.trim() === "") {
            errors.push("Template title is required.");
        }
    
        if (!data.main_topic || data.main_topic.trim() === "") {
            errors.push("Main topic is required.");
        }
    
        if (!data.short_summary || data.short_summary.trim() === "") {
            errors.push("Short summary is required.");
        }
    
        if (!data.full_summary || data.full_summary.trim() === "") {
            errors.push("Full summary is required.");
        }
    
        // Validate file format
        const validFormats = [
            "MS Word",
            "MS Excel",
            "MS PowerPoint",
            "PDF",
            "Mural",
            "Another format - please contact Twennie administrators"
        ];
        
        if (!validFormats.includes(data.file_format)) {
            errors.push("Please select a valid file format.");
        }
    
        return errors;
    },
    

    // Validate Exercise Data
    // Updated Validation Function
    validateExerciseData: (data) => {
        const errors = [];
    
        // Helper function to parse checkbox values
        const parseCheckbox = (value) => value === "on";
    
        // Required fields validation
        if (!data.exercise_title || data.exercise_title.trim() === "") {
            errors.push("Exercise title is required.");
        }
    
        if (!data.main_topic || data.main_topic.trim() === "") {
            errors.push("Main topic is required.");
        }
    
        if (!data.short_summary || data.short_summary.trim() === "") {
            errors.push("Short summary is required.");
        }
    
        if (!data.full_summary || data.full_summary.trim() === "") {
            errors.push("Full summary is required.");
        }
    
        // Validate file format
        const validFormats = [
            "MS Word",
            "MS Excel",
            "MS PowerPoint",
            "PDF",
            "Mural",
            "Another format - please contact Twennie administrators",
        ];
    
        if (!validFormats.includes(data.file_format)) {
            errors.push("A valid file format is required. Please select one from the available options.");
        }
    
        // Convert checkbox values to Boolean
        data.clarify_topic = parseCheckbox(data.clarify_topic);
        data.topics_and_enlightenment = parseCheckbox(data.topics_and_enlightenment);
        data.challenge = parseCheckbox(data.challenge);
        data.instructions = parseCheckbox(data.instructions);
        data.time = parseCheckbox(data.time);
        data.permission = parseCheckbox(data.permission);
    
        // Validate required Boolean fields
        if (data.permission !== true) {
            errors.push("You must provide consent for this exercise to be used for Twennie promotional purposes.");
        }
    
        return errors;
    },
    
    
    


    // Validate MicroStudy Data
    validateMicroStudyData: (data) => {
        const errors = [];
        const minChar = 300; // Minimum characters for micro-study content
        if (!data.microstudy_title || data.microstudy_title.trim() === "") errors.push("Micro-study title is required.");
        if (!data.main_topic || data.main_topic.trim() === "") errors.push("Main topic is required.");
        if (!data.microstudy_content || data.microstudy_content.trim() === "") errors.push("Micro-study content is required.");
        if (data.microstudy_content && data.microstudy_content.length < minChar) {
            errors.push(`Micro-study content must be at least ${minChar} characters long.`);
        }
        if (!data.short_summary || data.short_summary.trim() === "") errors.push("Short summary is required.");
        if (!data.full_summary || data.full_summary.trim() === "") errors.push("Full summary is required.");

        return errors;
    },

    // Validate MicroCourse Data
    validateMicroCourseData: (data) => {
        const errors = [];
        const minChar = 300; // Minimum characters for micro-course content
        if (!data.microcourse_title || data.microcourse_title.trim() === "") errors.push("Micro-course title is required.");
        if (!data.main_topic || data.main_topic.trim() === "") errors.push("Main topic is required.");
        if (!data.microcourse_content || data.microcourse_content.trim() === "") errors.push("Micro-course content is required.");
        if (data.microcourse_content && data.microcourse_content.length < minChar) {
            errors.push(`Micro-course content must be at least ${minChar} characters long.`);
        }
        if (!data.short_summary || data.short_summary.trim() === "") errors.push("Short summary is required.");
        if (!data.full_summary || data.full_summary.trim() === "") errors.push("Full summary is required.");

        return errors;
    },
};



