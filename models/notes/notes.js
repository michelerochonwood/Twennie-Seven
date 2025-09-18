const mongoose = require('mongoose');

const NotesSchema = new mongoose.Schema({
    unitID: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Unit', 
        required: true 
    },
    memberID: { 
        type: mongoose.Schema.Types.ObjectId, 
        refPath: 'memberType', // Dynamic reference to either GroupMember or Leader
        required: true 
    },
    memberType: { 
        type: String, 
        enum: ['group_member', 'leader'],  // <-- Change to match actual values in the database
        required: true 
    },
    
    main_topic: { 
        type: String, 
        required: true 
    },
    secondary_topic: { 
        type: String 
    },
    note_content: { 
        type: String, 
        required: true 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
});

module.exports = mongoose.model('Note', NotesSchema);
