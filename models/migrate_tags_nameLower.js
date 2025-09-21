// scripts/migrate_tags_nameLower.js
const mongoose = require('mongoose');
const Tag = require('../models/tag');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/yourdb';

(async () => {
  try {
    await mongoose.connect(MONGODB_URI);

    // 1) Backfill nameLower
    const cursor = Tag.find({ $or: [{ nameLower: { $exists: false } }, { nameLower: null }] }).cursor();
    let updated = 0;
    for (let tag = await cursor.next(); tag; tag = await cursor.next()) {
      tag.nameLower = String(tag.name || '').trim().toLowerCase();
      await tag.save();
      updated++;
    }
    console.log('Backfilled nameLower for', updated, 'tags');

    // 2) Drop old unique index on name (if it exists)
    try {
      await Tag.collection.dropIndex('name_1');
      console.log('Dropped index name_1');
    } catch (e) {
      console.log('No name_1 index to drop (ok)');
    }

    // 3) Ensure new compound unique index exists
    await Tag.collection.createIndex({ nameLower: 1, createdBy: 1 }, { unique: true });
    console.log('Ensured unique index on {nameLower, createdBy}');

    await mongoose.disconnect();
    console.log('Done.');
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();