require('dotenv').config();
const mongoose = require('mongoose');

const OrganizationProfile = require('./models/profile_models/organization_profile');

async function run() {
  try {

    await mongoose.connect(
      "mongodb+srv://michelelrochon:xWFJ1m4TV8zsBWMl@twenniecluster.s7idk.mongodb.net/?retryWrites=true&w=majority&appName=TwennieCluster"
    );

    console.log('✅ Connected to MongoDB');

    const existing = await OrganizationProfile.findOne({
      organizationId: '696138e795310bd55ecd2e70'
    });

    if (existing) {
      console.log('⚠️ Organization profile already exists.');
      await mongoose.disconnect();
      return;
    }

    const orgProfile = await OrganizationProfile.create({
      organizationId: '696138e795310bd55ecd2e70',
      adminLeaderId: '68f10f4610861b1dc57382a3',

      logo: {
        public_id: null,
        url: '/images/default-organization-logo.png'
      },

      bannerImage: {
        public_id: null,
        url: null
      },

      shortDescription:
        'TOMA Engineering Inc. is a multidisciplinary engineering firm focused on practical infrastructure solutions.',

      website: '',
      primaryColor: '#4e50a2',
      secondaryColor: '#262262'
    });

    console.log('✅ Organization profile created:', orgProfile._id.toString());

    await mongoose.disconnect();

  } catch (error) {
    console.error('❌ Error:', error);
  }
}

run();