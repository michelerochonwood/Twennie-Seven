// controllers/twenniemapController.js
exports.getTeachMe = (req, res) => {
  const mapLanes = [
    {
      key: "learn",
      title: "learn",
      subtitle: "Explore topics, KPIs, and learning units in the Twennie library.",
      images: [
        {
          src: "/images/topictreescreenshot.png",
          alt: "Topic tree",
          title: "Topic tree",
          desc: "Twennie learning lives in three topic areas: project management, business development, and leadership. Under those are seven categories: project management, business development and marketing, proposals, people management, technology, workplace culture, and AI."
        },
        {
          src: "/images/kpiviewscreenshot.png",
          alt: "Topic breakdown and KPIs",
          title: "Topic breakdown + KPIs",
          desc: "Your next step is the topic breakdown. Twennie doesn't use courses, quizzes, or tests - instead we provide key performance indicators(KPIs) here. This shows you how to apply topic-specific learning directly to your work performance. The KPIs are transferrable to a career plan and applicable to a range of professional roles."
        },
        {
          src: "/images/bytopicscreenshot.png",
          alt: "Units in the topic",
          title: "Units in the topic",
          desc: "The individual topic view shows units inside a topic. A handy reference explains Twennie's library units: articles, videos, interviews, prompt sets, exercises and templates. All Twennie learning uses these units, which are designed to fit in the time you have available, and accommodate the extent to which you wish to investigate a topic."
        },
        {
          src: "/images/singleunitscreenshot.png",
          alt: "Single learning unit",
          title: "Single learning unit",
          desc: "An individual learning unit is an article, video, interview, prompt set, exercise, or template. Depending on the unit, learning can be done within 5, 10, or 20 minutes. When you record notes, you have completed that unit. Completions are tracked in yours and your leader's dashboard. Leaders can assign these units to group members and track completion."
        }
      ]
    },
    {
  key: "create_learning",
  title: "create learning",
  subtitle: "Contribute and manage your own library content.",
  images: [
    {
      src: "/images/contributescreenshot.png",
      alt: "Contribute content",
      title: "contribute",
      desc: "This is where you contribute learning to the library. Use Twennie’s guided forms to add your own articles, videos, interviews, prompt sets, exercises, or templates. You can share with your group only, your organization only, or the whole Twennie community. Your units will show under the chosen topic, but will only be visible based on your chosen visibility settings."
    },
    {
      src: "/images/createvideoscreenshot.png",
      alt: "Create a unit",
      title: "create units",
      desc: "This is the unit creation form. Create content to share practical know-how with your team or the wider Twennie community, whichever is appropriate for the content."
    },
    {
      src: "/images/mylibraryunitsscreenshot.png",
      alt: "My library units",
      title: "my library units",
      desc: "This is the 'my library units' tab in your dashboard. This is your space to review, edit, and manage all the learning units you’ve created or contributed to your library."
    }
  ]
},

    {
      key: "mine",
      title: "the Mine - monitor project opportunities",
      subtitle: "Track nuggets by client, region, or discipline.",
      images: [
        {
          src: "/images/minescreenshot.png",
          alt: "The Twennie Mine",
          title: "The Twennie Mine",
          desc: "This is the Twennie Mine. It’s where you monitor market intel and early-stage opportunities - not RFPs. An RFP may later emerge from these opportunities, but the purpose of the Mine is to track them earlier in the cycle. "
        },
        {
          src: "/images/clientnuggetscreenshot.png",
          alt: "Nuggets list",
          title: "Nuggets list",
          desc: "This view shows nuggets grouped by client/region/discipline. The same nugget will appear in all three categories, but organized by client, region, or discipline. At the bottom you'll see example nuggets managed by Twennie - these are there to give you some ideas for where to mine your own nuggets. Nuggets you've created will show under 'created by me' section. You set the visibility level for your nuggets."
        },
        {
          src: "/images/singlenuggetscreenshot.png",
          alt: "Single nugget",
          title: "Market intelligence nugget",
          desc: "This is a single market intelligence nugget. It captures intel, key points, sources, and watch items for one project lead. The lead might represent multiple project opportunities later in the process, but here on Twennie this is considered one nugget. Nuggets can be linked to their online source to make it easy to monitor and update. Leaders can assign nuggets to members of their groups for ongoing tracking. When you want to create a nugget, go to the 'contribute to my library' tab in the dashboard and click 'nugget.'"
        }
      ]
    },
    {
      key: "missions",
      title: "Mission Control - package learning and tasks...then assign",
      subtitle: "Assign missions and track completion.",
      images: [
        {
          src: "/images/missioncontrolscreenshot.png",
          alt: "Mission Control",
          title: "Mission Control",
          desc: "This is Mission Control. It’s where leaders access and assign missions. A mission is a package of learning or work in a topic or category. Use missions when the workload is light, when you want to assign and track internal projects, or combine learning units into a more comprehensive analysis of a topic."
        },
        {
          src: "/images/missiontypescreenshot.png",
          alt: "Mission types",
          title: "Mission types",
          desc: "The mission type view shows mission types so you can choose the right kind of assignment for the time you have and the work or learning you want to complete. Twennie uses nine different types of missions: learning, research, business development, internal improvements, culture and play, client experience, community, administration, and other, which we call 'rogue'."
        },
        {
          src: "/images/singlemissionscreenshot.png",
          alt: "Single mission",
          title: "One mission",
          desc: "This is one mission. It includes instructions, expectations, and projected outcomes. Leaders can assign missions to their group members. Anyone can complete a mission or create new custom missions for colleagues in the dashboard tab, 'contribute to my library.' You can even combine Twennie learning units with your own custom units to create hybrid missions! Twennie provides some sample missions for inspiration and guidance - find these in Mission Control."
        }
      ]
    },
    {
      key: "reports",
      title: "monitor learning",
      subtitle: "FOR LEADERS ONLY | See what’s been learned and completed.",
      images: [
        {
          src: "/images/reportcenterscreenshot.png",
          alt: "Report center",
          title: "Report center",
          desc: "This is the Report Center, accessible to leaders only. It’s where leaders view group learning activity and completions.  Here you can see topics explored by your team, units completed, and badges earned. All notes your team has recorded on learning will show in these reports. Twennie can help you use AI to summarize these notes and plan future learning more strategically."
        },
        {
          src: "/images/onereportscreenshot.png",
          alt: "One report",
          title: "One report",
          desc: "This is a Twennie report. It summarizes completions and notes so you can coach effectively as the team leader. The report center provides four report types: Member Engagement, Completed Prompt Sets, Completed Library Units, and Nuggets Assigned."
        }
      ]
    }
  ];

  return res.render('promo_views/teach_me', {
    layout: 'mainlayout',
    mapLanes
  });
};
