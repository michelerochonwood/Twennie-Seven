// controllers/twenniemapController.js
exports.getTeachMe = (req, res) => {
  const mapLanes = [
    {
      key: "learn",
      title: "learn",
      subtitle: "Explore topics, KPIs, and learning units.",
      images: [
        {
          src: "/images/topictreescreenshot.png",
          alt: "Topic tree",
          title: "Topic tree",
          desc: "The topic tree is your first step in learning. It shows how Twennie's topics are organized. Twennie focuses on three main spheres of learning: project management, business development, and leadership. Under those you will find our seven main topic categories: project management, business development and marketing, proposals, people management, technology, workplace culture, and AI. Under those, topics are further broken down into items like proposal strategy, managing scope, or leading change. Easily browse everything available in the main library and find topics you want to explore. "
        },
        {
          src: "/images/kpiviewscreenshot.png",
          alt: "Topic breakdown and KPIs",
          title: "Topic breakdown + KPIs",
          desc: "Your next step is the topic breakdown. Twennie doesn't use courses, quizzes, or tests - instead we provide key performance indicators(KPIs) here in this view, which shows you how to apply topic-specific learning to your work performance. The KPIs are directly transferrable to a career plan and applicable to a range of professional roles."
        },
        {
          src: "/images/bytopicscreenshot.png",
          alt: "Units in the topic",
          title: "Units in the topic",
          desc: "Your third step is an individual topic. The topic view shows units inside a topic so you can quickly choose what to learn next. A handy reference explains Twennie's library units: articles, videos, interviews, prompt sets, exercises and templates. All Twennie learning uses these units, which are designed to adapt to different learning styles, the time you have available, and the extent to which you wish to investigate a topic."
        },
        {
          src: "/images/singleunitscreenshot.png",
          alt: "Single learning unit",
          title: "Single learning unit",
          desc: "This is an individual learning unit - an article, video, interview, prompt set, exercise, or template - one piece of content with its own view. Depending on the unit, learning can be done within 5, 10, or 20 minutes, which will show in the sidebar of the unit view. When you record notes on a library unit, you have completed that unit. Completions are tracked in yours and your leader's dashboard. The badges you've earned show in your dashboard tabs. Leaders can assign these units to group members and track completion."
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
      desc: "This is the 'contribute to my library tab' in your dashboard. Use Twennie’s guided forms to add learning content to your library. You can share your learning content with your group only, your organization only, or the whole Twennie community. Your units will show under the chosen topic, but will only be visible to other members based on your chosen visibility settings."
    },
    {
      src: "/images/createvideoscreenshot.png",
      alt: "Create a unit",
      title: "create units",
      desc: "This is the library unit creation form. Create articles, videos, interviews, prompt sets, exercises, or templates to share practical know-how with your team or the wider Twennie community, whichever is appropriate for the content."
    },
    {
      src: "/images/mylibraryunitsscreenshot.png",
      alt: "My library units",
      title: "my library units",
      desc: "This is the 'my library units' tab in your dashboard. This is your workspace to review, edit, and manage all the learning units you’ve created or contributed to your portion of the library."
    }
  ]
},

    {
      key: "mine",
      title: "monitor project opportunities",
      subtitle: "Track nuggets by client, region, or discipline.",
      images: [
        {
          src: "/images/minescreenshot.png",
          alt: "The Twennie Mine",
          title: "The Twennie Mine",
          desc: "This is the Twennie Mine. It’s where you monitor market intel and early-stage opportunities - not RFPs. An RFP may later emerge from these opportunities, but the purpose of the Mine is to track them earlier in the cycle. The Mine contains a mix of project opportunities in engineering disciplines - each one is called a nugget. You can create your own nuggets visible to your team only, or track the ones Twennie has already suggested. These leads are gathered from readily available online sources - they are NOT posted by any clients."
        },
        {
          src: "/images/clientnuggetscreenshot.png",
          alt: "Nuggets list",
          title: "Nuggets list",
          desc: "This view shows nuggets grouped by client/region/discipline so you can find exactly what you're looking for. The same nugget will appear in all three categories, but organized by client, region, or discipline. At the bottom of the page you'll see nuggets managed by Twennie. Nuggets you've created will show under 'created by me' section. If you've shared with your team only, your nugget will be visible only to them under the 'created by my group' section. If you've shared with your organization, the nugget will show in that section, too, to all people in your organization that have memberships on Twennie."
        },
        {
          src: "/images/singlenuggetscreenshot.png",
          alt: "Single nugget",
          title: "Market intelligence nugget",
          desc: "This is a single market intelligence nugget. It captures intel, key points, sources, and watch items for one project lead. The lead might represent multiple project opportunities later in the process, but here on Twennie this is considered one nugget. Nuggets can be linked to their online source to make it easy to monitor and update. Leaders can assign nuggets to members of their groups for ongoing tracking. Nuggets you've created can be visible to your whole organization or your group only. If you want to create a nugget, go to the 'contribute to my library' tab in the dashboard and click 'nugget.'"
        }
      ]
    },
    {
      key: "missions",
      title: "package learning and tasks...then assign",
      subtitle: "Assign missions and track completion.",
      images: [
        {
          src: "/images/missioncontrolscreenshot.png",
          alt: "Mission Control",
          title: "Mission Control",
          desc: "This is Mission Control. It’s where leaders access and assign missions. Missions are packages of learning or work assignments in a topic or category. Use missions when the workload is light, when you want to assign and track internal projects, or combine learning units into a more comprehensive examination of a topic."
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
          desc: "This is one mission. It includes instructions, expectations, and projected outcomes. Leaders can assign missions to their group members. Anyone can complete a mission or create new custom missions for colleagues in the dashboard tab, 'contribute to my library.' You can even combine Twennie learning units with your own custom units to create hybrid missions! Twennie provides some sample missions for inspiration and guidance."
        }
      ]
    },
    {
      key: "reports",
      title: "monitor learning",
      subtitle: "See what’s being learned and what’s completed.",
      images: [
        {
          src: "/images/reportcenterscreenshot.png",
          alt: "Report center",
          title: "Report center",
          desc: "This is the Report Center, accessible to leaders only. It’s where leaders view group learning activity and completions.  Here you can see topics covered by your team, units completed, and badges earned. All notes your team has recorded on learning will show in these reports. Twennie can help you use AI to summarize these notes and plan future learning more strategically."
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
