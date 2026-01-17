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
          desc: "This is your first step in learning, the topic tree. It shows how learning areas are organized so you can browse what’s available."
        },
        {
          src: "/images/kpiviewscreenshot.png",
          alt: "Topic breakdown and KPIs",
          title: "Topic breakdown + KPIs",
          desc: "Your next step is the topic breakdown and KPIs. This shows what good looks like and what gets measured - if you want to know how to apply what you've learned, see this view."
        },
        {
          src: "/images/bytopicscreenshot.png",
          alt: "Units in the topic",
          title: "Units in the topic",
          desc: "Your third step is an individual topic. The topic view shows units inside a topic so you can quickly pick what to learn next."
        },
        {
          src: "/images/singleunitscreenshot.png",
          alt: "Single learning unit",
          title: "Single learning unit",
          desc: "This is a learning unit. A learning unit can be an article, video, interview, prompt set, exercise, or template. It’s one piece of content with its own view."
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
          desc: "This is the Twennie Mine. It’s where you monitor market intel and early-stage opportunities. You can create your own nuggets or use the ones Twennie has already created. These leads are gathered from readily available online sources - they are NOT posted by any clients."
        },
        {
          src: "/images/clientnuggetscreenshot.png",
          alt: "Nuggets list",
          title: "Nuggets list",
          desc: "This view shows nuggets grouped by client/region/discipline so you can scan what exactly what you're looking for."
        },
        {
          src: "/images/singlenuggetscreenshot.png",
          alt: "Single nugget",
          title: "Market intelligence nugget",
          desc: "This is a single market intelligence nugget. It captures intel, key points, sources, and watch items for one project lead. The lead might represent multiple project opportunities later in the process, but here on Twennie are considered one lead."
        }
      ]
    },
    {
      key: "missions",
      title: "create learning and work packages",
      subtitle: "Assign missions and track completion.",
      images: [
        {
          src: "/images/missioncontrolscreenshot.png",
          alt: "Mission Control",
          title: "Mission Control",
          desc: "This is Mission Control. It’s where leaders create and assign missions. Missions are packages of learning or work that make it easier for you to complete assignments in a topic or category."
        },
        {
          src: "/images/missiontypescreenshot.png",
          alt: "Mission types",
          title: "Mission types",
          desc: "This shows mission types so you can choose the right kind of assignment for you. Twennie uses nine different types of missions: learning, research, business development, internal improvements, culture and play, client experience, community, administration, and other, which we call 'rogue'."
        },
        {
          src: "/images/singlemissionscreenshot.png",
          alt: "Single mission",
          title: "One mission",
          desc: "This is one mission. It includes instructions, expectations, and outcomes. Leaders can assign missions to their group members. Anyone can create new missions in the dashboard tab, contribute to my library."
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
          desc: "This is the Report Center. It’s where leaders view group learning activity. Here you can see topics covered, units completed, and badges earned."
        },
        {
          src: "/images/onereportscreenshot.png",
          alt: "One report",
          title: "One report",
          desc: "This is a report. It summarizes completions and engagement so you can coach effectively. The report center provides four report types."
        }
      ]
    }
  ];

  return res.render('promo_views/teach_me', {
    layout: 'mainlayout',
    mapLanes
  });
};
