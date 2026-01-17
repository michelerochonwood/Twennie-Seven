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
          desc: "This is the topic tree. It shows how learning areas are organized so you can browse what’s available."
        },
        {
          src: "/images/kpiviewscreenshot.png",
          alt: "Topic breakdown and KPIs",
          title: "Topic breakdown + KPIs",
          desc: "This is the topic breakdown and KPIs. It shows what good looks like and what gets measured."
        },
        {
          src: "/images/bytopicscreenshot.png",
          alt: "Units in the topic",
          title: "Units in the topic",
          desc: "This shows units inside a topic so you can quickly pick what to learn next."
        },
        {
          src: "/images/singleunitscreenshot.png",
          alt: "Single learning unit",
          title: "Single learning unit",
          desc: "This is a learning unit. It’s one piece of content with its own view."
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
          desc: "This is the Mine. It’s where you monitor market intel and early-stage opportunities."
        },
        {
          src: "/images/clientnuggetscreenshot.png",
          alt: "Nuggets list",
          title: "Nuggets list",
          desc: "This view shows nuggets grouped by client/region/discipline so you can scan what matters."
        },
        {
          src: "/images/singlenuggetscreenshot.png",
          alt: "Single nugget",
          title: "Market intelligence nugget",
          desc: "This is one nugget. It captures intel, key points, sources, and watch items."
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
          desc: "This is Mission Control. It’s where leaders create and assign missions."
        },
        {
          src: "/images/missiontypescreenshot.png",
          alt: "Mission types",
          title: "Mission types",
          desc: "This shows mission types so you can choose the right kind of assignment."
        },
        {
          src: "/images/singlemissionscreenshot.png",
          alt: "Single mission",
          title: "One mission",
          desc: "This is one mission. It includes instructions, expectations, and outcomes."
        }
      ]
    },
    {
      key: "reports",
      title: "monitor learning",
      subtitle: "See what’s being used and what’s completed.",
      images: [
        {
          src: "/images/reportcenterscreenshot.png",
          alt: "Report center",
          title: "Report center",
          desc: "This is the Report Center. It’s where leaders view group learning activity."
        },
        {
          src: "/images/onereportscreenshot.png",
          alt: "One report",
          title: "One report",
          desc: "This is a report. It summarizes completions and engagement so you can coach effectively."
        }
      ]
    }
  ];

  return res.render('promo_views/teach_me', {
    layout: 'mainlayout',
    mapLanes
  });
};
