const END_POINTS = {
  mostRead: (website) => `https://feedern.vkmedia.se/${website}/mostread`,
  pageviews: "https://content.vkmedia.se/pageviews/getPageviewsPerDay",
  pageviewsPerInterval:
    "https://content.vkmedia.se/pageviews/getPageviewsPerInterval",
  pageviewsPerDayFortnight:
    "https://content.vkmedia.se/pageviews/getPageviewsPerDay",
  contentVK: "https://content.vk.se/automaten/json/",
};

const fetchJson = async (url) => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Network response was not ok.");
  }
  return response.json();
};

const getTrend = (p, mult = 10) => {
  if (p === 0) return 0;

  if (p > (800 * mult) / 60) return 13;
  else if (p > (700 * mult) / 60) return 12;
  else if (p > (600 * mult) / 60) return 11;
  else if (p > (500 * mult) / 60) return 10;
  else if (p > (400 * mult) / 60) return 9;
  else if (p > (300 * mult) / 60) return 8;
  else if (p > (200 * mult) / 60) return 7;
  else if (p > (100 * mult) / 60) return 6;
  else if (p > (70 * mult) / 60) return 5;
  else if (p > (40 * mult) / 60) return 4;
  else if (p > (20 * mult) / 60) return 3;
  else if (p > (10 * mult) / 60) return 2;
  else if (p > (3 * mult) / 60) return 1;

  return 0;
};

const fetchArticles = async (website = "vk") => {
  try {
    const jsonfiles = {
      vk: "VK-algo.json",
      folkbladet: "Folkbladet-algo.json",
      nordsverige: "Nordsverige-algo.json",
      vasterbottningen: "Vasterbottningen-algo.json",
      mellanbygden: "Mellanbygden-algo.json",
      lokaltidningen: "Lokaltidningen-algo.json",
    };
    const automatenJson = await fetchJson(
      `${END_POINTS.contentVK}${jsonfiles[website]}`
    );

    const articles = Object.values(automatenJson);
    const alive = articles.filter((article) => article.hp > 0);
    let mult = 1;
    if (website === "vk") {
        mult = 10;
    } else if (website === "folkbladet") {
        mult = 1;
    } else {
        mult = 0.1;
    }


    const toplist = alive
      .map((article) => {
        const minutesPublished = Math.ceil(
          (Date.now() - new Date(article.published).getTime()) / 60000
        );
        const impressionsPerMinute =
          article.impressionWindow / Math.min(45, minutesPublished);
        return {
          uuid: article.uuid,
          impressions: article.impressions,
          impressionWindow: article.impressionWindow,
          published: article.published,
          headline: "", // This will be filled later from articleInfo
          minutesPublished: minutesPublished,
          impressionsPerMinute: impressionsPerMinute,
          trend: getTrend(impressionsPerMinute, mult),
        };
      })
      .sort((a, b) => b.impressionsPerMinute - a.impressionsPerMinute)
      .slice(0, 20);

    const uuidsString = toplist.map((a) => a.uuid).join(",");
    const articleInfo = await fetchJson(
      `https://feedern.vkmedia.se/${website}/articles/?articles=${uuidsString}`
    );

    if (!articleInfo || !articleInfo.articles) {
      throw new Error("Unable to parse json");
    }

    return toplist.map((a) => {
      const info = articleInfo.articles.find((info) => info.uuid === a.uuid);
      return {
        ...a,
        headline: info ? info.headline : a.headline,
      };
    });
  } catch (error) {
    console.error("Error fetching articles:", error);
    return [];
  }
};

const fetchMostRead = async (website = "vk", isPremium = false) => {
  try {
    const url = `${END_POINTS.mostRead(website)}${
      isPremium ? "?paywallTypes=premium" : ""
    }`;
    const data = await fetchJson(url);
    return data.articles.map((article) => ({
      headline: article.headline,
      count: article.count,
    }));
  } catch (error) {
    console.error("Error fetching most read articles:", error);
    return [];
  }
};

const getPageviewsPerDay = async (website = "vk", plus = false) => {
  try {
    const postdata = {
      days: 1,
      channel: website,
      paywallTypes: plus ? ["premium"] : undefined,
    };

    const response = await fetch(END_POINTS.pageviews, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(postdata),
    });

    if (!response.ok) {
      throw new Error("Network response was not ok.");
    }

    return response.json();
  } catch (error) {
    console.error("Error fetching pageviews per day:", error);
    return null;
  }
};

const getAveragePageviewByMinute = async (website = "vk") => {
  try {
    const postdata = {
      channel: website,
    };

    const response = await fetch(END_POINTS.pageviewsPerInterval, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(postdata),
    });

    if (!response.ok) {
      throw new Error("Network response was not ok.");
    }

    const totalPageviews = await response.json();
    return totalPageviews / 60;
  } catch (error) {
    console.error("Error fetching average pageviews per minute:", error);
    return null;
  }
};

// @ts-ignore
const splitDataIntoWeeks = (data) => {
  const groupedByWeeks = {};

  data.forEach((item) => {
    const date = new Date(item.date);
    // Adjust to the start of the week (Monday)
    const weekStart = new Date(date);
    weekStart.setDate(
      weekStart.getDate() -
        (weekStart.getDay() === 0 ? 6 : weekStart.getDay() - 1)
    );

    const weekKey = weekStart.toISOString().split("T")[0]; // Use the start of the week as a key

    if (!groupedByWeeks[weekKey]) {
      groupedByWeeks[weekKey] = [];
    }

    groupedByWeeks[weekKey].push(item);
  });

  // Sort each week's data by date in ascending order
  const sortedWeeks = Object.entries(groupedByWeeks).map(([key, week]) => {
    return {
      weekStart: key,
      // @ts-ignore
      data: week.sort((a, b) => new Date(a.date) - new Date(b.date)),
    };
  });

  // Sort weeks in descending order based on the start date
  // @ts-ignore
  return sortedWeeks
    .sort((a, b) => new Date(b.weekStart) - new Date(a.weekStart))
    .map((week) => week.data);
};

const getPageviewsPerIntervalForFortnight = async (
  website = "vk",
  isPremium = false
) => {
  try {
    const postdata = {
      channel: website,
      days: 14,
      limit: 14,
      ...(isPremium && { paywallTypes: ["premium"] }),
    };

    const response = await fetch(END_POINTS.pageviewsPerDayFortnight, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(postdata),
    });

    if (!response.ok) {
      throw new Error("Network response was not ok.");
    }

    return response.json();
  } catch (error) {
    console.error("Error fetching pageviews per day for fortnight:", error);
    return null;
  }
};

const processPageviews = async (website = "vk") => {
  try {
    const fetchDataAndSort = async (isPremium) => {
      const data = await getPageviewsPerIntervalForFortnight(
        website,
        isPremium
      );
      // Sort data by date
      return data.sort((a, b) => new Date(a.date) - new Date(b.date));
    };

    const [sortedPageviews, sortedPageviewsPlus] = await Promise.all([
      fetchDataAndSort(false),
      fetchDataAndSort(true),
    ]);

    const thisweek = {},
      lastweek = {},
      thisweek_plus = {},
      lastweek_plus = {};

    // Get today's date information - don't rely on local timezone
    // Create a fresh date in the local timezone context
    const now = new Date();
    
    // Find the current day of the week (0 = Sunday, 1 = Monday, etc.)
    const currentDayOfWeek = now.getDay();
    
    // Calculate the date of Monday for the current week
    // If today is Sunday (0), we need to go back 6 days
    // If today is Monday (1), we don't go back
    // If today is Tuesday (2), we go back 1 day, etc.
    const daysToSubtract = currentDayOfWeek === 0 ? 6 : currentDayOfWeek - 1;
    
    // Create a new date object for the Monday of the current week
    const monday = new Date(now);
    monday.setDate(now.getDate() - daysToSubtract);
    
    // Reset time to midnight (start of day)
    monday.setHours(0, 0, 0, 0);

    console.log("Current day:", now.toISOString());
    console.log("Monday of current week:", monday.toISOString());
    console.log("Day of week:", currentDayOfWeek);

    const categorizeData = (data, thisWeekContainer, lastWeekContainer) => {
      if (!data || !Array.isArray(data)) {
        console.error("Invalid data received:", data);
        return;
      }
      
      data.forEach(({ date, count }) => {
        if (!date || !count) {
          console.error("Invalid data item:", { date, count });
          return;
        }
        
        // Parse the date and normalize to midnight
        const viewDate = new Date(date);
        viewDate.setHours(0, 0, 0, 0);
        
        // Get day of week (1-7, where 1 is Monday and 7 is Sunday)
        // Convert from JavaScript's 0-6 (Sunday-Saturday) to 1-7 (Monday-Sunday)
        const dayOfWeek = viewDate.getDay() === 0 ? 7 : viewDate.getDay();
        
        console.log(
          "Processing:", 
          date, 
          "Parsed:", 
          viewDate.toISOString(), 
          "Day:", 
          dayOfWeek,
          "Is before Monday?", 
          viewDate < monday
        );

        // Determine if this date belongs to the current week or the previous week
        if (viewDate < monday) {
          console.log("-> Adding to last week:", dayOfWeek, count);
          lastWeekContainer[dayOfWeek] = { TotalViews: count };
        } else {
          console.log("-> Adding to this week:", dayOfWeek, count);
          thisWeekContainer[dayOfWeek] = { TotalViews: count };
        }
      });
      
      console.log("This week container:", thisWeekContainer);
      console.log("Last week container:", lastWeekContainer);
    };

    categorizeData(sortedPageviews, thisweek, lastweek);
    categorizeData(sortedPageviewsPlus, thisweek_plus, lastweek_plus);

    return { thisweek, lastweek, thisweek_plus, lastweek_plus };
  } catch (error) {
    console.error("Error processing pageviews:", error);
    return null;
  }
};

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const site = url.searchParams.get("site") || "vk";
  const clientIP = context.request.headers.get('cf-connecting-ip') || '127.0.0.1';

  console.log(clientIP);
  if (clientIP !== '193.180.2.5' && clientIP !== '127.0.0.1' && clientIP !== '::1') {
    return new Response('Unauthorized', { status: 403 });
  }

  let response = null;
  try {
    // Await the resolution of all promises
    const [
      fetchArticlesResult,
      pageviews,
      averagePageviewByMinute,
      pageviewsPerDay,
      pageviewsPerDayPlus,
      mostRead,
      mostReadPlus,
    ] = await Promise.all([
      fetchArticles(site),
      processPageviews(site),
      getAveragePageviewByMinute(site),
      getPageviewsPerDay(site),
      getPageviewsPerDay(site, true),
      fetchMostRead(site),
      fetchMostRead(site, true),
    ]);

    // Create a JSON response with the data
    const jsonResponse = JSON.stringify({
      popularArticles: fetchArticlesResult,
      pageviews,
      averagePageviewByMinute,
      pageviewsPerDay,
      pageviewsPerDayPlus,
      mostRead,
      mostReadPlus,
    });

    // Construct the response
    response = new Response(
      jsonResponse,
      { headers: { "Content-Type": "application/json" } },
      200
    );
  } catch (error) {
    // Handle errors
    response = new Response(JSON.stringify({ error: error.message }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  }
  return response;
}