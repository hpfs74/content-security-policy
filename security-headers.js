/**
 * security-headers.js
 *
 * set the heders of cloudfront reading them from a json object 'secHeaders'.
 * the json object is inside the code but i can also be stored in a file.
 *
 * IMPORTANT: cannot be put in a S3 bucket because it is too slow and will make
 * the lambda@edge go in timeout resulting the site to not be visible.
 */

const secHeaders = {
    "Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload",
    "Content-Security-Policy": [
        "default-src 'unsafe-inline' 'self'",
          "https://www.google-analytics.com",
          "https://www.googletagmanager.com",
          "http://aegon-middleware-qa.mobgen.com",
          "https://middleware.test.knabverzekeren.nl",
          "https://middleware.verzekeren.knab.nl",
          "https://middleware.uat.knabverzekeren.nl",
          "https://knab-dev.apigee.net",
          "https://knab-acc.apigee.net",
          "https://knab-prd.apigee.net",
          ";",
        "img-src  'self'",
          "data:",
          "https://ssl.google-analytics.com",
          "https://www.google.com",
          "https://www.google.nl",
          "https://www.google-analytics.com",
          "https://*.visualwebsiteoptimizer.com",
          "https://www.facebook.com",
          "https://googleads.g.doubleclick.net",
          "https://www.googleadservices.com",
          "https://secure.adnxs.com",
          "https://ib.adnxs.com",
          "https://www.facebook.com/tr/",
          "https://secure.adnxs.com",
          "https://www.at19.net",
          "https://knab.blueconic.net",
          "https://stats.g.doubleclick.net",
          "https://ad.doubleclick.net/ddm/activity/src=8163947",
          "https://secure.adnxs.com",
          "https://www.google.nl",
          "https://www.google-analytics.com",
          "https://stats.g.doubleclick.net",
          "http://placehold.it",
          "https://www.google.com/ads",
          "https://www.gstatic.com",
          "https://d3cuj82m9z5zxb.cloudfront.net;",
        "script-src ",
          "'unsafe-inline' 'self' 'unsafe-eval'",
          "http://www.googleadservices.com",
          "https://www.google-analytics.com",
          "https://www.gstatic.com",
          "https://www.google.com",
          "https://ajax.googleapis.com",
          "https://cdnjs.cloudflare.com",
          "https://www.google-analytics.com",
          "https://*.visualwebsiteoptimizer.com",
          "https://connect.facebook.net",
          "https://www.googletagmanager.com",
          "https://ssl.google-analytics.com",
          "https://www.googleadservices.com",
          "https://knab.blueconic.net",
          "https://apis.google.com",
          "https://googleads.g.doubleclick.net/pagead/viewthroughconversion/837300153;",
        "style-src 'unsafe-inline' 'self';",
        "frame-src 'self'",
          "https://www.google.com/recaptcha/",
          "https://*.cobrowse.liveperson.net",
          "https://lpcdn.lpsnmedia.net",
          "https://quadia.webtvframework.com",
          "https://bid.g.doubleclick.net",
          "https://8163947.fls.doubleclick.net",
          "https://staticxx.facebook.com/ https://mods.netb.nl;",
        "object-src 'none'; ",
        "connect-src 'self'",
          "https://knab.blueconic.net",
          "https://www.googletagmanager.com",
          "https://www.google-analytics.com",
          "https://middleware.test.knabverzekeren.nl",
          "https://middleware.verzekeren.knab.nl",
          "https://middleware.uat.knabverzekeren.nl",
          "https://knab-dev.apigee.net",
          "https://knab-acc.apigee.net",
          "https://knab-prd.apigee.net",
          "https://d3cuj82m9z5zxb.cloudfront.net",
          "https://www.google.com/ads/user-lists/837300153;"
    ],
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "same-origin",
    "X-UA-Compatible": "IE=edge"
};

exports.handler = (event, context, callback) => {
  const response = event.Records[0].cf.response;
  const headers = response.headers;

  Object.keys(secHeaders).forEach((el) => {
    let keyValue;

    if (Array.isArray(secHeaders[el])) {
      keyValue = secHeaders[el].join(" ");
    } else {
      keyValue = secHeaders[el];
    }

    headers[el] = [{key: el, value: keyValue}];
  });

  return callback(null, response);
}
