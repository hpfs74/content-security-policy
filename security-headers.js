/**
 * security-headers.js
 *
 * set the heders of cloudfront reading them from a json object 'secHeaders'.
 * the json object is inside the code but i can also be stored in a file.
 *
 * IMPORTANT: cannot be put in a S3 bucket because it is too slow and will make
 * the lambda@edge go in timeout resulting the site to not be visible.
 */

/**
 * build the tag inside the content security policy
 * @param tag
 * @param arr
 * @returns {string}
 */
function buildTag(tag, val) {
    let ret = "";
    if (val) {
        if (Array.isArray(val) && val.length > 0) {
            ret = `${tag} ${val.reduce((acc, el) => acc + " " + el)}; `;
        }

        if (typeof(val) === "string") {
            ret = `${tag} ${val}; `;
        }
    }

    return ret;
  }

  /**
  * iterate through csp configuration object
  *
  * @param csp
  * @returns {string}
  */
  function buildContentSecurityPolicy(csp) {

    if (typeof(csp) === "object") {

        return Object.keys(csp).reduce( (acc, el) => `${acc} ${buildTag(el, csp[el])}`, "");
    }
    return "";
  }

  const contentSecurityPolicy = {
    "report-uri": "https://report-uri.knab.nl/r/t/csp/enforce",
    "default-src": [
        "'unsafe-inline'",
        "'self'",
        "http://version.bogus.net/v1.4",
        "http://*.usabilla.com",
        "http://aegon-middleware-qa.mobgen.com",
        "https://*.usabilla.com",
        "https://api.test.knabverzekeren.nl",
        "https://cdn-static.formisimo.com",
        "https://code.jquery.com",
        "https://googleads.g.doubleclick.net",
        "https://knab-acc.apigee.net",
        "https://knab-dev.apigee.net",
        "https://knab-prd.apigee.net",
        "https://middleware.test.knabverzekeren.nl",
        "https://middleware.uat.knabverzekeren.nl",
        "https://middleware.verzekeren.knab.nl",
        "https://report-uri.knab.nl/r/t/csp/enforce",
        "https://script-rumlive.rum.nccgroup-webperf.com",
        "https://tracking.formisimo.com",
        "https://www.google-analytics.com",
        "https://www.googletagmanager.com"
    ],
    "img-src": [
        "'self'",
        "data:",
        "http://*.visualwebsiteoptimizer.com",
        "http://placehold.it",
        "https://*.cloudfront.net",
        "http://*.usabilla.com",
        "https://*.usabilla.com",
        "https://*.visualwebsiteoptimizer.com",
        "https://ad.doubleclick.net/ddm/activity/src=8163947",
        "https://d3cuj82m9z5zxb.cloudfront.net",
        "https://googleads.g.doubleclick.net",
        "https://ib.adnxs.com",
        "https://knab-acc.apigee.net",
        "https://knab-dev.apigee.net",
        "https://knab-prd.apigee.net",
        "https://knab.blueconic.net",
        "https://script-rumlive.rum.nccgroup-webperf.com",
        "https://secure.adnxs.com",
        "https://ssl.google-analytics.com",
        "https://stats.g.doubleclick.net",
        "https://www.at19.net",
        "https://www.facebook.com",
        "https://www.facebook.com/tr/",
        "https://www.google-analytics.com",
        "https://www.google.com",
        "https://www.google.bg",
        "https://www.google.nl",
        "https://www.googleadservices.com",
        "https://www.gstatic.com",
        "https://t.co",
        "https://webmodule2.risk-verzekeringen.nl",
        "https://webmodulea.risk-verzekeringen.nl"
    ],
    "script-src": [
        "'unsafe-inline'",
        "'self'",
        "'unsafe-eval'",
        "http://*.usabilla.com",
        "http://code.jquery.com",
        "http://tracking.formisimo.com",
        "http://www.googleadservices.com",
        "https://*.usabilla.com",
        "https://*.visualwebsiteoptimizer.com",
        "https://ajax.googleapis.com",
        "https://apis.google.com",
        "https://cdn-static.formisimo.com",
        "https://cdnjs.cloudflare.com",
        "https://connect.facebook.net",
        "https://googleads.g.doubleclick.net",
        "https://knab.blueconic.net",
        "https://script-rumlive.rum.nccgroup-webperf.com",
        "https://ssl.google-analytics.com",
        "https://www.google-analytics.com",
        "https://www.google.com",
        "https://www.googleadservices.com",
        "https://www.googletagmanager.com",
        "https://www.gstatic.com",
        "https://cdn.polyfill.io",
        "https://tagmanager.google.com",
        "https://snap.licdn.com",
        "https://static.ads-twitter.com",
        "https://px.ads.linkedin.com",
        "https://analytics.twitter.com",
        "https://www.linkedin.com",
        "https://d6tizftlrpuof.cloudfront.net"
    ],
    "style-src": [
        "'unsafe-inline'",
        "'self'",
        "https://d6tizftlrpuof.cloudfront.net",
        "https://mijnverzekeren.d.knabstaging.nl",
        "https://mijnverzekeren.t.knabstaging.nl",
        "https://mijnverzekeren.a.knabstaging.nl",
        "https://mijnverzekeren.knab.nl"
    ],
    "font-src": [
        "'self'",
        "https://d6tizftlrpuof.cloudfront.net"
    ],
    "frame-src": [
        "'self'",
        "https://www.google.com/recaptcha/",
        "https://*.cobrowse.liveperson.net",
        "https://lpcdn.lpsnmedia.net",
        "https://quadia.webtvframework.com",
        "https://bid.g.doubleclick.net",
        "https://8163947.fls.doubleclick.net",
        "https://connect.facebook.net",
        "https://staticxx.facebook.com/",
        "https://mods.netb.nl",
        "https://email.knab.nl",
        "https://d6tizftlrpuof.cloudfront.net"
    ],
    "connect-src": [
        "'self'",
        "http://*.usabilla.com",
        "http://code.jquery.com",
        "http://tracking.formisimo.com",
        "https://*.usabilla.com",
        "https://*.visualwebsiteoptimizer.com/",
        "https://api.test.knabverzekeren.nl",
        "https://cdn-static.formisimo.com/",
        "https://d3cuj82m9z5zxb.cloudfront.net",
        "https://googleads.g.doubleclick.net",
        "https://j58eycphw6.execute-api.eu-west-1.amazonaws.com",
        "https://knab-acc.apigee.net",
        "https://knab-dev.apigee.net",
        "https://knab-prd.apigee.net",
        "https://knab.blueconic.net",
        "https://middleware.test.knabverzekeren.nl",
        "https://middleware.uat.knabverzekeren.nl",
        "https://middleware.verzekeren.knab.nl",
        "https://script-rumlive.rum.nccgroup-webperf.com",
        "https://www.google-analytics.com",
        "https://www.google.com/ads/user-lists/837300153",
        "https://www.googletagmanager.com",
        "https://api.uat.knabverzekeren.nl",
        "https://api.knab.nl/"
    ],
    "object-src": ["'none'"]
  }

const secHeaders = {
    "csp-version": "v1",
    "Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload",
    "Content-Security-Policy": buildContentSecurityPolicy(contentSecurityPolicy),
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
        headers[el] = [{key: el, value: secHeaders[el]}];
    });

    return callback(null, response);
  }
