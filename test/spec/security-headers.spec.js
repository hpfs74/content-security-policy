const chai = require("chai");
const expect = chai.expect;

const securityHeader = require("../../security-headers");

describe("LAMBDA@EDGE", () => {

    let event = {};
    let cspString = "";

    beforeEach(() => {
        event = {
            Records: [{
                cf: {
                    response: {
                        headers: []
                    }
                }
            }]
        };

        securityHeader.handler(event, null, () => {

        });

        cspString = event.Records[0].cf.response.headers["Content-Security-Policy"][0].value;
    });

    afterEach(() => {
        requestHeader = {};
    });

    it("should add strict policy header", () => {
        expect(event.Records[0].cf.response.headers["Strict-Transport-Security"][0].key)
            .to.equal("Strict-Transport-Security");
        expect(event.Records[0].cf.response.headers["Strict-Transport-Security"][0].value)
            .to.equal("max-age=31536000; includeSubdomains; preload");
    });

    it("should add content type options", () => {

        expect(event.Records[0].cf.response.headers["X-Content-Type-Options"][0].key)
            .to.equal("X-Content-Type-Options");
        expect(event.Records[0].cf.response.headers["X-Content-Type-Options"][0].value)
            .to.equal("nosniff");
    });

    it("should add frame options", () => {
        expect(event.Records[0].cf.response.headers["X-Frame-Options"][0].key)
            .to.equal("X-Frame-Options");
        expect(event.Records[0].cf.response.headers["X-Frame-Options"][0].value)
            .to.equal("DENY");
    });

    it("should add xss protection", () => {
        expect(event.Records[0].cf.response.headers["X-XSS-Protection"][0].key)
            .to.equal("X-XSS-Protection");
        expect(event.Records[0].cf.response.headers["X-XSS-Protection"][0].value)
            .to.equal("1; mode=block");
    });

    it("should add referrer policy", () => {
        expect(event.Records[0].cf.response.headers["Referrer-Policy"][0].key)
            .to.equal("Referrer-Policy");
        expect(event.Records[0].cf.response.headers["Referrer-Policy"][0].value)
            .to.equal("same-origin");
    });

    describe("content security policy", () => {

        it("should contain the header", () => {
            expect(event.Records[0].cf.response.headers["Content-Security-Policy"][0].key)
                .to.equal("Content-Security-Policy");
        });
        it("should be a string", () => {
            expect(event.Records[0].cf.response.headers["Content-Security-Policy"][0].value)
                .to.be.a("string");
        });

        it("should not be empty", () => {
            expect(event.Records[0].cf.response.headers["Content-Security-Policy"][0].value)
                .not.to.be.empty;
        });

        it("should contain report-uri", () => {
            expect(cspString)
                .to.contains("report-uri https://report-uri.knab.nl/r/t/csp/enforce;");
        });

        it("should contain proper default-src", () => {
            expect(cspString)
                .to.contains("default-src 'unsafe-inline' 'self' https://www.google-analytics.com https://www.googletagmanager.com http://aegon-middleware-qa.mobgen.com https://middleware.test.knabverzekeren.nl https://middleware.verzekeren.knab.nl https://middleware.uat.knabverzekeren.nl https://knab-dev.apigee.net https://knab-acc.apigee.net https://knab-prd.apigee.net https://api.test.knabverzekeren.nl https://cdn-static.formisimo.com https://tracking.formisimo.com https://code.jquery.com;");
        });

        it("should contain proper img-src", () => {
            expect(cspString)
                .to.contains("img-src 'self' data: https://ssl.google-analytics.com https://www.google.com https://www.google.nl https://www.google-analytics.com https://*.visualwebsiteoptimizer.com https://www.facebook.com https://googleads.g.doubleclick.net https://www.googleadservices.com https://secure.adnxs.com https://ib.adnxs.com https://www.facebook.com/tr/ https://secure.adnxs.com https://www.at19.net https://knab.blueconic.net https://stats.g.doubleclick.net https://ad.doubleclick.net/ddm/activity/src=8163947 https://secure.adnxs.com https://www.google.nl https://www.google-analytics.com https://stats.g.doubleclick.net http://placehold.it https://www.google.com/ads https://www.gstatic.com https://d3cuj82m9z5zxb.cloudfront.net;");
        });

        it("should contain proper script-src", () => {
            expect(cspString)
                .to.contains("script-src 'unsafe-inline' 'self' 'unsafe-eval' http://www.googleadservices.com https://www.google-analytics.com https://www.gstatic.com https://www.google.com https://ajax.googleapis.com https://cdnjs.cloudflare.com https://www.google-analytics.com https://*.visualwebsiteoptimizer.com https://connect.facebook.net https://www.googletagmanager.com https://ssl.google-analytics.com https://www.googleadservices.com https://knab.blueconic.net https://apis.google.com https://googleads.g.doubleclick.net/pagead/viewthroughconversion/837300153;");
        });

        it("should contain proper style-src", () => {
            expect(cspString)
                .to.contains("style-src 'unsafe-inline' 'self';");
        });

        it("should contain proper frame-src", () => {
            expect(cspString)
                .to.contains("frame-src 'self' https://www.google.com/recaptcha/ https://*.cobrowse.liveperson.net https://lpcdn.lpsnmedia.net https://quadia.webtvframework.com https://bid.g.doubleclick.net https://8163947.fls.doubleclick.net https://connect.facebook.net https://staticxx.facebook.com/ https://mods.netb.nl;");
        });

        it("should contain proper connect-src", () => {
            expect(cspString)
                .to.contains("connect-src 'self' https://knab.blueconic.net https://www.googletagmanager.com https://www.google-analytics.com https://middleware.test.knabverzekeren.nl https://middleware.verzekeren.knab.nl https://middleware.uat.knabverzekeren.nl https://knab-dev.apigee.net https://knab-acc.apigee.net https://knab-prd.apigee.net https://api.test.knabverzekeren.nl https://d3cuj82m9z5zxb.cloudfront.net https://www.google.com/ads/user-lists/837300153 https://dev.visualwebsiteoptimizer.com/ https://j58eycphw6.execute-api.eu-west-1.amazonaws.com;");
        });

        it("should contain proper object-src", () => {
            expect(cspString)
                .to.contains("object-src 'none';");
        });
    });
});

