const chai = require('chai');
const expect = chai.expect;

const securityHeader = require('../../security-headers');

describe('LAMBDA@EDGE', () => {

  let event = {};

  beforeEach( () => {
    event = {
      Records: [ {
        cf: {
          response: {
            headers: []
          }
        }
      }]
    };

    securityHeader.handler(event, null, () => {

    });
  });

  afterEach( () => {
    requestHeader = {};
  });

  it('should add strict policy header', () => {
    expect(event.Records[0].cf.response.headers['Strict-Transport-Security'][0].key)
      .to.equal('Strict-Transport-Security');
    expect(event.Records[0].cf.response.headers['Strict-Transport-Security'][0].value)
      .to.equal('max-age=31536000; includeSubdomains; preload');
  });

  it('should add content type options', () => {

    expect(event.Records[0].cf.response.headers['X-Content-Type-Options'][0].key)
      .to.equal('X-Content-Type-Options');
    expect(event.Records[0].cf.response.headers['X-Content-Type-Options'][0].value)
      .to.equal('nosniff');
  });

  it('should add frame options', () => {
    expect(event.Records[0].cf.response.headers['X-Frame-Options'][0].key)
      .to.equal('X-Frame-Options');
    expect(event.Records[0].cf.response.headers['X-Frame-Options'][0].value)
      .to.equal('DENY');
  });


  it('should add xss protection', () => {
    expect(event.Records[0].cf.response.headers['X-XSS-Protection'][0].key)
      .to.equal('X-XSS-Protection');
    expect(event.Records[0].cf.response.headers['X-XSS-Protection'][0].value)
      .to.equal('1; mode=block');
  });


  it('should add referrer policy', () => {
    expect(event.Records[0].cf.response.headers['Referrer-Policy'][0].key)
      .to.equal('Referrer-Policy');
    expect(event.Records[0].cf.response.headers['Referrer-Policy'][0].value)
      .to.equal('same-origin');
  });

  describe('content security policy', () => {

    it('should contain the header', () => {
      expect(event.Records[0].cf.response.headers['Content-Security-Policy'][0].key)
        .to.equal('Content-Security-Policy');
    });
    it('should be a string', () => {
      expect(event.Records[0].cf.response.headers['Content-Security-Policy'][0].value)
        .to.be.a('string');
    });

    it('should not be empty', () => {
      expect(event.Records[0].cf.response.headers['Content-Security-Policy'][0].value)
        .not.to.be.empty;
    });
  });
});

