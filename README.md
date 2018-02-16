# Content Security Policy
Scripts to add the Content Security Policy headers.

## Description
We currently use one generic policy to insert security headers in the pages for Verzekeren.

Please do modify the contentSecurityPolicy object inside the javascript, *DO NOT* modify
the lambda function directly inside the AWS environment. That will never be tested 
and can bring errors.

## TODO:

- [ ] Add rules to enable logging to Report URI tooling
- [ ] Add Spec to the test to verify the content of lambda result
