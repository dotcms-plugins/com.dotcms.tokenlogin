# Token Login Example Code

This is an osgi plugin that provides an example of how dotCMS can respond to a token sent in a request header, validate that token, and then based on that token log the user of the request in.  

** This is not working code, it is only intended as an example **

### About the Implementaion
This code adds an interceptor that responds to requests to `/api/tokenlogin`.  If a request hits that url and includes a token in the headers (header name can be changed in the tokenlogin.properties) then it will try to decode that token, validate it against a 3rd party IDP and

---

# Plugin Components
