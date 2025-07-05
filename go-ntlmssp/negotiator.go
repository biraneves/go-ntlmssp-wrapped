package ntlmssp

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// GetDomain : parse domain name from based on slashes in the input
// Need to check for upn as well
func GetDomain(user string) (string, string, bool) {
	domain := ""
	domainNeeded := false

	if strings.Contains(user, "\\") {
		ucomponents := strings.SplitN(user, "\\", 2)
		domain = ucomponents[0]
		user = ucomponents[1]
		domainNeeded = true
	} else if strings.Contains(user, "@") {
		domainNeeded = false
	} else {
		domainNeeded = true
	}
	return user, domain, domainNeeded
}

// Negotiator is a http.Roundtripper decorator that automatically
// converts basic authentication to NTLM/Negotiate authentication when appropriate.
type Negotiator struct{ http.RoundTripper }

// RoundTrip sends the request to the server, handling any authentication
// re-sends as needed.
func (l Negotiator) RoundTrip(req *http.Request) (res *http.Response, err error) {
	// Use default round tripper if not provided
	rt := l.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}
	// If it is not basic auth, just round trip the request as usual
	reqauth := authheader(req.Header.Values("Authorization"))
	if !reqauth.IsBasic() {
		return rt.RoundTrip(req)
	}
	reqauthBasic := reqauth.Basic()
	// Save request body
	body := bytes.Buffer{}
	if req.Body != nil {
		_, err = body.ReadFrom(req.Body)
		if err != nil {
			log.Printf("[DEBUG]%s error reading req body: %s", CallerInfo(), err.Error())
			return nil, err
		}

		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
	}
	// first try anonymous, in case the server still finds us
	// authenticated from previous traffic
	req.Header.Del("Authorization")
	res, err = rt.RoundTrip(req)
	if err != nil {
		log.Printf("[DEBUG]%s error in anonymous try: %s", CallerInfo(), err.Error())
		return nil, err
	}
	if res.StatusCode != http.StatusUnauthorized {
		log.Printf("[DEBUG]%s res status code in anonymous try is not http unauthorized: %s", CallerInfo(), err.Error())
		return res, err
	}
	resauth := authheader(res.Header.Values("Www-Authenticate"))
	if !resauth.IsNegotiate() && !resauth.IsNTLM() {
		// Unauthorized, Negotiate not requested, let's try with basic auth
		req.Header.Set("Authorization", string(reqauthBasic))
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		res, err = rt.RoundTrip(req)
		if err != nil {
			log.Printf("[DEBUG]%s error in basic authentication try: %s", CallerInfo(), err.Error())
			return nil, err
		}
		if res.StatusCode != http.StatusUnauthorized {
			log.Printf("[DEBUG]%s res status code in basic authentication try is not http unauthorized: %s", CallerInfo(), err.Error())
			return res, err
		}
		resauth = authheader(res.Header.Values("Www-Authenticate"))
	}

	if resauth.IsNegotiate() || resauth.IsNTLM() {
		// 401 with request:Basic and response:Negotiate
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		// recycle credentials
		u, p, err := reqauth.GetBasicCreds()
		if err != nil {
			log.Printf("[DEBUG]%s error getting basic credentials: %s", CallerInfo(), err.Error())
			return nil, err
		}

		// get domain from username
		domain := ""
		u, domain, domainNeeded := GetDomain(u)

		// send negotiate
		negotiateMessage, err := NewNegotiateMessage(domain, "")
		if err != nil {
			log.Printf("[DEBUG]%s error creating negotiation message: %s", CallerInfo(), err.Error())
			return nil, err
		}
		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiateMessage))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateMessage))
		}

		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		res, err = rt.RoundTrip(req)
		if err != nil {
			log.Printf("[DEBUG]%s error sending negotiation: %s", CallerInfo(), err.Error())
			return nil, err
		}

		// receive challenge?
		resauth = authheader(res.Header.Values("Www-Authenticate"))
		challengeMessage, err := resauth.GetData()
		if err != nil {
			log.Printf("[DEBUG]%s error getting challenge data: %s", CallerInfo(), err.Error())
			return nil, err
		}
		if !(resauth.IsNegotiate() || resauth.IsNTLM()) || len(challengeMessage) == 0 {
			// Negotiation failed, let client deal with response
			log.Printf("[DEBUG]%s negotiation failed, letting client deal with response", CallerInfo())
			return res, nil
		}
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		// send authenticate
		authenticateMessage, err := ProcessChallenge(challengeMessage, u, p, domainNeeded)
		if err != nil {
			log.Printf("[DEBUG]%s error processing challenge: %s", CallerInfo(), err.Error())
			return nil, err
		}
		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticateMessage))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateMessage))
		}

		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		return rt.RoundTrip(req)
	}

	return res, err
}
