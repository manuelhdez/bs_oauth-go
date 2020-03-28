package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/manuelhdez/bs_oauth-go/oauth/utils/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Cliend-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}
	return req.Header.Get(headerXPublic) == "true"
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(req.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func AuthenticateRequest(req *http.Request) *errors.RestErr {
	if req == nil {
		return nil
	}

	cleanRequest(req)

	accessTokenId := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if response.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}

	req.Header.Add(headerXClientId, string(at.ClientId))
	req.Header.Add(headerXCallerId, string(at.UserId))

	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del(headerXClientId)
	req.Header.Del(headerXCallerId)
}

func getAccessToken(at string) (*accessToken, *errors.RestErr) {
	url := fmt.Sprintf("/oauth/access_token/%s", at)
	response := oauthRestClient.Get(url)

	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to get access token")
	}

	if response.StatusCode > 299 {
		var apiErr errors.RestErr
		fmt.Println(response)
		if err := json.Unmarshal(response.Bytes(), &apiErr); err != nil {
			return nil, errors.NewInternalServerError("invalid json error interface when trying to get access token")
		}
		return nil, &apiErr
	}

	var at2 accessToken
	if err := json.Unmarshal(response.Bytes(), &at2); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal token")
	}
	return &at2, nil

}
